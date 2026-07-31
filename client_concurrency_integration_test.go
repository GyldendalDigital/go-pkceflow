package pkceflow_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
	"github.com/GyldendalDigital/go-pkceflow/oidctest"
)

type gatedRefreshTransport struct {
	base         http.RoundTripper
	entered      chan struct{}
	enteredOnce  sync.Once
	release      chan struct{}
	releaseOnce  sync.Once
	dropResponse bool
}

func newGatedRefreshTransport(dropResponse bool) *gatedRefreshTransport {
	return &gatedRefreshTransport{
		base:         http.DefaultTransport,
		entered:      make(chan struct{}),
		release:      make(chan struct{}),
		dropResponse: dropResponse,
	}
}

func (t *gatedRefreshTransport) unblock() {
	t.releaseOnce.Do(func() {
		close(t.release)
	})
}

func (t *gatedRefreshTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	isRefresh, err := requestUsesRefreshGrant(request)
	if err != nil {
		return nil, err
	}

	response, err := t.base.RoundTrip(request)
	if err != nil || !isRefresh {
		return response, err
	}
	t.enteredOnce.Do(func() {
		close(t.entered)
	})
	<-t.release
	if !t.dropResponse {
		return response, nil
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return nil, errors.New("simulated lost refresh response")
}

func requestUsesRefreshGrant(request *http.Request) (bool, error) {
	if request.Method != http.MethodPost || request.Body == nil {
		return false, nil
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return false, err
	}
	_ = request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(body))

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return false, err
	}
	return values.Get("grant_type") == "refresh_token", nil
}

func waitForIntegrationSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal(message)
	}
}

func waitForAccessToken(t *testing.T, result <-chan string, message string) string {
	t.Helper()
	select {
	case token := <-result:
		return token
	case <-time.After(2 * time.Second):
		t.Fatal(message)
		return ""
	}
}

func TestDelayedRefreshCannotOverwriteNewerLogin(t *testing.T) {
	tests := []struct {
		name         string
		dropResponse bool
	}{
		{name: "delayed success"},
		{name: "consumed refresh response lost", dropResponse: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const redirectURI = "http://127.0.0.1:9999/callback"
			idp := oidctest.NewFakeIDP(t,
				oidctest.WithClientID("test-app"),
				oidctest.WithRedirectURI(redirectURI),
				oidctest.WithAccessTTL(5*time.Second),
			)
			store := &oidctest.MemoryStore{}
			emitter := &oidctest.RecordingEmitter{}
			transport := newGatedRefreshTransport(tt.dropResponse)
			t.Cleanup(transport.unblock)

			client, err := pkceflow.New(
				pkceflow.Config{
					IssuerURL: idp.IssuerURL(),
					ClientID:  "test-app",
				},
				oidctest.NewFakeFlowHandler(idp, redirectURI),
				pkceflow.WithHTTPClient(&http.Client{Transport: transport}),
				pkceflow.WithTokenPersistence(store),
				pkceflow.WithEventEmitter(emitter),
			)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := client.Init(context.Background()); err != nil {
				t.Fatalf("Init: %v", err)
			}
			if err := client.Login(context.Background()); err != nil {
				t.Fatalf("initial Login: %v", err)
			}
			older, err := store.Load()
			if err != nil {
				t.Fatalf("load initial state: %v", err)
			}
			emitter.Reset()

			refreshDone := make(chan string, 1)
			go func() {
				refreshDone <- client.AccessToken(context.Background())
			}()
			waitForIntegrationSignal(t, transport.entered, "refresh did not reach transport gate")

			if err := client.Login(context.Background()); err != nil {
				t.Fatalf("newer Login: %v", err)
			}
			newer, err := store.Load()
			if err != nil {
				t.Fatalf("load newer state: %v", err)
			}
			if newer.AccessToken == older.AccessToken {
				t.Fatal("newer Login did not replace the access token")
			}

			transport.unblock()
			if got := waitForAccessToken(t, refreshDone, "superseded refresh did not return"); got != newer.AccessToken {
				t.Fatalf("AccessToken = %q, want newer login token %q", got, newer.AccessToken)
			}
			persisted, err := store.Load()
			if err != nil {
				t.Fatalf("load final state: %v", err)
			}
			if persisted != newer {
				t.Fatalf("persisted state = %+v, want newer login %+v", persisted, newer)
			}

			var events []string
			for _, event := range emitter.Events() {
				events = append(events, event.Name)
			}
			if want := []string{pkceflow.EventLoggedIn}; !slices.Equal(events, want) {
				t.Fatalf("events = %v, want %v", events, want)
			}
		})
	}
}
