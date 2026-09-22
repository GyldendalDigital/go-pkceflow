package pkceflow_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
	"github.com/GyldendalDigital/go-pkceflow/oidctest"
)

const cancellationRedirectURI = "http://127.0.0.1:9999/callback"

// blockingAuthFlow never completes, so a login ends only by deadline,
// cancellation, or supersession.
type blockingAuthFlow struct{ started chan struct{} }

func (f *blockingAuthFlow) RedirectURI() string { return cancellationRedirectURI }

func (f *blockingAuthFlow) StartAuthFlow(ctx context.Context, _ string) (string, error) {
	select {
	case f.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return "", ctx.Err()
}

func newBlockedLoginClient(t *testing.T, loginTimeout time.Duration) (*pkceflow.Client, *blockingAuthFlow) {
	t.Helper()
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(cancellationRedirectURI),
	)
	flow := &blockingAuthFlow{started: make(chan struct{}, 1)}
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL:    idp.IssuerURL(),
		ClientID:     "test-app",
		LoginTimeout: loginTimeout,
	}, flow, pkceflow.WithTokenPersistence(&oidctest.MemoryStore{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return client, flow
}

// TestLoginCancellationCarriesItsCause is the point of the change: every one of
// these used to return a bare ErrFlowCancelled, so a caller could not tell a
// login that ran out of time from one the user cancelled.
func TestLoginCancellationCarriesItsCause(t *testing.T) {
	t.Run("login timeout", func(t *testing.T) {
		client, _ := newBlockedLoginClient(t, 100*time.Millisecond)
		err := client.Login(context.Background())
		assertCancelledWith(t, err, context.DeadlineExceeded)
	})

	t.Run("caller deadline", func(t *testing.T) {
		client, _ := newBlockedLoginClient(t, time.Minute)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		assertCancelledWith(t, client.Login(ctx), context.DeadlineExceeded)
	})

	t.Run("caller cancelled", func(t *testing.T) {
		client, flow := newBlockedLoginClient(t, time.Minute)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- client.Login(ctx) }()
		waitStarted(t, flow)
		cancel()
		assertCancelledWith(t, waitLoginError(t, result), context.Canceled)
	})

	t.Run("cancelled before entry", func(t *testing.T) {
		client, _ := newBlockedLoginClient(t, time.Minute)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assertCancelledWith(t, client.Login(ctx), context.Canceled)
	})

	// Supersession is deliberately bare: nothing timed out and nobody cancelled,
	// so there is no context cause to report.
	t.Run("superseded by a newer login", func(t *testing.T) {
		client, flow := newBlockedLoginClient(t, time.Minute)
		first := make(chan error, 1)
		go func() { first <- client.Login(context.Background()) }()
		waitStarted(t, flow)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		go func() { _ = client.Login(ctx) }()

		err := waitLoginError(t, first)
		if !errors.Is(err, pkceflow.ErrFlowCancelled) {
			t.Fatalf("error = %v, want it to wrap ErrFlowCancelled", err)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want no context cause for a superseded login", err)
		}
	})
}

func assertCancelledWith(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("error = %v, want it to wrap ErrFlowCancelled", err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want it to wrap %v", err, want)
	}
	// The two causes must stay mutually exclusive, or a consumer cannot branch.
	other := context.Canceled
	if errors.Is(want, context.Canceled) {
		other = context.DeadlineExceeded
	}
	if errors.Is(err, other) {
		t.Fatalf("error = %v, wraps both context causes", err)
	}
}

func waitStarted(t *testing.T, flow *blockingAuthFlow) {
	t.Helper()
	select {
	case <-flow.started:
	case <-time.After(2 * time.Second):
		t.Fatal("login never reached the flow handler")
	}
}

func waitLoginError(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("login never returned")
		return nil
	}
}

// TestLogoutCancellationIsNotLoggedAsFailure guards the equality comparison that
// had to move to errors.Is. Once the cancellation carries a cause, an `err !=
// ErrFlowCancelled` check stops matching and every ordinary cancelled logout
// starts emitting a failure warning.
func TestLogoutCancellationIsNotLoggedAsFailure(t *testing.T) {
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(cancellationRedirectURI),
	)
	var logs bytes.Buffer
	store := &oidctest.MemoryStore{}
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL:     idp.IssuerURL(),
		ClientID:      "test-app",
		LogoutTimeout: 100 * time.Millisecond,
	}, &blockingLogoutFlow{started: make(chan struct{}, 1)},
		pkceflow.WithTokenPersistence(store),
		pkceflow.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Seed a session so logout has an ID token and reaches the browser leg.
	if err := store.Save(pkceflow.TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		IDToken:      "id-token",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastAuthAt:   time.Now(),
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	if _, err := client.RestoreSession(); err != nil {
		t.Fatalf("RestoreSession: %v", err)
	}
	logs.Reset()

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if output := logs.String(); strings.Contains(output, "RP-Initiated Logout flow failed") {
		t.Fatalf("a cancelled logout was logged as a failure: %q", output)
	}
}

// blockingLogoutFlow stalls the logout browser leg until its context ends.
type blockingLogoutFlow struct{ started chan struct{} }

func (f *blockingLogoutFlow) RedirectURI() string { return cancellationRedirectURI }
func (f *blockingLogoutFlow) StartAuthFlow(ctx context.Context, _ string) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}
func (f *blockingLogoutFlow) PostLogoutRedirectURI() string {
	return cancellationRedirectURI
}
func (f *blockingLogoutFlow) StartLogoutFlow(ctx context.Context, _ string) (string, error) {
	select {
	case f.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return "", ctx.Err()
}
