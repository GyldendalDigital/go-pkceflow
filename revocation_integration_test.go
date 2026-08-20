package pkceflow_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
	"github.com/GyldendalDigital/go-pkceflow/oidctest"
)

// newRevocationClient builds a logged-in client and returns the refresh token it
// holds, so a test can check whether that credential still works afterwards.
func newRevocationClient(
	t *testing.T,
	opts ...oidctest.Option,
) (*pkceflow.Client, *oidctest.FakeIDPServer, *oidctest.MemoryStore, string) {
	t.Helper()

	redirectURI := "http://127.0.0.1:9999/callback"
	opts = append([]oidctest.Option{
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
	}, opts...)
	idp := oidctest.NewFakeIDP(t, opts...)

	store := &oidctest.MemoryStore{}
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: idp.IssuerURL(),
		ClientID:  "test-app",
	}, oidctest.NewFakeFlowHandler(idp, redirectURI),
		pkceflow.WithTokenPersistence(store),
	)
	if err != nil {
		t.Fatalf("pkceflow.New: %v", err)
	}

	ctx := context.Background()
	if err := client.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.RefreshToken == "" {
		t.Fatal("login produced no refresh token")
	}
	return client, idp, store, state.RefreshToken
}

// redeemRefreshToken presents a refresh token to the token endpoint directly and
// reports whether the provider still accepts it.
//
// It is single-use: the fake IdP rotates refresh tokens, so a successful
// redemption deletes the token it just accepted. Call it once, as the final
// assertion - a "still alive beforehand" probe would consume the credential and
// leave the real assertion unable to fail.
func redeemRefreshToken(t *testing.T, idp *oidctest.FakeIDPServer, refreshToken string) bool {
	t.Helper()
	resp, err := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"test-app"},
	})
	if err != nil {
		t.Fatalf("redeem refresh token: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// TestLogoutRevokesRefreshToken asserts the credential actually stops working.
// A recorded POST would only prove a request was sent; RFC 7009 requires a 200
// even for a token the provider does not recognize, so the request alone proves
// nothing.
func TestLogoutRevokesRefreshToken(t *testing.T) {
	client, idp, _, refreshToken := newRevocationClient(t)

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if redeemRefreshToken(t, idp, refreshToken) {
		t.Fatal("refresh token is still redeemable after logout")
	}

	// The request carried exactly what RFC 7009 requires of a public client.
	records := idp.Recorder.RecordsFor("/revoke")
	if len(records) != 1 {
		t.Fatalf("revocation requests = %d, want 1", len(records))
	}
	params := records[0].Params
	if params.Get("token") != refreshToken {
		t.Error("revocation request did not carry the refresh token")
	}
	if got := params.Get("token_type_hint"); got != "refresh_token" {
		t.Errorf("token_type_hint = %q, want %q", got, "refresh_token")
	}
	if got := params.Get("client_id"); got != "test-app" {
		t.Errorf("client_id = %q, want %q", got, "test-app")
	}
	if params.Get("client_secret") != "" {
		t.Error("revocation request sent a client secret for a public client")
	}
}

// A provider without RFC 7009 support, such as Microsoft Entra ID, must not
// change logout at all.
func TestLogoutWithoutRevocationEndpoint(t *testing.T) {
	client, idp, _, refreshToken := newRevocationClient(t, oidctest.WithOmitRevocationEndpoint())

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if records := idp.Recorder.RecordsFor("/revoke"); len(records) != 0 {
		t.Fatalf("revocation requests = %d, want 0 when unadvertised", len(records))
	}
	if status := client.AuthStatus(); status.CanUseApp {
		t.Fatalf("AuthStatus after logout = %+v, want logged out", status)
	}
	// Liveness control for TestLogoutRevokesRefreshToken: with no endpoint
	// advertised the credential must survive, which is what proves that logout
	// on its own does not kill it.
	if !redeemRefreshToken(t, idp, refreshToken) {
		t.Fatal("refresh token died without a revocation endpoint")
	}
}

// Revocation is best effort: a provider failure must not leave the user unable
// to log out, and must not keep local state alive.
func TestLogoutCompletesWhenRevocationFails(t *testing.T) {
	client, idp, store, _ := newRevocationClient(t)
	idp.Hooks.SetRevocationHook(func(w http.ResponseWriter, _ *http.Request) bool {
		http.Error(w, "boom", http.StatusInternalServerError)
		return true
	})

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if status := client.AuthStatus(); status.CanUseApp {
		t.Fatalf("AuthStatus after logout = %+v, want logged out", status)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if !state.IsZero() {
		t.Fatalf("persisted state survived logout: %+v", state)
	}
}

// A redirecting revocation endpoint must not carry the refresh token onward: Go
// replays the request body on 307 and 308, cross-origin included, and the
// endpoint comes from the discovery document.
func TestLogoutRevocationDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	var bodyMu sync.Mutex
	var body string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		received, _ := io.ReadAll(r.Body)
		bodyMu.Lock()
		body = string(received)
		bodyMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	client, idp, _, refreshToken := newRevocationClient(t)
	idp.Hooks.SetRevocationHook(func(w http.ResponseWriter, r *http.Request) bool {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
		return true
	})

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, want 0", got)
	}
	bodyMu.Lock()
	leaked := strings.Contains(body, refreshToken)
	bodyMu.Unlock()
	if leaked {
		t.Fatal("refresh token reached the redirect target")
	}
}

// A caller whose context is already cancelled - "log out and quit" - must still
// get its refresh token revoked. Otherwise the only copy is deleted locally
// while the credential stays live at the provider, unrevokable by anyone.
func TestLogoutRevokesWithCancelledContext(t *testing.T) {
	client, idp, _, refreshToken := newRevocationClient(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := client.Logout(ctx); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if redeemRefreshToken(t, idp, refreshToken) {
		t.Fatal("refresh token is still redeemable after logout with a cancelled context")
	}
}
