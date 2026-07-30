package pkceflow_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
	"github.com/GyldendalDigital/go-pkceflow/oidctest"
)

func newTestClient(t *testing.T) (*pkceflow.Client, *oidctest.FakeIDPServer, *oidctest.MemoryStore, *oidctest.RecordingEmitter) {
	t.Helper()

	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
		oidctest.WithAccessTTL(5*time.Minute),
	)

	store := &oidctest.MemoryStore{}
	emitter := &oidctest.RecordingEmitter{}
	handler := oidctest.NewFakeFlowHandler(idp, redirectURI)

	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: idp.IssuerURL(),
		ClientID:  "test-app",
	}, handler,
		pkceflow.WithTokenPersistence(store),
		pkceflow.WithEventEmitter(emitter),
	)
	if err != nil {
		t.Fatalf("pkceflow.New: %v", err)
	}

	return client, idp, store, emitter
}

type authorizationErrorFlow struct {
	redirectURI string
	stateMode   string
}

func (h *authorizationErrorFlow) RedirectURI() string {
	return h.redirectURI
}

func (h *authorizationErrorFlow) StartAuthFlow(_ context.Context, authURL string) (string, error) {
	target, _ := url.Parse(authURL)
	state := target.Query().Get("state")
	query := url.Values{
		"error":             {"access_denied"},
		"error_description": {"user cancelled"},
	}
	switch h.stateMode {
	case "matching":
		query.Set("state", state)
	case "wrong":
		query.Set("state", "wrong-state")
	case "duplicate":
		query["state"] = []string{state, "wrong-state"}
	case "missing":
	}
	return h.redirectURI + "?" + query.Encode(), nil
}

func TestInit_Discovery(t *testing.T) {
	client, _, _, _ := newTestClient(t)

	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func TestInit_BadIssuer(t *testing.T) {
	handler := oidctest.NewFakeFlowHandler(nil, "http://127.0.0.1:9999/callback")
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: "https://invalid.example.com",
		ClientID:  "test-app",
	}, handler)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = client.Init(ctx)
	if err == nil {
		t.Fatal("expected Init to fail with bad issuer")
	}
}

func TestInit_BadIssuer_EmitsInitFailed(t *testing.T) {
	handler := oidctest.NewFakeFlowHandler(nil, "http://127.0.0.1:9999/callback")
	emitter := &oidctest.RecordingEmitter{}
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: "https://invalid.example.com",
		ClientID:  "test-app",
	}, handler, pkceflow.WithEventEmitter(emitter))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Init(ctx); err == nil {
		t.Fatal("expected Init to fail with bad issuer")
	}
	if !emitter.HasEvent(pkceflow.EventInitFailed) {
		t.Error("EventInitFailed not emitted on discovery failure")
	}
}

func TestInit_Idempotent(t *testing.T) {
	client, _, _, _ := newTestClient(t)

	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init (first): %v", err)
	}
	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init (second): %v", err)
	}
}

func TestRestoreSession_Empty(t *testing.T) {
	client, _, _, _ := newTestClient(t)

	if client.RestoreSession() {
		t.Error("RestoreSession should return false on empty store")
	}
}

func TestRestoreSession_WithTokens(t *testing.T) {
	client, _, store, _ := newTestClient(t)

	// Pre-populate the store
	err := store.Save(pkceflow.TokenState{
		AccessToken:  "saved-access",
		RefreshToken: "saved-refresh",
		IDToken:      "saved-id",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastAuthAt:   time.Now(),
	})
	if err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	if !client.RestoreSession() {
		t.Error("RestoreSession should return true with tokens in store")
	}

	status := client.AuthStatus()
	if !status.Valid {
		t.Error("AuthStatus should be valid after restore")
	}
}

func TestLogin_HappyPath(t *testing.T) {
	client, _, store, emitter := newTestClient(t)

	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	// Tokens should be stored
	state, _ := store.Load()
	if state.IsZero() {
		t.Error("tokens not persisted after login")
	}
	if state.AccessToken == "" {
		t.Error("access token empty after login")
	}

	// Event should be emitted
	if !emitter.HasEvent(pkceflow.EventLoggedIn) {
		t.Error("EventLoggedIn not emitted")
	}

	// AuthStatus should be valid
	status := client.AuthStatus()
	if !status.Valid {
		t.Error("AuthStatus should be valid after login")
	}
	if !status.CanUseApp {
		t.Error("CanUseApp should be true after login")
	}
}

func TestLogin_NotInitialized(t *testing.T) {
	client, _, _, _ := newTestClient(t)

	err := client.Login(context.Background())
	if err == nil {
		t.Fatal("Login without Init should fail")
	}
}

func TestLoginValidatesStateBeforeAuthorizationError(t *testing.T) {
	tests := []struct {
		name      string
		stateMode string
		wantAuth  bool
	}{
		{name: "matching state preserves provider error", stateMode: "matching", wantAuth: true},
		{name: "wrong state", stateMode: "wrong"},
		{name: "missing state", stateMode: "missing"},
		{name: "duplicate state", stateMode: "duplicate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirectURI := "http://127.0.0.1:9999/callback"
			idp := oidctest.NewFakeIDP(t,
				oidctest.WithClientID("test-app"),
				oidctest.WithRedirectURI(redirectURI),
			)
			handler := &authorizationErrorFlow{
				redirectURI: redirectURI,
				stateMode:   tt.stateMode,
			}
			client, err := pkceflow.New(pkceflow.Config{
				IssuerURL: idp.IssuerURL(),
				ClientID:  "test-app",
			}, handler)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := client.Init(context.Background()); err != nil {
				t.Fatalf("Init: %v", err)
			}

			err = client.Login(context.Background())
			if tt.wantAuth {
				var authErr *pkceflow.AuthError
				if !errors.As(err, &authErr) || authErr.Code != "access_denied" {
					t.Fatalf("Login error = %v, want access_denied AuthError", err)
				}
				return
			}
			if !errors.Is(err, pkceflow.ErrStateMismatch) {
				t.Fatalf("Login error = %v, want ErrStateMismatch", err)
			}
		})
	}
}

func TestLogin_NonceMismatch(t *testing.T) {
	tests := []struct {
		name        string
		forcedNonce string
	}{
		{name: "wrong nonce", forcedNonce: "attacker-controlled-nonce"},
		{name: "missing nonce", forcedNonce: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			redirectURI := "http://127.0.0.1:9999/callback"
			idp := oidctest.NewFakeIDP(t,
				oidctest.WithClientID("test-app"),
				oidctest.WithRedirectURI(redirectURI),
				oidctest.WithForcedIDTokenNonce(tc.forcedNonce),
			)

			handler := oidctest.NewFakeFlowHandler(idp, redirectURI)
			client, err := pkceflow.New(pkceflow.Config{
				IssuerURL: idp.IssuerURL(),
				ClientID:  "test-app",
			}, handler)
			if err != nil {
				t.Fatalf("pkceflow.New: %v", err)
			}

			if err := client.Init(context.Background()); err != nil {
				t.Fatalf("Init: %v", err)
			}

			err = client.Login(context.Background())
			if !errors.Is(err, pkceflow.ErrNonceMismatch) {
				t.Fatalf("Login: expected ErrNonceMismatch, got %v", err)
			}
		})
	}
}

func TestAccessToken_ValidToken(t *testing.T) {
	client, _, _, _ := newTestClient(t)

	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	token := client.AccessToken(context.Background())
	if token == "" {
		t.Error("AccessToken returned empty string for valid token")
	}
}

func TestAccessToken_NoSession(t *testing.T) {
	client, _, _, _ := newTestClient(t)

	token := client.AccessToken(context.Background())
	if token != "" {
		t.Errorf("AccessToken returned %q, want empty", token)
	}
}

func TestTokenFn(t *testing.T) {
	client, _, _, _ := newTestClient(t)

	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	fn := client.TokenFn(context.Background())
	token := fn()
	if token == "" {
		t.Error("TokenFn returned empty string")
	}
}

// spyLogoutHandler wraps a FakeFlowHandler and additionally implements
// LogoutFlowHandler, recording the URLs passed to each flow method.
type spyLogoutHandler struct {
	inner           *oidctest.FakeFlowHandler
	postLogoutURI   string
	startAuthURLs   []string
	startLogoutURLs []string
}

func (s *spyLogoutHandler) StartAuthFlow(ctx context.Context, u string) (string, error) {
	s.startAuthURLs = append(s.startAuthURLs, u)
	return s.inner.StartAuthFlow(ctx, u)
}

func (s *spyLogoutHandler) RedirectURI() string { return s.inner.RedirectURI() }

func (s *spyLogoutHandler) StartLogoutFlow(ctx context.Context, u string) (string, error) {
	s.startLogoutURLs = append(s.startLogoutURLs, u)
	return s.inner.StartAuthFlow(ctx, u)
}

func (s *spyLogoutHandler) PostLogoutRedirectURI() string { return s.postLogoutURI }

func TestLogout_UsesLogoutFlowHandler(t *testing.T) {
	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
		oidctest.WithAccessTTL(5*time.Minute),
	)
	spy := &spyLogoutHandler{
		inner:         oidctest.NewFakeFlowHandler(idp, redirectURI),
		postLogoutURI: redirectURI,
	}
	store := &oidctest.MemoryStore{}
	emitter := &oidctest.RecordingEmitter{}

	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: idp.IssuerURL(),
		ClientID:  "test-app",
	}, spy,
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
		t.Fatalf("Login: %v", err)
	}
	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	// Logout must go through StartLogoutFlow, not StartAuthFlow.
	if len(spy.startLogoutURLs) != 1 {
		t.Fatalf("StartLogoutFlow called %d times, want 1", len(spy.startLogoutURLs))
	}

	u, err := url.Parse(spy.startLogoutURLs[0])
	if err != nil {
		t.Fatalf("parse logout URL: %v", err)
	}
	q := u.Query()
	if q.Get("state") == "" {
		t.Error("logout URL missing state")
	}
	if got := q.Get("post_logout_redirect_uri"); got != redirectURI {
		t.Errorf("post_logout_redirect_uri = %q, want %q", got, redirectURI)
	}
	if q.Get("id_token_hint") == "" {
		t.Error("logout URL missing id_token_hint")
	}

	if !emitter.HasEvent(pkceflow.EventLoggedOut) {
		t.Error("EventLoggedOut not emitted")
	}
}

func TestLogout_ClearsState(t *testing.T) {
	client, _, store, emitter := newTestClient(t)

	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	emitter.Reset()

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	// Store should be empty
	state, _ := store.Load()
	if !state.IsZero() {
		t.Error("store not cleared after logout")
	}

	// Event should be emitted
	if !emitter.HasEvent(pkceflow.EventLoggedOut) {
		t.Error("EventLoggedOut not emitted")
	}

	// AuthStatus should be empty
	status := client.AuthStatus()
	if status.Valid || status.CanUseApp {
		t.Error("AuthStatus should be invalid after logout")
	}

	// AccessToken should return empty
	token := client.AccessToken(context.Background())
	if token != "" {
		t.Errorf("AccessToken after logout = %q, want empty", token)
	}
}

func TestAuthStatus_NoSession(t *testing.T) {
	client, _, _, _ := newTestClient(t)

	status := client.AuthStatus()
	if status.Valid || status.GraceMode || status.CanUseApp {
		t.Errorf("AuthStatus with no session: %+v", status)
	}
}

func TestAuthStatus_GracePeriod(t *testing.T) {
	handler := oidctest.NewFakeFlowHandler(nil, "http://127.0.0.1:9999/callback")
	store := &oidctest.MemoryStore{}

	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL:   "https://idp.example.com",
		ClientID:    "my-app",
		GracePeriod: 30 * 24 * time.Hour,
	}, handler, pkceflow.WithTokenPersistence(store))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Simulate an expired token with recent auth
	err = store.Save(pkceflow.TokenState{
		AccessToken:  "expired",
		RefreshToken: "refresh",
		IDToken:      "id",
		ExpiresAt:    time.Now().Add(-time.Hour),
		LastAuthAt:   time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	client.RestoreSession()

	status := client.AuthStatus()
	if status.Valid {
		t.Error("should not be valid (token expired)")
	}
	if !status.GraceMode {
		t.Error("should be in grace mode")
	}
	if !status.CanUseApp {
		t.Error("CanUseApp should be true in grace mode")
	}
	if status.GraceDaysLeft <= 0 {
		t.Errorf("GraceDaysLeft = %d, want > 0", status.GraceDaysLeft)
	}
}

func TestAuthStatus_GraceDisabled(t *testing.T) {
	handler := oidctest.NewFakeFlowHandler(nil, "http://127.0.0.1:9999/callback")
	store := &oidctest.MemoryStore{}

	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: "https://idp.example.com",
		ClientID:  "my-app",
		// GracePeriod: 0 (default, disabled)
	}, handler, pkceflow.WithTokenPersistence(store))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = store.Save(pkceflow.TokenState{
		AccessToken: "expired",
		ExpiresAt:   time.Now().Add(-time.Hour),
		LastAuthAt:  time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	client.RestoreSession()

	status := client.AuthStatus()
	if status.GraceMode {
		t.Error("GraceMode should be false when GracePeriod is 0")
	}
	if status.CanUseApp {
		t.Error("CanUseApp should be false when expired and no grace")
	}
}

// waitForEvent polls the emitter until the named event appears or the timeout
// elapses. It fails the test if the event never arrives.
func waitForEvent(t *testing.T, emitter *oidctest.RecordingEmitter, name string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if emitter.HasEvent(name) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("event %q not emitted within %s; got events %+v", name, timeout, emitter.Events())
}

func unsignedIDToken(payload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return header + "." + body + ".signature"
}

func TestRefreshLoop_PermanentError_EmitsSessionExpired(t *testing.T) {
	client, idp, _, emitter := newTestClient(t)

	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	// The IdP rejects every token request as a revoked refresh token.
	idp.SetTokenError("invalid_grant")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The loop performs an immediate refresh on start, which fails permanently.
	client.StartRefreshLoop(ctx)
	defer client.StopRefreshLoop()

	waitForEvent(t, emitter, pkceflow.EventSessionExpired, 2*time.Second)
}

func TestRefreshLoop_PermanentError_StaysInGrace(t *testing.T) {
	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
		oidctest.WithAccessTTL(5*time.Minute),
	)
	store := &oidctest.MemoryStore{}
	emitter := &oidctest.RecordingEmitter{}
	handler := oidctest.NewFakeFlowHandler(idp, redirectURI)

	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL:   idp.IssuerURL(),
		ClientID:    "test-app",
		GracePeriod: 30 * 24 * time.Hour,
	}, handler,
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
		t.Fatalf("Login: %v", err)
	}

	// Permanent error, but a fresh login means grace has not expired: the loop
	// must keep the session and NOT emit EventSessionExpired.
	idp.SetTokenError("invalid_grant")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.StartRefreshLoop(ctx)
	defer client.StopRefreshLoop()

	// Give the immediate refresh time to run and fail.
	time.Sleep(100 * time.Millisecond)

	if emitter.HasEvent(pkceflow.EventSessionExpired) {
		t.Error("EventSessionExpired emitted while still within grace period")
	}
}

// countingTransport records the request paths that pass through it.
type countingTransport struct {
	mu   sync.Mutex
	hits map[string]int
	base http.RoundTripper
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.hits[req.URL.Path]++
	t.mu.Unlock()
	return t.base.RoundTrip(req)
}

func (t *countingTransport) count(path string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.hits[path]
}

func TestWithHTTPClient_RoutesLibraryHTTP(t *testing.T) {
	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
		oidctest.WithAccessTTL(5*time.Second), // already past the 30s buffer, so AccessToken refreshes
	)

	ct := &countingTransport{hits: map[string]int{}, base: http.DefaultTransport}
	hc := &http.Client{Transport: ct}

	handler := oidctest.NewFakeFlowHandler(idp, redirectURI)
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: idp.IssuerURL(),
		ClientID:  "test-app",
	}, handler,
		pkceflow.WithTokenPersistence(&oidctest.MemoryStore{}),
		pkceflow.WithHTTPClient(hc),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := client.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	// The access token is already beyond the 30s freshness buffer, so this
	// triggers a refresh through the same client.
	_ = client.AccessToken(ctx)

	if got := ct.count("/.well-known/openid-configuration"); got == 0 {
		t.Error("discovery did not use the custom HTTP client")
	}
	if got := ct.count("/token"); got < 2 {
		t.Errorf("token endpoint via custom client = %d, want >=2 (exchange + refresh)", got)
	}
	if got := ct.count("/jwks"); got == 0 {
		t.Error("JWKS verification did not use the custom HTTP client")
	}
}

func TestRefresh_PreservesIDTokenWhenRefreshOmitsOne(t *testing.T) {
	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
		oidctest.WithAccessTTL(5*time.Second), // beyond the 30s freshness buffer
		oidctest.WithOmitRefreshIDToken(),
	)

	store := &oidctest.MemoryStore{}
	handler := oidctest.NewFakeFlowHandler(idp, redirectURI)
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: idp.IssuerURL(),
		ClientID:  "test-app",
	}, handler, pkceflow.WithTokenPersistence(store))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := client.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	before, err := store.Load()
	if err != nil {
		t.Fatalf("load before refresh: %v", err)
	}
	if before.IDToken == "" {
		t.Fatal("login did not store ID token")
	}

	if got := client.AccessToken(ctx); got == "" {
		t.Fatal("AccessToken returned empty string after refresh without id_token")
	}

	after, err := store.Load()
	if err != nil {
		t.Fatalf("load after refresh: %v", err)
	}
	if after.AccessToken == before.AccessToken {
		t.Error("access token was not refreshed")
	}
	if after.IDToken != before.IDToken {
		t.Error("refresh without id_token did not preserve the previous verified ID token")
	}
}

func TestRefresh_RejectsIDTokenForDifferentSubject(t *testing.T) {
	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
		oidctest.WithAccessTTL(5*time.Second), // beyond the 30s freshness buffer
		oidctest.WithRefreshIDTokenSubject("attacker-user"),
	)

	store := &oidctest.MemoryStore{}
	emitter := &oidctest.RecordingEmitter{}
	handler := oidctest.NewFakeFlowHandler(idp, redirectURI)
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL:   idp.IssuerURL(),
		ClientID:    "test-app",
		GracePeriod: 30 * 24 * time.Hour,
	}, handler,
		pkceflow.WithTokenPersistence(store),
		pkceflow.WithEventEmitter(emitter),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := client.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	before, err := store.Load()
	if err != nil {
		t.Fatalf("load before refresh: %v", err)
	}
	emitter.Reset()

	if got := client.AccessToken(ctx); got != "" {
		t.Fatalf("AccessToken after rejected refresh = %q, want empty", got)
	}
	if emitter.HasEvent(pkceflow.EventTokenRefreshed) {
		t.Fatal("EventTokenRefreshed emitted after rejected refreshed ID token")
	}

	after, err := store.Load()
	if err != nil {
		t.Fatalf("load after refresh: %v", err)
	}
	if after.AccessToken != before.AccessToken {
		t.Error("rejected refreshed ID token still updated access token")
	}
	if after.IDToken != before.IDToken {
		t.Error("rejected refreshed ID token replaced the previous ID token")
	}
}

func TestRefresh_RejectsCurrentIDTokenWithoutSubject(t *testing.T) {
	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
		oidctest.WithAccessTTL(5*time.Second), // beyond the 30s freshness buffer
	)

	store := &oidctest.MemoryStore{}
	emitter := &oidctest.RecordingEmitter{}
	handler := oidctest.NewFakeFlowHandler(idp, redirectURI)
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: idp.IssuerURL(),
		ClientID:  "test-app",
	}, handler,
		pkceflow.WithTokenPersistence(store),
		pkceflow.WithEventEmitter(emitter),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := client.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	before, err := store.Load()
	if err != nil {
		t.Fatalf("load before refresh: %v", err)
	}
	before.IDToken = unsignedIDToken(`{"iss":"` + idp.IssuerURL() + `","aud":"test-app"}`)
	if err := store.Save(before); err != nil {
		t.Fatalf("save modified state: %v", err)
	}
	if !client.RestoreSession() {
		t.Fatal("RestoreSession failed after modifying stored ID token")
	}
	emitter.Reset()

	if got := client.AccessToken(ctx); got != "" {
		t.Fatalf("AccessToken after subjectless current ID token = %q, want empty", got)
	}
	if emitter.HasEvent(pkceflow.EventTokenRefreshed) {
		t.Fatal("EventTokenRefreshed emitted after subjectless current ID token")
	}

	after, err := store.Load()
	if err != nil {
		t.Fatalf("load after refresh: %v", err)
	}
	if after.IDToken != before.IDToken {
		t.Error("subjectless current ID token was replaced during rejected refresh")
	}
}

func TestRefreshLoop_IDTokenIntegrityFailure_EmitsSessionExpiredDespiteGrace(t *testing.T) {
	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
		oidctest.WithRawRefreshIDToken("not.a.jwt"),
	)

	store := &oidctest.MemoryStore{}
	emitter := &oidctest.RecordingEmitter{}
	handler := oidctest.NewFakeFlowHandler(idp, redirectURI)
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL:   idp.IssuerURL(),
		ClientID:    "test-app",
		GracePeriod: 30 * 24 * time.Hour,
	}, handler,
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
		t.Fatalf("Login: %v", err)
	}

	emitter.Reset()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.StartRefreshLoop(ctx)
	defer client.StopRefreshLoop()

	waitForEvent(t, emitter, pkceflow.EventSessionExpired, 2*time.Second)
	if emitter.HasEvent(pkceflow.EventTokenRefreshed) {
		t.Fatal("EventTokenRefreshed emitted after malformed refreshed ID token")
	}
}

func TestRefresh_RejectsMalformedIDToken(t *testing.T) {
	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
		oidctest.WithAccessTTL(5*time.Second), // beyond the 30s freshness buffer
		oidctest.WithRawRefreshIDToken("not.a.jwt"),
	)

	store := &oidctest.MemoryStore{}
	emitter := &oidctest.RecordingEmitter{}
	handler := oidctest.NewFakeFlowHandler(idp, redirectURI)
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: idp.IssuerURL(),
		ClientID:  "test-app",
	}, handler,
		pkceflow.WithTokenPersistence(store),
		pkceflow.WithEventEmitter(emitter),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := client.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	before, err := store.Load()
	if err != nil {
		t.Fatalf("load before refresh: %v", err)
	}
	emitter.Reset()

	if got := client.AccessToken(ctx); got != "" {
		t.Fatalf("AccessToken after malformed refreshed ID token = %q, want empty", got)
	}
	if emitter.HasEvent(pkceflow.EventTokenRefreshed) {
		t.Fatal("EventTokenRefreshed emitted after malformed refreshed ID token")
	}

	after, err := store.Load()
	if err != nil {
		t.Fatalf("load after refresh: %v", err)
	}
	if after.AccessToken != before.AccessToken {
		t.Error("malformed refreshed ID token still updated access token")
	}
	if after.IDToken != before.IDToken {
		t.Error("malformed refreshed ID token replaced the previous ID token")
	}
}

func TestNew_FreezesMutableConfigFields(t *testing.T) {
	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
	)

	scopes := []string{"openid"}
	authParams := map[string]string{"prompt": "login"}
	tokenParams := map[string]string{"requested_token_use": "on_behalf_of"}
	spy := &spyLogoutHandler{inner: oidctest.NewFakeFlowHandler(idp, redirectURI)}

	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL:        idp.IssuerURL(),
		ClientID:         "test-app",
		Scopes:           scopes,
		ExtraAuthParams:  authParams,
		ExtraTokenParams: tokenParams,
	}, spy, pkceflow.WithTokenPersistence(&oidctest.MemoryStore{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	scopes[0] = "profile"
	authParams["nonce"] = "attacker-nonce"
	authParams["client_secret"] = "auth-secret"
	tokenParams["code_verifier"] = "attacker-verifier"
	tokenParams["client_secret"] = "token-secret"

	ctx := context.Background()
	if err := client.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login failed after mutating caller-owned config fields: %v", err)
	}

	if len(spy.startAuthURLs) != 1 {
		t.Fatalf("StartAuthFlow called %d times, want 1", len(spy.startAuthURLs))
	}
	authURL, err := url.Parse(spy.startAuthURLs[0])
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	q := authURL.Query()
	if got := q.Get("scope"); got != "openid" {
		t.Errorf("scope = %q, want openid", got)
	}
	if got := q.Get("nonce"); got == "attacker-nonce" {
		t.Error("caller mutation changed nonce after New")
	}
	if got := q.Get("client_secret"); got != "" {
		t.Errorf("client_secret leaked into auth URL after caller mutation: %q", got)
	}
}

func TestLogin_PublicClient_NoBasicAuthProbe(t *testing.T) {
	// Model a public client (like Keycloak): the token endpoint rejects HTTP
	// Basic client auth and invalidates the code. If the client let oauth2 probe
	// Basic-first, the exchange would fail with invalid_grant ("Code not valid").
	// pkceflow must send client_id in the body (AuthStyleInParams) and never
	// attempt Basic auth.
	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
		oidctest.WithRejectBasicAuth(),
	)

	handler := oidctest.NewFakeFlowHandler(idp, redirectURI)
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: idp.IssuerURL(),
		ClientID:  "test-app",
	}, handler, pkceflow.WithTokenPersistence(&oidctest.MemoryStore{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := client.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login failed against a public client (auth-style probe regression): %v", err)
	}
	if !client.AuthStatus().Valid {
		t.Error("expected a valid session after login")
	}
}
