package pkceflow_test

import (
	"context"
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
