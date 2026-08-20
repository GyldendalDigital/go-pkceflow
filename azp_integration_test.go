package pkceflow_test

import (
	"context"
	"testing"
	"time"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"

	"github.com/GyldendalDigital/go-pkceflow/oidctest"
)

// TestLoginValidatesAzpClaim covers OIDC Core 3.1.3.7 steps 4 and 5. go-oidc
// only checks that the client ID appears in "aud", so without this validation an
// ID token issued to a different client, or a multi-audience token with no
// authorized party at all, was accepted.
func TestLoginValidatesAzpClaim(t *testing.T) {
	tests := []struct {
		name       string
		azp        string
		azpRawJSON string
		audiences  []string
		wantOK     bool
	}{
		{
			name:   "no azp, single audience",
			wantOK: true,
		},
		{
			name:   "azp naming this client",
			azp:    "test-app",
			wantOK: true,
		},
		{
			name: "azp naming another client",
			azp:  "some-other-app",
		},
		{
			name:      "multiple audiences with a matching azp",
			azp:       "test-app",
			audiences: []string{"test-app", "https://api.example.com"},
			wantOK:    true,
		},
		{
			// The spec makes azp mandatory once there is more than one audience,
			// and this is the shape the check exists to catch.
			name:      "multiple audiences with no azp",
			audiences: []string{"test-app", "https://api.example.com"},
		},
		{
			name:      "multiple audiences with a mismatched azp",
			azp:       "some-other-app",
			audiences: []string{"test-app", "https://api.example.com"},
		},
		{
			name:       "azp that is not a string",
			azpRawJSON: `1234`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, idp, _, _ := newTestClient(t)
			if tt.azp != "" {
				idp.SetForceAzp(tt.azp)
			}
			if tt.azpRawJSON != "" {
				idp.SetForceAzpRawJSON(tt.azpRawJSON)
			}
			if len(tt.audiences) > 0 {
				idp.SetForceAudiences(tt.audiences...)
			}

			ctx := context.Background()
			if err := client.Init(ctx); err != nil {
				t.Fatalf("Init: %v", err)
			}

			err := client.Login(ctx)
			if tt.wantOK {
				if err != nil {
					t.Fatalf("Login: %v", err)
				}
				if !client.AuthStatus().Valid {
					t.Fatal("session is not valid after an accepted ID token")
				}
				return
			}
			if err == nil {
				t.Fatal("Login accepted an ID token that does not authorize this client")
			}
			if client.AuthStatus().CanUseApp {
				t.Fatalf("session usable after a rejected ID token: %+v", client.AuthStatus())
			}
		})
	}
}

// TestRefreshRejectsAzpMismatchAsIntegrityFailure asserts the behaviour rather
// than the error text: mid-session, an ID token that names another client is a
// session-integrity failure, which fails closed even with a grace period
// configured. The access token is issued with a short lifetime so the first
// AccessToken call lands inside the expiry buffer and drives a real refresh.
func TestRefreshRejectsAzpMismatchAsIntegrityFailure(t *testing.T) {
	redirectURI := "http://127.0.0.1:9999/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
		oidctest.WithAccessTTL(10*time.Second),
	)
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL:   idp.IssuerURL(),
		ClientID:    "test-app",
		GracePeriod: 30 * 24 * time.Hour,
	}, oidctest.NewFakeFlowHandler(idp, redirectURI),
		pkceflow.WithTokenPersistence(&oidctest.MemoryStore{}),
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

	// From here the provider issues ID tokens naming a different client.
	idp.SetForceAzp("some-other-app")

	if token := client.AccessToken(ctx); token != "" {
		t.Fatalf("AccessToken = %q, want %q despite an open grace window", token, "")
	}
	if status := client.AuthStatus(); status.CanUseApp || status.GraceMode {
		t.Fatalf("AuthStatus = %+v, want fail-closed", status)
	}
}
