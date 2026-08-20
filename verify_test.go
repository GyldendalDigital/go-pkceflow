package pkceflow

import (
	"errors"
	"io"
	"log/slog"
	"testing"
)

// errAzpMismatch is only ever reachable through fmt.Errorf wrapping, and the
// integration tests live in package pkceflow_test where they cannot see it. This
// pins it as a real sentinel rather than a message prefix, which matters most on
// the login path: there the error is neither an *AuthError nor a
// session-integrity error, so errors.Is is the only way to identify it.
func TestCheckAuthorizedParty(t *testing.T) {
	client := &Client{
		config: Config{ClientID: "test-app"},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	tests := []struct {
		name     string
		claims   map[string]any
		audience []string
		wantErr  bool
	}{
		{
			name:     "absent with a single audience",
			claims:   map[string]any{},
			audience: []string{"test-app"},
		},
		{
			name:     "matching this client",
			claims:   map[string]any{"azp": "test-app"},
			audience: []string{"test-app"},
		},
		{
			name:     "matching with multiple audiences",
			claims:   map[string]any{"azp": "test-app"},
			audience: []string{"test-app", "https://api.example.com"},
		},
		{
			name:     "naming another client",
			claims:   map[string]any{"azp": "some-other-app"},
			audience: []string{"test-app"},
			wantErr:  true,
		},
		{
			// OIDC Core 3.1.3.7 step 4: azp is required once aud has more than
			// one value, and a client ID in aud does not protect against this.
			name:     "absent with multiple audiences",
			claims:   map[string]any{},
			audience: []string{"test-app", "https://api.example.com"},
			wantErr:  true,
		},
		{
			name:     "not a string",
			claims:   map[string]any{"azp": float64(1234)},
			audience: []string{"test-app"},
			wantErr:  true,
		},
		{
			name:     "JSON null",
			claims:   map[string]any{"azp": nil},
			audience: []string{"test-app"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.checkAuthorizedParty(tt.claims, tt.audience)
			if tt.wantErr {
				if !errors.Is(err, errAzpMismatch) {
					t.Fatalf("error = %v, want it to wrap errAzpMismatch", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
		})
	}
}
