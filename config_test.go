package pkceflow

import (
	"testing"
	"time"
)

func TestConfig_Validate_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name:    "empty IssuerURL",
			config:  Config{ClientID: "my-app"},
			wantErr: "IssuerURL is required",
		},
		{
			name:    "whitespace IssuerURL",
			config:  Config{IssuerURL: "  ", ClientID: "my-app"},
			wantErr: "IssuerURL is required",
		},
		{
			name:    "empty ClientID",
			config:  Config{IssuerURL: "https://idp.example.com"},
			wantErr: "ClientID is required",
		},
		{
			name:    "whitespace ClientID",
			config:  Config{IssuerURL: "https://idp.example.com", ClientID: "  "},
			wantErr: "ClientID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := err.Error(); !contains(got, tt.wantErr) {
				t.Errorf("error = %q, want substring %q", got, tt.wantErr)
			}
		})
	}
}

func TestConfig_Validate_Defaults(t *testing.T) {
	cfg := Config{
		IssuerURL: "https://idp.example.com",
		ClientID:  "my-app",
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Scopes) != len(DefaultScopes) {
		t.Errorf("Scopes = %v, want %v", cfg.Scopes, DefaultScopes)
	}
	for i, s := range cfg.Scopes {
		if s != DefaultScopes[i] {
			t.Errorf("Scopes[%d] = %q, want %q", i, s, DefaultScopes[i])
		}
	}

	if cfg.LoginTimeout != 2*time.Minute {
		t.Errorf("LoginTimeout = %v, want 2m", cfg.LoginTimeout)
	}
	if cfg.LogoutTimeout != 30*time.Second {
		t.Errorf("LogoutTimeout = %v, want 30s", cfg.LogoutTimeout)
	}
}

func TestConfig_Validate_PreservesExplicitValues(t *testing.T) {
	cfg := Config{
		IssuerURL:     "https://idp.example.com",
		ClientID:      "my-app",
		Scopes:        []string{"openid", "custom"},
		LoginTimeout:  5 * time.Minute,
		LogoutTimeout: 1 * time.Minute,
		GracePeriod:   30 * 24 * time.Hour,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Scopes) != 2 || cfg.Scopes[0] != "openid" || cfg.Scopes[1] != "custom" {
		t.Errorf("Scopes overwritten: %v", cfg.Scopes)
	}
	if cfg.LoginTimeout != 5*time.Minute {
		t.Errorf("LoginTimeout overwritten: %v", cfg.LoginTimeout)
	}
	if cfg.LogoutTimeout != 1*time.Minute {
		t.Errorf("LogoutTimeout overwritten: %v", cfg.LogoutTimeout)
	}
}

func TestConfig_RedactedString_NoSecrets(t *testing.T) {
	cfg := Config{
		IssuerURL: "https://idp.example.com",
		ClientID:  "my-app",
		ExtraAuthParams: map[string]string{
			"audience": "https://api.example.com",
		},
		ExtraTokenParams: map[string]string{
			"access_type": "offline",
		},
	}

	s := cfg.RedactedString()

	// Should contain the non-secret fields
	if !contains(s, "idp.example.com") {
		t.Errorf("RedactedString missing IssuerURL: %s", s)
	}
	if !contains(s, "my-app") {
		t.Errorf("RedactedString missing ClientID: %s", s)
	}

	// ExtraAuthParams/ExtraTokenParams are not included (could contain secrets)
	if contains(s, "audience") || contains(s, "access_type") {
		t.Errorf("RedactedString leaks extra params: %s", s)
	}
}

func TestConfig_Validate_DefaultScopesCopied(t *testing.T) {
	cfg := Config{
		IssuerURL: "https://idp.example.com",
		ClientID:  "my-app",
	}
	_ = cfg.Validate()

	// Mutating the config's scopes should not affect DefaultScopes
	cfg.Scopes[0] = "mutated"
	if DefaultScopes[0] == "mutated" {
		t.Error("Config.Validate did not copy DefaultScopes (shares backing array)")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s != "" && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
