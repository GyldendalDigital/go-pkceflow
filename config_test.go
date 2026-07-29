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
		{
			name:    "IssuerURL without scheme",
			config:  Config{IssuerURL: "idp.example.com", ClientID: "my-app"},
			wantErr: "absolute http(s) URL",
		},
		{
			name:    "IssuerURL with non-http scheme",
			config:  Config{IssuerURL: "ftp://idp.example.com", ClientID: "my-app"},
			wantErr: "absolute http(s) URL",
		},
		{
			name:    "IssuerURL with scheme but no host",
			config:  Config{IssuerURL: "https://", ClientID: "my-app"},
			wantErr: "absolute http(s) URL",
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

func TestConfig_Validate_AllowsProviderExtraParams(t *testing.T) {
	cfg := Config{
		IssuerURL: "https://idp.example.com",
		ClientID:  "my-app",
		ExtraAuthParams: map[string]string{
			"audience":   "https://api.example.com",
			"prompt":     "login",
			"login_hint": "user@example.com",
			"resource":   "api://resource",
		},
		ExtraTokenParams: map[string]string{
			"requested_token_use": "on_behalf_of",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_RejectsReservedExtraParams(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "auth nonce",
			config: Config{
				IssuerURL:       "https://idp.example.com",
				ClientID:        "my-app",
				ExtraAuthParams: map[string]string{"nonce": "override"},
			},
			wantErr: "nonce",
		},
		{
			name: "auth nonce normalized",
			config: Config{
				IssuerURL:       "https://idp.example.com",
				ClientID:        "my-app",
				ExtraAuthParams: map[string]string{" Nonce ": "override"},
			},
			wantErr: "Nonce",
		},
		{
			name: "auth code challenge",
			config: Config{
				IssuerURL:       "https://idp.example.com",
				ClientID:        "my-app",
				ExtraAuthParams: map[string]string{"code_challenge_method": "plain"},
			},
			wantErr: "code_challenge_method",
		},
		{
			name: "auth client secret",
			config: Config{
				IssuerURL:       "https://idp.example.com",
				ClientID:        "my-app",
				ExtraAuthParams: map[string]string{"client_secret": "secret"},
			},
			wantErr: "client_secret",
		},
		{
			name: "token verifier",
			config: Config{
				IssuerURL:        "https://idp.example.com",
				ClientID:         "my-app",
				ExtraTokenParams: map[string]string{"code_verifier": "override"},
			},
			wantErr: "code_verifier",
		},
		{
			name: "token client secret",
			config: Config{
				IssuerURL:        "https://idp.example.com",
				ClientID:         "my-app",
				ExtraTokenParams: map[string]string{"client_secret": "secret"},
			},
			wantErr: "client_secret",
		},
		{
			name: "token client secret normalized",
			config: Config{
				IssuerURL:        "https://idp.example.com",
				ClientID:         "my-app",
				ExtraTokenParams: map[string]string{" Client_Secret ": "secret"},
			},
			wantErr: "Client_Secret",
		},
		{
			name: "token redirect uri",
			config: Config{
				IssuerURL:        "https://idp.example.com",
				ClientID:         "my-app",
				ExtraTokenParams: map[string]string{"redirect_uri": "https://evil.example/callback"},
			},
			wantErr: "redirect_uri",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestConfig_Validate_CopiesMutableFields(t *testing.T) {
	scopes := []string{"openid"}
	authParams := map[string]string{"prompt": "login"}
	tokenParams := map[string]string{"requested_token_use": "on_behalf_of"}

	cfg := Config{
		IssuerURL:        "https://idp.example.com",
		ClientID:         "my-app",
		Scopes:           scopes,
		ExtraAuthParams:  authParams,
		ExtraTokenParams: tokenParams,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	scopes[0] = "profile"
	authParams["prompt"] = "none"
	authParams["nonce"] = "attacker"
	tokenParams["requested_token_use"] = "mutated"
	tokenParams["code_verifier"] = "attacker"

	if got := cfg.Scopes[0]; got != "openid" {
		t.Errorf("Scopes[0] = %q, want openid", got)
	}
	if got := cfg.ExtraAuthParams["prompt"]; got != "login" {
		t.Errorf("ExtraAuthParams[prompt] = %q, want login", got)
	}
	if _, ok := cfg.ExtraAuthParams["nonce"]; ok {
		t.Error("ExtraAuthParams changed after caller map mutation")
	}
	if got := cfg.ExtraTokenParams["requested_token_use"]; got != "on_behalf_of" {
		t.Errorf("ExtraTokenParams[requested_token_use] = %q, want on_behalf_of", got)
	}
	if _, ok := cfg.ExtraTokenParams["code_verifier"]; ok {
		t.Error("ExtraTokenParams changed after caller map mutation")
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
