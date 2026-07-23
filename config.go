package pkceflow

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultScopes are the OIDC scopes requested if Config.Scopes is empty.
var DefaultScopes = []string{"openid", "profile", "email", "offline_access"}

// Config holds the OIDC client configuration.
// RedirectURI is not included here; it is owned by the AuthFlowHandler.
type Config struct {
	// IssuerURL is the OIDC provider's issuer URL (used for discovery).
	// Required.
	IssuerURL string

	// ClientID is the OAuth2 client identifier registered with the IdP.
	// Required.
	ClientID string

	// Scopes to request during authorization. Defaults to DefaultScopes.
	Scopes []string

	// GracePeriod allows the app to continue functioning after token refresh
	// fails, for up to this duration since last successful authentication.
	// Zero means grace mode is disabled.
	GracePeriod time.Duration

	// LoginTimeout is the maximum time to wait for the user to complete login.
	// Defaults to 2 minutes.
	LoginTimeout time.Duration

	// LogoutTimeout is the maximum time to wait for RP-Initiated Logout.
	// Defaults to 30 seconds.
	LogoutTimeout time.Duration

	// ExtraAuthParams are additional parameters sent on the authorization request.
	// Use for IdP quirks (e.g., "prompt"="login" for Entra ID, "audience" for Auth0).
	ExtraAuthParams map[string]string

	// ExtraTokenParams are additional parameters sent on the token request.
	// Use for IdP quirks (e.g., "access_type"="offline" for Google).
	ExtraTokenParams map[string]string
}

// Validate checks required fields and applies defaults. Call before using the Config.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.IssuerURL) == "" {
		return errors.New("pkceflow: Config.IssuerURL is required")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("pkceflow: Config.ClientID is required")
	}

	if len(c.Scopes) == 0 {
		c.Scopes = append([]string(nil), DefaultScopes...)
	}
	if c.LoginTimeout == 0 {
		c.LoginTimeout = 2 * time.Minute
	}
	if c.LogoutTimeout == 0 {
		c.LogoutTimeout = 30 * time.Second
	}

	return nil
}

// RedactedString returns a string representation of the config safe for logging.
// It never includes secrets or tokens.
func (c *Config) RedactedString() string {
	return fmt.Sprintf("Config{IssuerURL: %q, ClientID: %q, Scopes: %v, GracePeriod: %s, LoginTimeout: %s, LogoutTimeout: %s}",
		c.IssuerURL, c.ClientID, c.Scopes, c.GracePeriod, c.LoginTimeout, c.LogoutTimeout)
}
