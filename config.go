package pkceflow

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// defaultScopes are the OIDC scopes requested if Config.Scopes is empty.
var defaultScopes = []string{"openid", "profile", "email", "offline_access"}

// DefaultScopes returns the default OIDC scopes requested when Config.Scopes
// is empty. Returns a fresh copy on each call, safe to mutate.
func DefaultScopes() []string {
	return append([]string(nil), defaultScopes...)
}

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
	// fails, for up to this duration since the last successful login or token
	// refresh. Zero means grace mode is disabled.
	//
	// Grace covers "the app could not reach the provider": transport failures,
	// timeouts, 5xx responses, and a refused client registration. It does not
	// cover "the app asked and was refused": when the provider rejects the
	// refresh token itself with invalid_grant, the session ends at once
	// regardless of how much of this period remains — unless that refusal cannot
	// be trusted as authoritative, because an earlier attempt was abandoned in
	// flight or stored state holds a newer refresh token.
	GracePeriod time.Duration

	// LoginTimeout is the maximum time to wait for the user to complete login.
	// Defaults to 2 minutes.
	LoginTimeout time.Duration

	// LogoutTimeout is the maximum time to wait for RP-Initiated Logout.
	// Defaults to 30 seconds.
	LogoutTimeout time.Duration

	// ExtraAuthParams are additional parameters sent on the authorization request.
	// Use for IdP quirks (e.g., "prompt"="login" for Entra ID, "audience" for Auth0).
	// Validate rejects protected OAuth/OIDC/PKCE parameters such as nonce,
	// state, scope, redirect_uri, code_challenge*, client_id, and client_secret.
	ExtraAuthParams map[string]string

	// ExtraTokenParams are additional parameters sent on the authorization-code
	// token exchange. They are not added to later refresh requests. Use only for
	// provider-specific, non-standard exchange parameters.
	// Validate rejects protected OAuth/OIDC/PKCE parameters such as grant_type,
	// code, code_verifier, redirect_uri, client_id, and client_secret.
	ExtraTokenParams map[string]string
}

var reservedExtraAuthParams = map[string]struct{}{
	"client_id":             {},
	"client_secret":         {},
	"code_challenge":        {},
	"code_challenge_method": {},
	"nonce":                 {},
	"redirect_uri":          {},
	"response_type":         {},
	"scope":                 {},
	"state":                 {},
}

var reservedExtraTokenParams = map[string]struct{}{
	"client_assertion":      {},
	"client_assertion_type": {},
	"client_id":             {},
	"client_secret":         {},
	"code":                  {},
	"code_verifier":         {},
	"grant_type":            {},
	"redirect_uri":          {},
}

// Validate checks required fields and applies defaults. Call before using the Config.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.IssuerURL) == "" {
		return errors.New("pkceflow: Config.IssuerURL is required")
	}
	if u, err := url.Parse(c.IssuerURL); err != nil {
		return fmt.Errorf("pkceflow: Config.IssuerURL is not a valid URL: %w", err)
	} else if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("pkceflow: Config.IssuerURL must be an absolute http(s) URL, got %q", c.IssuerURL)
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("pkceflow: Config.ClientID is required")
	}
	if err := validateExtraParams("ExtraAuthParams", c.ExtraAuthParams, reservedExtraAuthParams); err != nil {
		return err
	}
	if err := validateExtraParams("ExtraTokenParams", c.ExtraTokenParams, reservedExtraTokenParams); err != nil {
		return err
	}

	if len(c.Scopes) == 0 {
		c.Scopes = append([]string(nil), defaultScopes...)
	} else {
		c.Scopes = append([]string(nil), c.Scopes...)
	}
	c.ExtraAuthParams = cloneStringMap(c.ExtraAuthParams)
	c.ExtraTokenParams = cloneStringMap(c.ExtraTokenParams)
	if c.LoginTimeout == 0 {
		c.LoginTimeout = 2 * time.Minute
	}
	if c.LogoutTimeout == 0 {
		c.LogoutTimeout = 30 * time.Second
	}

	return nil
}

func validateExtraParams(name string, params map[string]string, reserved map[string]struct{}) error {
	for key := range params {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if _, ok := reserved[normalized]; ok {
			return fmt.Errorf("pkceflow: Config.%s must not set reserved OAuth/OIDC parameter %q", name, key)
		}
	}
	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// RedactedString returns a string representation of the config safe for logging.
// It never includes secrets or tokens.
func (c *Config) RedactedString() string {
	return fmt.Sprintf("Config{IssuerURL: %q, ClientID: %q, Scopes: %v, GracePeriod: %s, LoginTimeout: %s, LogoutTimeout: %s}",
		c.IssuerURL, c.ClientID, c.Scopes, c.GracePeriod, c.LoginTimeout, c.LogoutTimeout)
}
