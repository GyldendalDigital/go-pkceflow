package pkceflow

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Claims holds the standard OpenID Connect claims decoded from an ID token,
// plus the full raw claim set for provider-specific fields.
//
// The values come from the ID token payload, which the IdP signed to describe
// the authenticated user. Access tokens are deliberately not decoded: they are
// opaque to clients per RFC 6750, and their format is not guaranteed.
type Claims struct {
	Subject           string
	Name              string
	GivenName         string
	FamilyName        string
	PreferredUsername string
	Email             string
	EmailVerified     bool
	Issuer            string
	Audience          []string
	ExpiresAt         time.Time
	IssuedAt          time.Time
	AuthTime          time.Time

	// Raw holds every claim in the ID token payload, including any not mapped
	// to a typed field above (e.g., "groups", "roles", tenant identifiers).
	Raw map[string]any
}

// Get returns the raw value of an arbitrary claim by name, and whether it was
// present. Use it for provider-specific claims not exposed as typed fields.
func (c *Claims) Get(name string) (any, bool) {
	v, ok := c.Raw[name]
	return v, ok
}

// Claims decodes the claims from the current session's ID token. It returns
// ErrNotAuthenticated when no ID token is held.
//
// Success is not proof of a usable session: a session the provider has refused
// keeps its ID token precisely so a re-authentication prompt can name the user.
// AuthStatus is authoritative for usability.
//
// The ID token signature is not verified: go-oidc already verified it during
// the token exchange. This method inspects the already-trusted token to read
// user attributes. Do not use it to validate tokens received from elsewhere.
func (c *Client) Claims() (Claims, error) {
	c.mu.Lock()
	idToken := c.state.IDToken
	c.mu.Unlock()

	if idToken == "" {
		return Claims{}, ErrNotAuthenticated
	}
	return DecodeIDToken(idToken)
}

// DecodeIDToken decodes the claims from a raw JWT ID token WITHOUT verifying its
// signature. It is intended for inspecting a token that was already verified
// during the OIDC exchange (for example, the token held by a Client). Never use
// it to trust a token obtained from an untrusted source.
func DecodeIDToken(raw string) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("pkceflow: malformed ID token: expected 3 JWT segments, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("pkceflow: decoding ID token payload: %w", err)
	}

	var claimSet map[string]any
	if err := json.Unmarshal(payload, &claimSet); err != nil {
		return Claims{}, fmt.Errorf("pkceflow: parsing ID token claims: %w", err)
	}

	claims := Claims{
		Subject:           stringClaim(claimSet, "sub"),
		Name:              stringClaim(claimSet, "name"),
		GivenName:         stringClaim(claimSet, "given_name"),
		FamilyName:        stringClaim(claimSet, "family_name"),
		PreferredUsername: stringClaim(claimSet, "preferred_username"),
		Email:             stringClaim(claimSet, "email"),
		EmailVerified:     boolClaim(claimSet, "email_verified"),
		Issuer:            stringClaim(claimSet, "iss"),
		Audience:          audienceClaim(claimSet, "aud"),
		ExpiresAt:         timeClaim(claimSet, "exp"),
		IssuedAt:          timeClaim(claimSet, "iat"),
		AuthTime:          timeClaim(claimSet, "auth_time"),
		Raw:               claimSet,
	}
	return claims, nil
}

func stringClaim(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func boolClaim(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

// audienceClaim handles the "aud" claim, which per RFC 7519 may be a single
// string or an array of strings.
func audienceClaim(m map[string]any, key string) []string {
	switch v := m[key].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// timeClaim handles numeric date claims (exp, iat, auth_time), which JSON
// unmarshals to float64. Returns the zero time when the claim is absent or not
// numeric.
func timeClaim(m map[string]any, key string) time.Time {
	if v, ok := m[key].(float64); ok {
		return time.Unix(int64(v), 0).UTC()
	}
	return time.Time{}
}
