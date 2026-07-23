package pkceflow

import "time"

// TokenState holds the tokens and metadata from an OIDC authentication.
// This is what gets persisted by TokenPersistence and held in memory by Client.
type TokenState struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastAuthAt   time.Time `json:"last_auth_at"`
}

// IsZero reports whether the token state is empty (no tokens stored).
func (ts TokenState) IsZero() bool {
	return ts.AccessToken == "" && ts.RefreshToken == "" && ts.IDToken == ""
}

// AuthStatusResult reports the current authentication state.
// Consumers use this to decide UI behavior (show login, show grace warning, etc.).
type AuthStatusResult struct {
	// Valid is true when the access token has not expired (with 30s buffer).
	Valid bool `json:"valid"`

	// GraceMode is true when the token is expired but within the configured
	// grace period. Only possible when Config.GracePeriod > 0.
	GraceMode bool `json:"grace_mode"`

	// GraceDaysLeft is the number of days remaining in the grace period.
	// Zero when not in grace mode.
	GraceDaysLeft int `json:"grace_days_left"`

	// CanUseApp is true when the user has a usable session (Valid || GraceMode).
	CanUseApp bool `json:"can_use_app"`
}
