package pkceflow

// Auth lifecycle events emitted by the Client via EventEmitter.
//
// The typical event sequence for a successful session:
//
//	Init succeeds    -> (no event, Init is silent on success)
//	Login completes  -> EventLoggedIn
//	Token refreshed  -> EventTokenRefreshed (repeats on schedule)
//	User logs out    -> EventLoggedOut
//
// Error scenarios:
//
//	Init fails           -> EventInitFailed (non-fatal, app continues offline)
//	Refresh permanently fails -> EventSessionExpired (user must re-authenticate)
const (
	// EventLoggedIn is emitted after a successful Login() token exchange.
	EventLoggedIn = "oidcauth:logged-in"

	// EventLoggedOut is emitted after Logout() clears auth state.
	EventLoggedOut = "oidcauth:logged-out"

	// EventTokenRefreshed is emitted after any successful token refresh,
	// including one triggered synchronously by AccessToken.
	EventTokenRefreshed = "oidcauth:token-refreshed" //nolint:gosec // G101 false positive: not a credential

	// EventSessionExpired is emitted when the refresh token is permanently
	// invalid (e.g., revoked) and the grace period (if configured) has expired,
	// or when a refresh response fails session-integrity checks.
	EventSessionExpired = "oidcauth:session-expired"

	// EventInitFailed is emitted when Init() fails to perform OIDC discovery.
	// This is non-fatal: the app can continue offline with cached tokens
	// from RestoreSession().
	EventInitFailed = "oidcauth:init-failed"
)
