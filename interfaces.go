package pkceflow

import "context"

// AuthFlowHandler handles the platform-specific part of the authorization flow:
// opening the auth URL (typically in a browser) and capturing the callback.
//
// Implementations:
//   - desktopflow.Handler: localhost HTTP server + system browser
//   - mobileflow.Handler: state-correlated DeliverURL routing from a deep link handler
type AuthFlowHandler interface {
	// StartAuthFlow opens the authorization URL and waits for the callback.
	// Returns the full callback URL including query parameters (code, state, error).
	// The context controls timeout/cancellation of the flow.
	StartAuthFlow(ctx context.Context, authURL string) (callbackURL string, err error)

	// RedirectURI returns the redirect URI that this handler listens on.
	// This is registered with the IdP and used in the authorization request.
	RedirectURI() string
}

// LogoutFlowHandler is an OPTIONAL interface an AuthFlowHandler may implement to
// run RP-Initiated Logout on a redirect URI that differs from the login redirect
// URI (a different path, or a fully different loopback URI). IdPs commonly
// register post_logout_redirect_uris in a list that is separate from
// redirect_uris, so the logout callback may need a distinct URI.
//
// When a handler does not implement this interface, Logout falls back to
// StartAuthFlow and RedirectURI (the same URI as login), disambiguated by state.
type LogoutFlowHandler interface {
	// StartLogoutFlow opens the end-session URL and waits for the post-logout
	// callback, mirroring StartAuthFlow but for the logout redirect.
	StartLogoutFlow(ctx context.Context, logoutURL string) (callbackURL string, err error)

	// PostLogoutRedirectURI returns the URI to send as post_logout_redirect_uri.
	// An empty string means "use the login RedirectURI".
	PostLogoutRedirectURI() string
}

// TokenPersistence handles saving and loading token state across app restarts.
//
// Implementations:
//   - filestore.Store: AES-256-GCM encrypted file (default for v1)
//   - oidctest.MemoryStore: in-memory for testing
//
// The default filestore encrypts tokens at rest with AES-256-GCM. Combined with
// per-user file permissions on desktop and the application sandbox on mobile,
// this is sufficient for storing typical OIDC tokens, and keeps the default
// dependency-free and CGo-free. Consumers with stricter requirements (an OS
// keyring or Keychain, a hardware-backed keystore, or a secure enclave) can
// implement this interface and inject it via WithTokenPersistence, with no other
// code changes.
//
// Client serializes calls to these methods with token-state transitions.
// Implementations must not synchronously call back into Client methods that can
// mutate or refresh token state.
type TokenPersistence interface {
	// Save persists the token state. Called after login and token refresh.
	Save(state TokenState) error

	// Load retrieves persisted token state. Returns zero TokenState (not error)
	// if no state exists or the stored data is corrupted/unreadable.
	Load() (TokenState, error)

	// Delete removes persisted token state. Called on logout.
	Delete() error
}

// EventEmitter emits auth lifecycle events. Consumers provide an implementation
// that bridges to their framework's event system (e.g., Wails app events).
// Client serializes Emit calls in token-state commit order and does not hold its
// state or persistence locks while invoking the implementation. An event queued
// while another callback is active may be delivered after its originating
// Client operation returns.
type EventEmitter interface {
	// Emit sends a named event with optional associated data.
	Emit(event string, data any)
}
