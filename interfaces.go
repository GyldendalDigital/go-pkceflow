package pkceflow

import "context"

// AuthFlowHandler handles the platform-specific part of the authorization flow:
// opening the auth URL (typically in a browser) and capturing the callback.
//
// Implementations:
//   - desktopflow.Handler: localhost HTTP server + system browser
//   - mobileflow.Handler: channel-based, waits for DeliverURL from deep link handler
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
type EventEmitter interface {
	// Emit sends a named event with optional associated data.
	Emit(event string, data any)
}

// EventListener subscribes to auth lifecycle events.
type EventListener interface {
	// On registers a handler for the named event. Returns an unsubscribe function.
	On(event string, handler func(data any)) func()
}

// EventBus combines event emission and subscription.
type EventBus interface {
	EventEmitter
	EventListener
}

// BrowserOpener is a function that opens a URL in the user's default browser.
// Used by desktopflow.Handler; consumers can override with their own implementation
// (e.g., Wails app.Browser.OpenURL).
type BrowserOpener func(url string) error
