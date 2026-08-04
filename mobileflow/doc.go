// Package mobileflow provides an AuthFlowHandler for mobile applications.
//
// It opens the auth URL via an injected function and waits for the callback
// URL to be delivered via DeliverURL. This is a pure Go implementation with
// no platform dependencies; the platform-specific wiring (iOS Universal Links,
// Android App Links) is handled by the consumer or framework host. An adapter
// such as wails-pkceflow may forward URLs after the host surfaces them.
//
// Handler also implements pkceflow.LogoutFlowHandler for RP-Initiated Logout.
// One login or logout browser flow may be active at a time. DeliverURL ignores
// malformed and unrelated links, and resolves the active flow only when the
// callback URI and state match. For provider compatibility, logout alone also
// accepts a truly absent state after the complete post-logout redirect URI
// matches; empty, duplicate, and authorization-shaped callbacks are rejected.
// The post-logout redirect URI defaults to the login redirect URI; override it
// with SetLogoutURI when the IdP registers a distinct post_logout_redirect_uri.
//
// The active waiter and its surrounding login or logout transaction exist only
// in process memory. A callback delivered after process death has no active
// flow and is ignored; the application must start the flow again.
//
// The one-flow guard protects direct Handler users. Client coordinates calls
// into one handler under its documented lifecycle ordering; framework adapters
// may enforce a stricter busy policy for user experience.
//
// Usage:
//
//	handler := mobileflow.New("https://myapp.example.com/auth/callback", openURL)
//	client, _ := pkceflow.New(cfg, handler)
//
//	// In your browser-session completion or OS lifecycle callback:
//	handler.DeliverURL(callbackURL)
package mobileflow
