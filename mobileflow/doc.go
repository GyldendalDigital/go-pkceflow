// Package mobileflow provides an AuthFlowHandler for mobile applications.
//
// It opens the auth URL via an injected function and waits for the callback
// URL to be delivered via DeliverURL. This is a pure Go implementation with
// no platform dependencies; the platform-specific wiring (iOS Universal Links,
// Android App Links) is handled by the consumer or a wrapper like wails-pkceflow.
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
// The one-flow guard protects callback routing inside Handler. It does not
// serialize higher-level client operations; applications should not invoke
// Client.Login and Client.Logout concurrently.
//
// Usage:
//
//	handler := mobileflow.New("https://myapp.example.com/auth/callback", openURL)
//	client, _ := pkceflow.New(cfg, handler)
//
//	// In your deep link handler (platform-specific):
//	handler.DeliverURL(callbackURL)
package mobileflow
