// Package mobileflow provides an AuthFlowHandler for mobile applications.
//
// It opens the auth URL via an injected function and waits for the callback
// URL to be delivered via DeliverURL. This is a pure Go implementation with
// no platform dependencies; the platform-specific wiring (iOS Universal Links,
// Android App Links) is handled by the consumer or a wrapper like wails-pkceflow.
//
// Handler also implements pkceflow.LogoutFlowHandler for RP-Initiated Logout.
// StartLogoutFlow reuses the same delivery channel as StartAuthFlow, so the
// app's deep link handler needs no extra wiring. The post-logout redirect URI
// defaults to the login redirect URI; override it with SetLogoutURI when the
// IdP registers a distinct post_logout_redirect_uri.
//
// Usage:
//
//	handler := mobileflow.New("https://myapp.example.com/auth/callback", openURL)
//	client, _ := pkceflow.New(cfg, handler)
//
//	// In your deep link handler (platform-specific):
//	handler.DeliverURL(callbackURL)
package mobileflow
