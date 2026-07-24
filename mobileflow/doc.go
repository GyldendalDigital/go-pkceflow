// Package mobileflow provides an AuthFlowHandler for mobile applications.
//
// It opens the auth URL via an injected function and waits for the callback
// URL to be delivered via DeliverURL. This is a pure Go implementation with
// no platform dependencies; the platform-specific wiring (iOS Universal Links,
// Android App Links) is handled by the consumer or a wrapper like wails-pkceflow.
//
// Usage:
//
//	handler := mobileflow.New("https://myapp.example.com/auth/callback", openURL)
//	client, _ := pkceflow.New(cfg, handler)
//
//	// In your deep link handler (platform-specific):
//	handler.DeliverURL(callbackURL)
package mobileflow
