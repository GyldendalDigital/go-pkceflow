// Package mobileflow provides an AuthFlowHandler for mobile applications.
// It opens the auth URL via an injected function and waits for the callback
// URL to be delivered via DeliverURL (called from the app's deep link handler).
//
// This is a pure Go, framework-agnostic implementation. The platform-specific
// wiring (subscribing to iOS Universal Links or Android App Links) is done
// by the consumer or a wrapper like wails-pkceflow.
//
// Usage:
//
//	handler := mobileflow.New("https://myapp.example.com/auth/callback", openURL)
//	client, _ := pkceflow.New(cfg, handler)
//
//	// In your deep link handler:
//	handler.DeliverURL(callbackURL)
package mobileflow

import (
	"context"
	"fmt"
	"net/url"
)

// Handler implements pkceflow.AuthFlowHandler for mobile applications.
// It opens the auth URL via an injected function and waits for the callback
// to be delivered via DeliverURL.
type Handler struct {
	redirectURI       string
	logoutRedirectURI string
	openURL           func(string) error
	delivery          chan string
}

// New creates a Handler with the given redirect URI and URL opener.
// The redirectURI should be the claimed HTTPS URI registered with the IdP
// (e.g., "https://myapp.example.com/auth/callback").
// The openURL function is called to open the auth URL (e.g., via system browser).
func New(redirectURI string, openURL func(string) error) *Handler {
	return &Handler{
		redirectURI: redirectURI,
		// Logout defaults to the login redirect URI; override with SetLogoutURI
		// when the IdP registers a distinct post_logout_redirect_uri.
		logoutRedirectURI: redirectURI,
		openURL:           openURL,
		delivery:          make(chan string, 1),
	}
}

// RedirectURI returns the configured redirect URI.
func (h *Handler) RedirectURI() string {
	return h.redirectURI
}

// StartAuthFlow opens the auth URL and blocks until DeliverURL is called
// or the context is cancelled.
func (h *Handler) StartAuthFlow(ctx context.Context, authURL string) (string, error) {
	// Drain any stale delivery from a previous cancelled flow
	select {
	case <-h.delivery:
	default:
	}

	if err := h.openURL(authURL); err != nil {
		return "", fmt.Errorf("mobileflow: failed to open auth URL: %w", err)
	}

	select {
	case callbackURL := <-h.delivery:
		return callbackURL, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// DeliverURL delivers the callback URL to a waiting StartAuthFlow call.
// If no flow is in progress, the delivery is silently dropped (no panic, no block).
// This should be called from the app's deep link handler when the IdP redirects back.
func (h *Handler) DeliverURL(callbackURL string) {
	select {
	case h.delivery <- callbackURL:
	default:
		// No flow waiting; drop silently
	}
}

// StartLogoutFlow opens the end-session URL and blocks until DeliverURL is
// called with the post-logout callback or the context is cancelled. It reuses
// the same delivery channel as StartAuthFlow, so the app's deep link handler
// needs no additional wiring. It implements pkceflow.LogoutFlowHandler.
func (h *Handler) StartLogoutFlow(ctx context.Context, logoutURL string) (string, error) {
	// Drain any stale delivery from a previous cancelled flow
	select {
	case <-h.delivery:
	default:
	}

	if err := h.openURL(logoutURL); err != nil {
		return "", fmt.Errorf("mobileflow: failed to open logout URL: %w", err)
	}

	select {
	case callbackURL := <-h.delivery:
		return callbackURL, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// PostLogoutRedirectURI returns the URI sent as post_logout_redirect_uri. It
// defaults to the login redirect URI unless SetLogoutURI was called. It
// implements pkceflow.LogoutFlowHandler.
func (h *Handler) PostLogoutRedirectURI() string {
	return h.logoutRedirectURI
}

// SetLogoutURI configures a distinct post-logout redirect URI for RP-Initiated
// Logout. IdPs commonly register post_logout_redirect_uris separately from
// redirect_uris. The URI must be a non-empty, parseable claimed HTTPS URI or
// custom scheme URI registered with the IdP; unlike desktop there is no
// loopback constraint because mobile callbacks arrive via deep links.
func (h *Handler) SetLogoutURI(uri string) error {
	if uri == "" {
		return fmt.Errorf("mobileflow: logout URI must not be empty")
	}
	if _, err := url.Parse(uri); err != nil {
		return fmt.Errorf("mobileflow: invalid logout URI: %w", err)
	}
	h.logoutRedirectURI = uri
	return nil
}
