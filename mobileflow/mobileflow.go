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
)

// Handler implements pkceflow.AuthFlowHandler for mobile applications.
// It opens the auth URL via an injected function and waits for the callback
// to be delivered via DeliverURL.
type Handler struct {
	redirectURI string
	openURL     func(string) error
	delivery    chan string
}

// New creates a Handler with the given redirect URI and URL opener.
// The redirectURI should be the claimed HTTPS URI registered with the IdP
// (e.g., "https://myapp.example.com/auth/callback").
// The openURL function is called to open the auth URL (e.g., via system browser).
func New(redirectURI string, openURL func(string) error) *Handler {
	return &Handler{
		redirectURI: redirectURI,
		openURL:     openURL,
		delivery:    make(chan string, 1),
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
	case url := <-h.delivery:
		return url, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// DeliverURL delivers the callback URL to a waiting StartAuthFlow call.
// If no flow is in progress, the delivery is silently dropped (no panic, no block).
// This should be called from the app's deep link handler when the IdP redirects back.
func (h *Handler) DeliverURL(url string) {
	select {
	case h.delivery <- url:
	default:
		// No flow waiting; drop silently
	}
}
