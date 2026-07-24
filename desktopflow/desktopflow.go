// Package desktopflow provides an AuthFlowHandler for desktop applications.
// It starts a localhost HTTP server to capture the IdP callback after
// browser-based authentication.
//
// Usage:
//
//	handler := desktopflow.New(15051)
//	client, _ := pkceflow.New(cfg, handler)
//
// The handler binds to 127.0.0.1 only (never 0.0.0.0) per RFC 8252.
// The port must be pre-registered with the IdP as part of the redirect URI.
package desktopflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Handler implements pkceflow.AuthFlowHandler for desktop applications.
// It starts a localhost HTTP server, opens the auth URL in the system browser,
// and waits for the IdP to redirect back with the authorization code.
type Handler struct {
	redirectURI string
	host        string
	port        string
	path        string

	// OpenBrowser is called to open the auth URL in the user's browser.
	// If nil, DefaultBrowserOpener is used.
	OpenBrowser func(url string) error

	// SuccessHTML is the HTML page shown after successful authentication.
	// If empty, a default success page is shown.
	SuccessHTML string

	// ErrorHTML is the HTML page shown when the IdP returns an error.
	// If empty, a default error page is shown.
	ErrorHTML string
}

// New creates a Handler with redirect URI http://127.0.0.1:{port}/callback.
func New(port int) *Handler {
	uri := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	return &Handler{
		redirectURI: uri,
		host:        "127.0.0.1",
		port:        fmt.Sprintf("%d", port),
		path:        "/callback",
	}
}

// NewWithURI creates a Handler from a full redirect URI.
// The URI must use a loopback host (127.0.0.1, localhost, or [::1]).
// Returns an error if the host is not a loopback address.
func NewWithURI(uri string) (*Handler, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("desktopflow: invalid redirect URI: %w", err)
	}

	host := parsed.Hostname()
	if !isLoopback(host) {
		return nil, fmt.Errorf("desktopflow: redirect URI host %q is not a loopback address (must be 127.0.0.1, localhost, or [::1])", host)
	}

	port := parsed.Port()
	if port == "" {
		return nil, fmt.Errorf("desktopflow: redirect URI must include a port")
	}

	path := parsed.Path
	if path == "" {
		path = "/"
	}

	return &Handler{
		redirectURI: uri,
		host:        host,
		port:        port,
		path:        path,
	}, nil
}

// RedirectURI returns the configured redirect URI.
func (h *Handler) RedirectURI() string {
	return h.redirectURI
}

// StartAuthFlow starts the localhost HTTP server, opens the auth URL in the browser,
// and waits for the callback. Returns the full callback URL including query parameters.
// The context controls timeout/cancellation.
func (h *Handler) StartAuthFlow(ctx context.Context, authURL string) (string, error) {
	var (
		callbackURL string
		callbackErr error
		once        sync.Once
		done        = make(chan struct{})
	)

	mux := http.NewServeMux()
	mux.HandleFunc(h.path, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			// Reconstruct full callback URL
			callbackURL = h.redirectURI + "?" + r.URL.RawQuery

			// Check if IdP returned an error
			if r.URL.Query().Get("error") != "" {
				html := h.ErrorHTML
				if html == "" {
					html = defaultErrorHTML
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, html) //nolint:errcheck // response write failure surfaces as client-side error in test
			} else {
				html := h.SuccessHTML
				if html == "" {
					html = defaultSuccessHTML
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, html) //nolint:errcheck // response write failure surfaces as client-side error in test
			}
			close(done)
		})
	})

	addr := net.JoinHostPort(h.host, h.port)
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("desktopflow: failed to listen on %s: %w", addr, err)
	}

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start server in background
	serverErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			once.Do(func() {
				callbackErr = err
				close(done)
			})
		}
	}()

	// Open browser
	opener := h.OpenBrowser
	if opener == nil {
		opener = DefaultBrowserOpener
	}
	if err := opener(authURL); err != nil {
		_ = server.Close()
		return "", fmt.Errorf("desktopflow: failed to open browser: %w", err)
	}

	// Wait for callback or cancellation
	select {
	case <-done:
		// Callback received
	case <-ctx.Done():
		callbackErr = ctx.Err()
	case err := <-serverErr:
		callbackErr = fmt.Errorf("desktopflow: server error: %w", err)
	}

	// Shutdown server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)

	if callbackErr != nil {
		return "", callbackErr
	}
	return callbackURL, nil
}

// isLoopback checks if the host is a loopback address.
func isLoopback(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	// Check if it's an IP that resolves to loopback
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

const defaultSuccessHTML = `<!DOCTYPE html>
<html><head><title>Authentication Successful</title></head>
<body><h1>Authentication Successful</h1><p>You can close this window.</p></body></html>`

const defaultErrorHTML = `<!DOCTYPE html>
<html><head><title>Authentication Error</title></head>
<body><h1>Authentication Error</h1><p>An error occurred during authentication. Please try again.</p></body></html>`
