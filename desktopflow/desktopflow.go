// Package desktopflow provides an AuthFlowHandler for desktop applications.
// It starts a localhost HTTP server to capture the IdP callback after
// browser-based authentication.
//
// Usage:
//
//	handler := desktopflow.New(15051)
//	client, _ := pkceflow.New(cfg, handler)
//
// The handler binds to loopback only (127.0.0.1 and/or [::1]) per RFC 8252.
// The port must be pre-registered with the IdP as part of the redirect URI.
//
// Internally the handler uses a shared, reference-counted callback broker: one
// localhost server multiplexes every in-flight flow, routed by the callback path
// plus the OAuth2 state parameter. This lets multiple flows (for example several
// logins, or a login and a logout) run without colliding on the port, and
// ensures a callback resolves only the flow that started it. The port is opened
// lazily on the first flow and closed after a short grace period once the last
// flow completes, minimizing the open-port attack surface.
package desktopflow

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// shutdownGrace is how long the broker keeps its server alive after the last
// waiter clears, so rapid successive flows do not thrash bind/unbind. It is a
// var (not a const) so tests can shorten it.
var shutdownGrace = 2 * time.Second

// Handler implements pkceflow.AuthFlowHandler for desktop applications.
// It opens the auth URL in the system browser and waits for the IdP to redirect
// back with the authorization code, captured by a shared localhost broker.
type Handler struct {
	redirectURI string
	host        string
	port        string
	path        string

	broker *broker

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
	h := &Handler{
		redirectURI: uri,
		host:        "127.0.0.1",
		port:        fmt.Sprintf("%d", port),
		path:        "/callback",
	}
	h.broker = newBroker(loopbackAddrs(h.host, h.port), h.pageFor)
	return h
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

	h := &Handler{
		redirectURI: uri,
		host:        host,
		port:        port,
		path:        path,
	}
	h.broker = newBroker(loopbackAddrs(h.host, h.port), h.pageFor)
	return h, nil
}

// RedirectURI returns the configured redirect URI.
func (h *Handler) RedirectURI() string {
	return h.redirectURI
}

// StartAuthFlow opens the auth URL in the browser and waits for the callback on
// the handler's redirect path, matched by the state parameter carried in authURL.
// Returns the full callback URL including query parameters. The context controls
// timeout/cancellation.
func (h *Handler) StartAuthFlow(ctx context.Context, authURL string) (string, error) {
	return h.runFlow(ctx, authURL, h.path)
}

// runFlow registers a one-shot waiter keyed by (path, state), opens the browser,
// and waits for the matching callback or context cancellation.
func (h *Handler) runFlow(ctx context.Context, targetURL, path string) (string, error) {
	state := stateFromURL(targetURL)
	key := callbackKey(path, state)

	ch := make(chan callbackResult, 1)
	if err := h.broker.register(key, ch); err != nil {
		return "", err
	}
	defer h.broker.deregister(key)

	opener := h.OpenBrowser
	if opener == nil {
		opener = DefaultBrowserOpener
	}
	if err := opener(targetURL); err != nil {
		return "", fmt.Errorf("desktopflow: failed to open browser: %w", err)
	}

	select {
	case res := <-ch:
		if res.rawQuery == "" {
			return h.redirectURI, nil
		}
		return h.redirectURI + "?" + res.rawQuery, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// pageFor returns the HTML page to render for a callback response.
func (h *Handler) pageFor(isError bool) string {
	if isError {
		if h.ErrorHTML != "" {
			return h.ErrorHTML
		}
		return defaultErrorHTML
	}
	if h.SuccessHTML != "" {
		return h.SuccessHTML
	}
	return defaultSuccessHTML
}

// callbackResult carries the raw query string of a matched callback.
type callbackResult struct {
	rawQuery string
}

// broker is a shared, reference-counted localhost callback server. Flows register
// a one-shot waiter keyed by path+state; the server is started on the first
// registration and shut down a grace period after the last one clears.
type broker struct {
	addrs   []string
	pageFor func(isError bool) string
	grace   time.Duration

	mu         sync.Mutex
	waiters    map[string]chan<- callbackResult
	server     *http.Server
	listeners  []net.Listener
	graceTimer *time.Timer
}

func newBroker(addrs []string, pageFor func(isError bool) string) *broker {
	return &broker{
		addrs:   addrs,
		pageFor: pageFor,
		grace:   shutdownGrace,
		waiters: make(map[string]chan<- callbackResult),
	}
}

// register adds a one-shot waiter and ensures the server is running. It returns
// an error if the key is already registered or if the server fails to bind.
func (b *broker) register(key string, ch chan<- callbackResult) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, dup := b.waiters[key]; dup {
		return fmt.Errorf("desktopflow: a callback is already registered for this path and state")
	}
	if b.graceTimer != nil {
		b.graceTimer.Stop()
		b.graceTimer = nil
	}
	if b.server == nil {
		if err := b.startLocked(); err != nil {
			return err
		}
	}
	b.waiters[key] = ch
	return nil
}

// deregister removes a waiter (if still present) and schedules a grace shutdown
// when the broker becomes idle.
func (b *broker) deregister(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.waiters[key]; !ok {
		return
	}
	delete(b.waiters, key)
	b.scheduleShutdownLocked()
}

// scheduleShutdownLocked arms the grace timer if the broker is idle. Caller must
// hold b.mu.
func (b *broker) scheduleShutdownLocked() {
	if len(b.waiters) == 0 && b.server != nil && b.graceTimer == nil {
		b.graceTimer = time.AfterFunc(b.grace, b.graceShutdown)
	}
}

// graceShutdown closes the server if the broker is still idle. If a flow
// registered during the grace window, the shutdown is aborted; a later register
// would in any case restart the server since it re-checks server == nil.
func (b *broker) graceShutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.graceTimer = nil
	if len(b.waiters) != 0 || b.server == nil {
		return
	}
	_ = b.server.Close()
	b.server = nil
	b.listeners = nil
}

// startLocked binds the loopback addresses and serves them from one mux. It
// succeeds if at least one address binds (IPv6 may be disabled). Caller must
// hold b.mu.
func (b *broker) startLocked() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", b.handle)
	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	var (
		listeners []net.Listener
		lastErr   error
	)
	for _, addr := range b.addrs {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
		if err != nil {
			lastErr = err
			continue
		}
		listeners = append(listeners, ln)
	}
	if len(listeners) == 0 {
		return fmt.Errorf("desktopflow: failed to listen on %v: %w", b.addrs, lastErr)
	}

	b.server = server
	b.listeners = listeners
	for _, ln := range listeners {
		go func(l net.Listener) {
			_ = server.Serve(l)
		}(ln)
	}
	return nil
}

// handle routes an incoming callback to the waiter registered for its path and
// state. Unmatched requests receive the same success page as matched ones (no
// distinguishable "unknown state" response), so a local process cannot probe for
// live flows.
func (b *broker) handle(w http.ResponseWriter, r *http.Request) {
	key := callbackKey(r.URL.Path, r.URL.Query().Get("state"))

	b.mu.Lock()
	ch, ok := b.waiters[key]
	if ok {
		delete(b.waiters, key)
		b.scheduleShutdownLocked()
	}
	b.mu.Unlock()

	isError := ok && r.URL.Query().Get("error") != ""
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, b.pageFor(isError)) //nolint:errcheck // response write failure surfaces as client-side error

	if ok {
		ch <- callbackResult{rawQuery: r.URL.RawQuery}
	}
}

// callbackKey builds the broker map key from a callback path and state. The NUL
// separator cannot appear in a URL path or state, so keys never collide across
// path/state boundaries.
func callbackKey(path, state string) string {
	return path + "\x00" + state
}

// stateFromURL extracts the OAuth2 state parameter from a URL, or "" if absent.
func stateFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("state")
}

// loopbackAddrs returns the loopback addresses to bind for the given host. For
// "localhost" it returns both IPv4 and IPv6 loopback so a callback resolving to
// either family is captured. For a specific loopback IP it returns just that
// address. It never returns a wildcard address.
func loopbackAddrs(host, port string) []string {
	if host == "localhost" {
		return []string{
			net.JoinHostPort("127.0.0.1", port),
			net.JoinHostPort("::1", port),
		}
	}
	return []string{net.JoinHostPort(host, port)}
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
