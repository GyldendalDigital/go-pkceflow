package pkceflow

import (
	"log/slog"
	"net/http"
)

// Option configures optional Client dependencies.
// Use With* functions to create options.
type Option func(*clientOptions)

// clientOptions holds the optional dependencies for a Client.
type clientOptions struct {
	store      TokenPersistence
	emitter    EventEmitter
	logger     *slog.Logger
	httpClient *http.Client
}

// WithTokenPersistence sets the token persistence backend.
// If not provided, tokens are stored in memory only (lost on restart).
func WithTokenPersistence(store TokenPersistence) Option {
	return func(o *clientOptions) {
		o.store = store
	}
}

// WithEventEmitter sets the event emitter for auth lifecycle events.
// If not provided, events are silently dropped.
func WithEventEmitter(emitter EventEmitter) Option {
	return func(o *clientOptions) {
		o.emitter = emitter
	}
}

// WithLogger sets the structured logger for the Client.
// If not provided, slog.Default() is used.
func WithLogger(logger *slog.Logger) Option {
	return func(o *clientOptions) {
		o.logger = logger
	}
}

// WithHTTPClient sets the HTTP client used for every outbound request the
// Client makes: OIDC discovery, JWKS fetching during ID-token verification,
// token exchange, token refresh, and token revocation on logout. Use it for
// corporate proxies, custom CA bundles or mutual TLS, and transport tuning
// (connection pools, per-transport timeouts).
//
// If not provided, the default HTTP client is used. The library never mutates
// the client and never disables TLS verification on your behalf; supplying a
// client that skips verification or drops redirects is your explicit choice.
// Context deadlines (LoginTimeout, LogoutTimeout, and any ctx you pass) still
// apply independently of the client's own Timeout.
//
// One exception to "never mutates": the revocation request runs on a shallow
// copy whose CheckRedirect refuses to follow redirects, whatever the supplied
// client does. Go replays a request body on 307 and 308, and the revocation
// endpoint comes from the discovery document, so following one could hand the
// refresh token to another host.
func WithHTTPClient(hc *http.Client) Option {
	return func(o *clientOptions) {
		o.httpClient = hc
	}
}
