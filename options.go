package pkceflow

import "log/slog"

// Option configures optional Client dependencies.
// Use With* functions to create options.
type Option func(*clientOptions)

// clientOptions holds the optional dependencies for a Client.
type clientOptions struct {
	store   TokenPersistence
	emitter EventEmitter
	logger  *slog.Logger
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
