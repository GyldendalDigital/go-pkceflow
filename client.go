package pkceflow

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Client is the main entry point for OIDC PKCE authentication.
// Create one with New(), call Init() for OIDC discovery, then use
// Login/Logout/AccessToken to manage the auth lifecycle.
type Client struct {
	config  Config
	flow    AuthFlowHandler
	store   TokenPersistence
	emitter EventEmitter
	logger  *slog.Logger

	mu       sync.Mutex
	state    TokenState
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth2   *oauth2.Config

	endSessionEndpoint string

	refreshCancel func() // cancels the active refresh loop
}

// New creates a new Client with the given configuration and flow handler.
// The flow handler is required; it determines how the user authenticates
// (e.g., localhost callback for desktop, deep link for mobile).
//
// Options can override defaults:
//   - WithTokenPersistence: default is in-memory (lost on restart)
//   - WithEventEmitter: default is no-op (events silently dropped)
//   - WithLogger: default is slog.Default()
func New(cfg Config, flow AuthFlowHandler, opts ...Option) (*Client, error) {
	if flow == nil {
		return nil, errors.New("pkceflow: AuthFlowHandler is required")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	options := &clientOptions{}
	for _, opt := range opts {
		opt(options)
	}

	c := &Client{
		config: cfg,
		flow:   flow,
		store:  options.store,
		emitter: options.emitter,
		logger: options.logger,
	}

	if c.store == nil {
		c.store = &memoryStore{}
	}
	if c.emitter == nil {
		c.emitter = noopEmitter{}
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}

	return c, nil
}

// memoryStore is a minimal in-memory TokenPersistence used as the default
// when no store is provided via WithTokenPersistence.
type memoryStore struct {
	mu    sync.Mutex
	state TokenState
}

func (s *memoryStore) Save(state TokenState) error { //nolint:gocritic // hugeParam: interface requires value parameter
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	return nil
}

func (s *memoryStore) Load() (TokenState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, nil
}

func (s *memoryStore) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = TokenState{}
	return nil
}

// noopEmitter silently drops all events. Used as the default
// when no emitter is provided via WithEventEmitter.
type noopEmitter struct{}

func (noopEmitter) Emit(_ string, _ any) {}

// now returns the current time. Can be overridden in tests.
func (c *Client) now() time.Time {
	return time.Now()
}
