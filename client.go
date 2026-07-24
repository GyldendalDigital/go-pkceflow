package pkceflow

import (
	"context"
	"errors"
	"fmt"
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
		config:  cfg,
		flow:    flow,
		store:   options.store,
		emitter: options.emitter,
		logger:  options.logger,
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

// tokenExpiryBuffer is subtracted from the token expiry to avoid using
// a token that expires mid-request.
const tokenExpiryBuffer = 30 * time.Second

// AuthStatus reports the current authentication state.
// No network calls; purely based on in-memory state and config.
func (c *Client) AuthStatus() AuthStatusResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state.IsZero() {
		return AuthStatusResult{}
	}

	now := c.now()
	valid := now.Before(c.state.ExpiresAt.Add(-tokenExpiryBuffer))

	var graceMode bool
	var graceDaysLeft int

	if !valid && c.config.GracePeriod > 0 && !c.state.LastAuthAt.IsZero() {
		graceEnd := c.state.LastAuthAt.Add(c.config.GracePeriod)
		if now.Before(graceEnd) {
			graceMode = true
			graceDaysLeft = int(time.Until(graceEnd).Hours() / 24)
		}
	}

	return AuthStatusResult{
		Valid:         valid,
		GraceMode:     graceMode,
		GraceDaysLeft: graceDaysLeft,
		CanUseApp:     valid || graceMode,
	}
}

// RestoreSession loads persisted tokens into memory.
// Returns true if a usable session was found.
// Does NOT require network (works before Init).
func (c *Client) RestoreSession() bool {
	state, err := c.store.Load()
	if err != nil {
		c.logger.Warn("failed to load persisted session", "error", err)
		return false
	}

	if state.IsZero() {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = state
	return true
}

// Init performs OIDC discovery and configures the OAuth2 client.
// Call this after New() and optionally after RestoreSession().
// Init failure is non-fatal: the app can work offline with cached tokens.
// Idempotent: calling Init() again re-discovers.
func (c *Client) Init(ctx context.Context) error {
	provider, err := oidc.NewProvider(ctx, c.config.IssuerURL)
	if err != nil {
		return fmt.Errorf("pkceflow: OIDC discovery failed for %q: %w", c.config.IssuerURL, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.provider = provider
	c.verifier = provider.Verifier(&oidc.Config{ClientID: c.config.ClientID})
	c.oauth2 = &oauth2.Config{
		ClientID:    c.config.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: c.flow.RedirectURI(),
		Scopes:      c.config.Scopes,
	}

	// Extract end_session_endpoint from discovery claims (for RP-Initiated Logout)
	var claims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&claims); err == nil && claims.EndSessionEndpoint != "" {
		c.endSessionEndpoint = claims.EndSessionEndpoint
	}

	return nil
}

// initialized reports whether Init() has been called successfully.
func (c *Client) initialized() bool {
	return c.provider != nil
}
