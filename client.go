package pkceflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
	clock   refreshClock

	httpClient *http.Client // nil = library default; routes all outbound HTTP

	// Init commits acquire initMu before mu and Init failures may then enqueue
	// events under eventMu. Lifecycle replacement and Login/Logout commits acquire
	// lifecycleMu before stateCommitMu. Refresh registration acquires refreshMu
	// before mu. State transitions acquire stateCommitMu before mu and may then
	// enqueue events under eventMu. Persistence runs under stateCommitMu but never
	// mu; discovery, browser flows, token endpoint work, token revocation, and
	// EventEmitter callbacks hold none of these locks.
	initMu        sync.Mutex
	lifecycleMu   sync.Mutex
	stateCommitMu sync.Mutex
	refreshMu     sync.Mutex
	eventMu       sync.Mutex

	mu            sync.Mutex
	state         TokenState
	stateRevision uint64
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
	oauth2        *oauth2.Config

	endSessionEndpoint  string
	revocationEndpoint  string
	refreshRun          *refreshLoopHandle
	refreshAttempt      *refreshAttempt
	refreshWake         chan struct{}
	refreshSchedule     refreshLoopSchedule
	refreshClaimSeq     uint64
	persistenceRetry    persistenceRetryState
	persistenceClaimSeq uint64
	restoreBlocked      bool
	initSeq             uint64
	initOperation       *initOperation
	lifecycleSeq        uint64
	lifecycleOperation  *lifecycleOperation
	lifecycleFlow       chan struct{}

	pendingEvents    []clientEvent
	eventDispatching bool
}

// New creates a new Client with the given configuration and flow handler.
// The flow handler is required; it determines how the user authenticates
// (e.g., localhost callback for desktop, deep link for mobile).
//
// Options can override defaults:
//   - WithTokenPersistence: default is in-memory (lost on restart)
//   - WithEventEmitter: default is no-op (events silently dropped)
//   - WithLogger: default is slog.Default()
//   - WithHTTPClient: default is the standard HTTP client
func New(cfg Config, flow AuthFlowHandler, opts ...Option) (*Client, error) { //nolint:gocritic // hugeParam: intentionally by value so Validate() doesn't mutate caller's copy
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
		config:        cfg,
		flow:          flow,
		store:         options.store,
		emitter:       options.emitter,
		logger:        options.logger,
		clock:         systemRefreshClock{},
		lifecycleFlow: make(chan struct{}, 1),
	}

	c.httpClient = options.httpClient

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
	if c.clock == nil {
		return time.Now()
	}
	return c.clock.Now()
}

// tokenExpiryBuffer is subtracted from the token expiry to avoid using
// a token that expires mid-request.
const tokenExpiryBuffer = 30 * time.Second

// AuthStatus reports the current authentication state.
// No network calls; purely based on in-memory state and config.
//
// A session the provider has refused, and one that failed a session-integrity
// check, both report the zero result: not valid, not in grace, not usable. That
// is indistinguishable from never having authenticated. To tell the two apart,
// call Claims: it still succeeds for a refused session, naming the user a
// re-authentication prompt should address.
func (c *Client) AuthStatus() AuthStatusResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state.IsZero() {
		return AuthStatusResult{}
	}
	if c.refreshIntegrityBlockedLocked() {
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
			graceDaysLeft = int(graceEnd.Sub(now).Hours() / 24)
		}
	}

	return AuthStatusResult{
		Valid:         valid,
		GraceMode:     graceMode,
		GraceDaysLeft: graceDaysLeft,
		CanUseApp:     valid || graceMode,
	}
}

// RestoreSession loads persisted tokens into memory. restored is true when a
// non-zero persisted state was installed or an authoritative non-zero in-memory
// generation was retained. It does not report whether that state is currently
// valid or within grace; use AuthStatus for that decision.
// Does NOT require network (works before Init).
//
// Missing or malformed persisted state returns false, nil. An operational Load
// failure returns false and a safely redacted error that unwraps to the backend
// cause. A Load error never changes the current in-memory state.
//
// A locally logged-out Client does not restore again; create a new Client for a
// new application lifetime. If the current in-memory generation has unresolved
// persistence, it remains authoritative and RestoreSession does not replace it
// with an uncertain older stored generation.
func (c *Client) RestoreSession() (restored bool, err error) {
	c.stateCommitMu.Lock()
	c.mu.Lock()
	if c.restoreBlocked {
		c.mu.Unlock()
		c.stateCommitMu.Unlock()
		return false, nil
	}
	if c.persistenceRetry.valid &&
		c.persistenceRetry.revision == c.stateRevision {
		restored = !c.state.IsZero()
		c.mu.Unlock()
		c.stateCommitMu.Unlock()
		return restored, nil
	}
	c.mu.Unlock()

	state, err := c.store.Load()
	if err != nil {
		c.stateCommitMu.Unlock()
		return false, &restoreSessionError{cause: err}
	}

	if state.IsZero() {
		c.stateCommitMu.Unlock()
		return false, nil
	}

	c.mu.Lock()
	c.setStateLocked(&state)
	c.mu.Unlock()
	c.stateCommitMu.Unlock()
	return true, nil
}

// setStateLocked replaces the in-memory token state when it materially changes.
// c.mu must be held.
func (c *Client) setStateLocked(state *TokenState) {
	if c.state == *state {
		return
	}
	c.advanceStateLocked(state)
}

// advanceStateLocked installs a new semantic token generation even if a
// provider returned byte-for-byte equal values. c.mu must be held.
func (c *Client) advanceStateLocked(state *TokenState) {
	c.state = *state
	c.stateRevision++
	c.refreshSchedule = refreshLoopSchedule{}
	c.persistenceRetry = persistenceRetryState{}
	c.restoreBlocked = false
	c.signalRefreshLoopLocked()
}

// signalRefreshLoopLocked wakes every refresh-loop observer without allowing
// one canceled runner to consume another runner's notification. c.mu must be
// held.
func (c *Client) signalRefreshLoopLocked() {
	if c.refreshWake != nil {
		close(c.refreshWake)
	}
	c.refreshWake = make(chan struct{})
}

// refreshWakeLocked returns the current close-and-replace broadcast channel.
// c.mu must be held.
func (c *Client) refreshWakeLocked() <-chan struct{} {
	if c.refreshWake == nil {
		c.refreshWake = make(chan struct{})
	}
	return c.refreshWake
}

func (c *Client) refreshIntegrityBlockedLocked() bool {
	return c.refreshSchedule.valid &&
		c.refreshSchedule.revision == c.stateRevision &&
		c.refreshSchedule.disposition == refreshLoopBlockedIntegrity
}

func (c *Client) refreshPermanentlyBlockedLocked() bool {
	return c.refreshSchedule.valid &&
		c.refreshSchedule.revision == c.stateRevision &&
		c.refreshSchedule.disposition == refreshLoopBlockedPermanent
}

type initOperation struct {
	id     uint64
	parent context.Context
	ctx    context.Context
	cancel context.CancelFunc
}

type initSnapshot struct {
	provider           *oidc.Provider
	verifier           *oidc.IDTokenVerifier
	oauth2             *oauth2.Config
	endSessionEndpoint string
	revocationEndpoint string
}

// Init performs OIDC discovery and configures the OAuth2 client. Call this
// after New() and optionally after RestoreSession().
//
// Init failure is non-fatal: the app can work offline with cached tokens.
// Calling Init again re-discovers. When calls overlap, the latest admitted call
// supersedes older calls on the same Client. Before applying a discovery
// result, Init rechecks operation ownership and cancellation. A call that loses
// that check does not replace discovery state, wake refresh work, or emit
// EventInitFailed; its returned error wraps the applicable context error.
func (c *Client) Init(ctx context.Context) error {
	operation := c.beginInitOperation(ctx)
	if operation == nil {
		return c.wrapInitError(ctx.Err())
	}
	defer c.finishInitOperation(operation)

	provider, err := oidc.NewProvider(c.httpContext(operation.ctx), c.config.IssuerURL)
	if err != nil {
		return c.wrapInitError(c.completeInitFailure(operation, err))
	}

	endpoint := provider.Endpoint()
	// Force client_id in the request body (RFC 6749 section 2.3.1 "including the
	// client credentials in the request-body"). pkceflow targets public native
	// clients with no secret, so HTTP Basic client authentication is wrong. Left
	// as AuthStyleAutoDetect, golang.org/x/oauth2 probes Basic first; providers
	// like Keycloak reject Basic for a public client AND invalidate the
	// single-use authorization code, so the automatic retry fails with
	// "invalid_grant: Code not valid". Setting the style avoids the probe.
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	snapshot := initSnapshot{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: c.config.ClientID}),
		oauth2: &oauth2.Config{
			ClientID:    c.config.ClientID,
			Endpoint:    endpoint,
			RedirectURL: c.flow.RedirectURI(),
			Scopes:      c.config.Scopes,
		},
	}

	// Extract the logout and revocation endpoints from discovery claims. If
	// claims parsing fails, preserve the previously committed endpoint rather
	// than accidentally clearing it — discovery otherwise succeeded.
	//
	// Decoded independently, one field at a time. encoding/json records a type
	// mismatch and keeps going, returning the error only at the end, so a single
	// shared struct would let a malformed revocation_endpoint discard a
	// perfectly good end_session_endpoint and silently disable RP-Initiated
	// Logout.
	c.mu.Lock()
	previousEndSession := c.endSessionEndpoint
	previousRevocation := c.revocationEndpoint
	c.mu.Unlock()
	snapshot.endSessionEndpoint = discoveredEndpoint(
		provider, "end_session_endpoint", previousEndSession,
	)
	snapshot.revocationEndpoint = discoveredEndpoint(
		provider, "revocation_endpoint", previousRevocation,
	)

	return c.wrapInitError(c.commitInit(operation, snapshot))
}

// discoveredEndpoint reads one string endpoint from the discovery document,
// falling back to the previously committed value when the claim is absent or not
// a string.
func discoveredEndpoint(provider *oidc.Provider, name, previous string) string {
	var claims map[string]json.RawMessage
	if err := provider.Claims(&claims); err != nil {
		return previous
	}
	raw, ok := claims[name]
	if !ok {
		return ""
	}
	var endpoint string
	if err := json.Unmarshal(raw, &endpoint); err != nil {
		return previous
	}
	return endpoint
}

func (c *Client) beginInitOperation(ctx context.Context) *initOperation {
	c.initMu.Lock()
	defer c.initMu.Unlock()
	if ctx.Err() != nil {
		return nil
	}

	if c.initOperation != nil {
		c.initOperation.cancel()
	}
	c.initSeq++
	operationCtx, cancel := context.WithCancel(ctx)
	operation := &initOperation{
		id:     c.initSeq,
		parent: ctx,
		ctx:    operationCtx,
		cancel: cancel,
	}
	c.initOperation = operation
	return operation
}

func (c *Client) finishInitOperation(operation *initOperation) {
	c.initMu.Lock()
	if c.initOperation == operation && c.initOperation.id == operation.id {
		c.initOperation = nil
	}
	c.initMu.Unlock()

	operation.cancel()
}

func (c *Client) initOperationCurrentLocked(operation *initOperation) bool {
	return c.initOperation == operation &&
		c.initOperation.id == operation.id &&
		operation.parent.Err() == nil &&
		operation.ctx.Err() == nil
}

func (c *Client) completeInitFailure(operation *initOperation, discoveryErr error) error {
	c.initMu.Lock()
	if !c.initOperationCurrentLocked(operation) {
		c.initMu.Unlock()
		return initOperationContextError(operation)
	}
	shouldDrain := c.enqueueEvent(EventInitFailed, nil)
	c.initMu.Unlock()

	if shouldDrain {
		c.drainEvents()
	}
	return discoveryErr
}

func (c *Client) commitInit(operation *initOperation, snapshot initSnapshot) error {
	c.initMu.Lock()
	c.mu.Lock()
	if !c.initOperationCurrentLocked(operation) {
		c.mu.Unlock()
		c.initMu.Unlock()
		return initOperationContextError(operation)
	}

	c.provider = snapshot.provider
	c.verifier = snapshot.verifier
	c.oauth2 = snapshot.oauth2
	c.endSessionEndpoint = snapshot.endSessionEndpoint
	c.revocationEndpoint = snapshot.revocationEndpoint
	c.signalRefreshLoopLocked()
	c.mu.Unlock()
	c.initMu.Unlock()
	return nil
}

func initOperationContextError(operation *initOperation) error {
	if err := operation.parent.Err(); err != nil {
		return err
	}
	if err := operation.ctx.Err(); err != nil {
		return err
	}
	return context.Canceled
}

func (c *Client) wrapInitError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("pkceflow: OIDC discovery failed for %q: %w", c.config.IssuerURL, err)
}

// initialized reports whether Init() has been called successfully.
func (c *Client) initialized() bool {
	return c.provider != nil
}

// httpContext returns ctx wrapped so that go-oidc and golang.org/x/oauth2 use
// the configured HTTP client for discovery, JWKS verification, token exchange,
// and refresh. oidc.ClientContext stores the client under the oauth2.HTTPClient
// context key, which both libraries read. When no client is configured it
// returns ctx unchanged (library default HTTP client).
func (c *Client) httpContext(ctx context.Context) context.Context {
	if c.httpClient == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, c.httpClient)
}
