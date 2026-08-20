package pkceflow

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// graceTestClient builds a client whose access token has expired but whose grace
// window is still wide open, which is where the defect lived: a provider that
// authoritatively refused the refresh token still got the expired access token
// back for the rest of the grace period.
func graceTestClient(
	t *testing.T,
	store TokenPersistence,
	emitter EventEmitter,
) (*Client, TokenState, *refreshEndpointGate) {
	t.Helper()

	client, state, endpoint := newRefreshConcurrencyClient(t, store, emitter)

	authenticatedAt := time.Now().UTC().Truncate(time.Second)
	state.LastAuthAt = authenticatedAt
	state.ExpiresAt = authenticatedAt.Add(time.Minute)

	// Well inside a long grace window, and past access-token expiry.
	clock := newManualRefreshClock(authenticatedAt.Add(2 * time.Minute))

	client.mu.Lock()
	client.state = state
	client.clock = clock
	client.config.GracePeriod = 30 * 24 * time.Hour
	client.mu.Unlock()

	if err := client.store.Save(state); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	return client, state, endpoint
}

func TestGraceEndsOnCredentialRefusal(t *testing.T) {
	tests := []struct {
		name string
		// how the refresh fails
		oauthError string
		status     int
		// expectations
		wantToken       bool // grace still hands back the expired token
		wantExpiredNow  bool // EventSessionExpired emitted immediately
		wantStateWiped  bool // credentials dropped from state and store
		wantGraceStatus bool // AuthStatus reports grace and usability
	}{
		{
			// "Could not ask" — the network failed. Grace is exactly for this.
			name:            "transport failure keeps grace",
			status:          http.StatusServiceUnavailable,
			wantToken:       true,
			wantGraceStatus: true,
		},
		{
			// A 5xx or non-standard body yields no OAuth error code, so it is
			// not an authoritative refusal. Pinned decision, see plan.
			name:            "server error without an error code keeps grace",
			status:          http.StatusInternalServerError,
			wantToken:       true,
			wantGraceStatus: true,
		},
		{
			name:            "temporary OAuth error keeps grace",
			oauthError:      "temporarily_unavailable",
			wantToken:       true,
			wantGraceStatus: true,
		},
		{
			// "Asked and was refused" — the credential is dead.
			name:           "credential refusal ends grace",
			oauthError:     "invalid_grant",
			wantExpiredNow: true,
			wantStateWiped: true,
		},
		{
			// The client registration is refused, not the token. The user cannot
			// fix that and a fresh Login would fail too, so grace continues.
			name:            "client refusal keeps grace",
			oauthError:      "invalid_client",
			wantToken:       true,
			wantGraceStatus: true,
		},
		{
			name:            "unauthorized client keeps grace",
			oauthError:      "unauthorized_client",
			wantToken:       true,
			wantGraceStatus: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := &recordingTestEmitter{}
			store := &memoryStore{}
			client, state, endpoint := graceTestClient(t, store, emitter)
			endpoint.oauthError = tt.oauthError
			endpoint.status = tt.status
			endpoint.unblock()

			got := client.AccessToken(context.Background())
			want := ""
			if tt.wantToken {
				want = state.AccessToken
			}
			if got != want {
				t.Fatalf("AccessToken = %q, want %q", got, want)
			}

			wantEvents := 0
			if tt.wantExpiredNow {
				wantEvents = 1
			}
			if expired := emitter.count(EventSessionExpired); expired != wantEvents {
				t.Fatalf(
					"EventSessionExpired emitted %d times, want exactly %d",
					expired, wantEvents,
				)
			}

			status := client.AuthStatus()
			if status.GraceMode != tt.wantGraceStatus || status.CanUseApp != tt.wantGraceStatus {
				t.Fatalf("AuthStatus = %+v, want grace and usability %v", status, tt.wantGraceStatus)
			}

			client.mu.Lock()
			current := client.state
			client.mu.Unlock()
			persisted, err := store.Load()
			if err != nil {
				t.Fatalf("load persisted state: %v", err)
			}

			if tt.wantStateWiped {
				// The ID token is deliberately retained so Claims still names the
				// user a re-authentication prompt should address.
				for _, s := range []struct {
					label string
					state TokenState
				}{{"memory", current}, {"store", persisted}} {
					if s.state.AccessToken != "" || s.state.RefreshToken != "" {
						t.Errorf("%s state kept credentials: %+v", s.label, s.state)
					}
					if !s.state.LastAuthAt.IsZero() || !s.state.ExpiresAt.IsZero() {
						t.Errorf("%s state kept a grace anchor: %+v", s.label, s.state)
					}
					if s.state.IDToken != state.IDToken {
						t.Errorf("%s state dropped the ID token: %+v", s.label, s.state)
					}
				}
			} else if current != state {
				t.Errorf("state changed after a non-authoritative failure: %+v", current)
			}
		})
	}
}

// TestCredentialRefusalSurvivesRestart is the durability half of the fix. The
// in-memory permanent block is keyed to a state revision and RestoreSession
// installs a fresh one, so without a persisted mark a revoked account regained a
// full grace window on every launch.
func TestCredentialRefusalSurvivesRestart(t *testing.T) {
	store := &memoryStore{}
	client, _, endpoint := graceTestClient(t, store, nil)
	endpoint.oauthError = "invalid_grant"
	endpoint.unblock()

	if token := client.AccessToken(context.Background()); token != "" {
		t.Fatalf("AccessToken after refusal = %q, want %q", token, "")
	}

	refused, err := store.Load()
	if err != nil {
		t.Fatalf("load refused state: %v", err)
	}

	// A new process: same store, fresh client, fresh revision, no schedule.
	// newRefreshConcurrencyClient seeds the store with a usable state, so put
	// the refused generation back to model what is really on disk at startup.
	restarted, _, restartedEndpoint := newRefreshConcurrencyClient(t, store, nil)
	restartedEndpoint.unblock()
	restarted.mu.Lock()
	restarted.state = TokenState{}
	restarted.config.GracePeriod = 30 * 24 * time.Hour
	restarted.mu.Unlock()
	if err := store.Save(refused); err != nil {
		t.Fatalf("restore refused state to the store: %v", err)
	}

	restored, err := restarted.RestoreSession()
	if err != nil {
		t.Fatalf("RestoreSession: %v", err)
	}
	if !restored {
		t.Fatal("RestoreSession did not restore the refused generation")
	}

	if token := restarted.AccessToken(context.Background()); token != "" {
		t.Fatalf("AccessToken after restart = %q, want %q", token, "")
	}
	if status := restarted.AuthStatus(); status.CanUseApp || status.GraceMode {
		t.Fatalf("AuthStatus after restart = %+v, want unusable", status)
	}
	if requests := restartedEndpoint.requests.Load(); requests != 0 {
		t.Fatalf("restarted client made %d token requests, want 0", requests)
	}

	// The ID token survives the restart, so a re-authentication prompt can still
	// name the user. (Claims itself needs a real JWT; this fixture's ID token is
	// an opaque placeholder, and the decode path is covered in claims_test.go.)
	restarted.mu.Lock()
	restoredIDToken := restarted.state.IDToken
	restarted.mu.Unlock()
	if restoredIDToken != refused.IDToken {
		t.Fatalf("restored ID token = %q, want %q", restoredIDToken, refused.IDToken)
	}
}

// TestCredentialRefusalAfterInconclusiveAttemptKeepsGrace covers the rotation
// hazard: releaseRefreshParticipant cancels an in-flight refresh when the last
// caller leaves, which happens on a request timeout, Pause, or mobile
// backgrounding. A provider that rotates refresh tokens may already have spent
// the presented token, so the next attempt's invalid_grant does not prove the
// session was revoked and must not hard-log-out a live user.
func TestCredentialRefusalAfterInconclusiveAttemptKeepsGrace(t *testing.T) {
	emitter := &recordingTestEmitter{}
	// A dedicated endpoint, not the shared gate: the first attempt must be
	// answerless. Letting an invalid_grant response race the cancellation would
	// make the outcome known, which is deliberately not inconclusive.
	var requests atomic.Int32
	entered := make(chan struct{}, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			entered <- struct{}{}
			// Abandoned in flight and never answered. Bounded so a stuck
			// connection cannot wedge httptest.Server.Close at cleanup; either
			// way the client gets no OAuth error code, which is the point.
			select {
			case <-r.Context().Done():
			case <-time.After(time.Second):
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	t.Cleanup(server.Close)

	client, state := newGraceClientForEndpoint(t, server.URL, emitter)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan string, 1)
	go func() { result <- client.AccessToken(ctx) }()
	waitForTestSignal(t, entered, "refresh did not reach the token endpoint")
	cancel()
	waitForTestString(t, result, "AccessToken did not return after cancellation")
	waitForInconclusiveRefresh(t, client)

	// Second attempt: refused, but ambiguously so. Grace must hold.
	if token := client.AccessToken(context.Background()); token != state.AccessToken {
		t.Fatalf("AccessToken = %q, want the grace token %q", token, state.AccessToken)
	}
	if expired := emitter.count(EventSessionExpired); expired != 0 {
		t.Fatalf("EventSessionExpired emitted %d times, want 0 for an ambiguous refusal", expired)
	}
	if status := client.AuthStatus(); !status.GraceMode || !status.CanUseApp {
		t.Fatalf("AuthStatus = %+v, want grace retained", status)
	}

	client.mu.Lock()
	parked := client.refreshPermanentlyBlockedLocked()
	client.mu.Unlock()
	if !parked {
		t.Fatal("generation is not parked after an ambiguous refusal")
	}
	before := requests.Load()
	for range 3 {
		client.AccessToken(context.Background())
	}
	if after := requests.Load(); after != before {
		t.Fatalf(
			"token endpoint requests went from %d to %d; the dead token is being re-presented",
			before, after,
		)
	}
}

// newGraceClientForEndpoint builds an expired-but-in-grace client whose token
// endpoint is the given URL.
func newGraceClientForEndpoint(
	t *testing.T,
	tokenURL string,
	emitter EventEmitter,
) (*Client, TokenState) {
	t.Helper()

	authenticatedAt := time.Now().UTC().Truncate(time.Second)
	state := TokenState{
		AccessToken:  "access-old",
		RefreshToken: "refresh-old",
		IDToken:      "id-token-old",
		ExpiresAt:    authenticatedAt.Add(time.Minute),
		LastAuthAt:   authenticatedAt,
	}
	store := &memoryStore{}
	if err := store.Save(state); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	client := &Client{
		config:        Config{GracePeriod: 30 * 24 * time.Hour},
		store:         store,
		emitter:       emitter,
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:         newManualRefreshClock(authenticatedAt.Add(2 * time.Minute)),
		state:         state,
		stateRevision: 1,
		lifecycleFlow: make(chan struct{}, 1),
		oauth2: &oauth2.Config{
			ClientID: "test-client",
			Endpoint: oauth2.Endpoint{
				TokenURL:  tokenURL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		provider: &oidc.Provider{},
		verifier: &oidc.IDTokenVerifier{},
	}
	return client, state
}

// TestCredentialRefusalOfSupersededTokenKeepsGrace covers the cross-process
// rotation race: another process rotated the refresh token and persisted the
// newer one, so this process's invalid_grant concerns a token that is merely
// superseded, not revoked.
func TestCredentialRefusalOfSupersededTokenKeepsGrace(t *testing.T) {
	emitter := &recordingTestEmitter{}
	store := &memoryStore{}
	client, state, endpoint := graceTestClient(t, store, emitter)
	endpoint.oauthError = "invalid_grant"
	endpoint.unblock()

	// Another process rotated and persisted a newer generation.
	newer := state
	newer.RefreshToken = "refresh-rotated-elsewhere"
	newer.LastAuthAt = state.LastAuthAt.Add(time.Second)
	if err := store.Save(newer); err != nil {
		t.Fatalf("save rotated state: %v", err)
	}

	if token := client.AccessToken(context.Background()); token != state.AccessToken {
		t.Fatalf("AccessToken = %q, want the grace token %q", token, state.AccessToken)
	}
	if expired := emitter.count(EventSessionExpired); expired != 0 {
		t.Fatalf("EventSessionExpired emitted %d times, want 0 for a superseded token", expired)
	}

	// The newer persisted generation must survive: overwriting it with a refused
	// state would kill a live credential for every process sharing the store.
	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if persisted.RefreshToken != newer.RefreshToken {
		t.Fatalf("persisted refresh token = %q, want the rotated %q", persisted.RefreshToken, newer.RefreshToken)
	}
	assertGenerationParked(t, client, endpoint)
}

// assertGenerationParked pins the other half of keeping grace on an ambiguous
// refusal: the generation must still be parked. Without the park, every later
// AccessToken call re-presents the dead token - once per HTTP request under
// BearerTransport - which on Keycloak "Revoke Refresh Token" can itself clear the
// client session, and on Auth0 is a reuse-detection signal that revokes the whole
// token family. The guard would then cause the revocation it exists to avoid.
func assertGenerationParked(t *testing.T, client *Client, endpoint *refreshEndpointGate) {
	t.Helper()

	client.mu.Lock()
	parked := client.refreshPermanentlyBlockedLocked()
	client.mu.Unlock()
	if !parked {
		t.Fatal("generation is not parked after an ambiguous refusal")
	}

	before := endpoint.requests.Load()
	for range 3 {
		client.AccessToken(context.Background())
	}
	if after := endpoint.requests.Load(); after != before {
		t.Fatalf(
			"token endpoint requests went from %d to %d; the dead token is being re-presented",
			before, after,
		)
	}
}

// TestCredentialRefusalPersistenceFailureArmsRetry covers the durability half of
// the refused commit. A bare Save with no retry would let the next
// RestoreSession reload the pre-refusal state and hand a revoked account another
// grace window, which is the defect the persisted mark exists to close.
func TestCredentialRefusalPersistenceFailureArmsRetry(t *testing.T) {
	store := &graceFailingSaveStore{}
	client, _, endpoint := graceTestClient(t, store, nil)
	store.failing.Store(true)
	endpoint.oauthError = "invalid_grant"
	endpoint.unblock()

	if token := client.AccessToken(context.Background()); token != "" {
		t.Fatalf("AccessToken = %q, want %q", token, "")
	}

	client.mu.Lock()
	retry := client.persistenceRetry
	revision := client.stateRevision
	client.mu.Unlock()
	if !retry.valid || retry.revision != revision {
		t.Fatalf("persistenceRetry = %+v, want it armed for revision %d", retry, revision)
	}

	// The unsaved refused generation stays authoritative: RestoreSession must not
	// replace it with the older state still sitting in the store.
	restored, err := client.RestoreSession()
	if err != nil {
		t.Fatalf("RestoreSession: %v", err)
	}
	if !restored {
		t.Fatal("RestoreSession discarded the authoritative refused generation")
	}
	if token := client.AccessToken(context.Background()); token != "" {
		t.Fatalf("AccessToken after RestoreSession = %q, want %q", token, "")
	}
	if status := client.AuthStatus(); status.CanUseApp || status.GraceMode {
		t.Fatalf("AuthStatus = %+v, want unusable", status)
	}
}

// graceFailingSaveStore stops accepting writes once armed, so the store keeps
// returning the pre-refusal state. It accepts the test's own seeding first.
type graceFailingSaveStore struct {
	memoryStore
	failing atomic.Bool
}

func (s *graceFailingSaveStore) Save(state TokenState) error { //nolint:gocritic // hugeParam: matches the TokenPersistence interface
	if s.failing.Load() {
		return errGraceStoreUnwritable
	}
	return s.memoryStore.Save(state)
}

// A store holding an OLDER refresh token is behind memory, not ahead of it: that
// happens after a failed Save, and it must not suppress a genuine refusal. This
// pins the LastAuthAt discriminator, which token inequality alone would miss.
func TestCredentialRefusalWithStaleStoredTokenEndsGrace(t *testing.T) {
	emitter := &recordingTestEmitter{}
	store := &memoryStore{}
	client, state, endpoint := graceTestClient(t, store, emitter)
	endpoint.oauthError = "invalid_grant"
	endpoint.unblock()

	older := state
	older.RefreshToken = "refresh-older"
	older.LastAuthAt = state.LastAuthAt.Add(-time.Hour)
	if err := store.Save(older); err != nil {
		t.Fatalf("save stale state: %v", err)
	}

	if token := client.AccessToken(context.Background()); token != "" {
		t.Fatalf("AccessToken = %q, want %q", token, "")
	}
	if expired := emitter.count(EventSessionExpired); expired != 1 {
		t.Fatalf("EventSessionExpired emitted %d times, want exactly 1", expired)
	}
	if status := client.AuthStatus(); status.CanUseApp || status.GraceMode {
		t.Fatalf("AuthStatus = %+v, want unusable", status)
	}
}

// A store that cannot be read is not evidence of rotation, while the refusal is
// authoritative about the token that was presented. Fail closed.
func TestCredentialRefusalWithUnreadableStoreEndsGrace(t *testing.T) {
	store := &graceFailingLoadStore{}
	client, _, endpoint := graceTestClient(t, store, nil)
	endpoint.oauthError = "invalid_grant"
	endpoint.unblock()

	if token := client.AccessToken(context.Background()); token != "" {
		t.Fatalf("AccessToken = %q, want %q", token, "")
	}
	if status := client.AuthStatus(); status.CanUseApp || status.GraceMode {
		t.Fatalf("AuthStatus = %+v, want unusable", status)
	}
}

// graceFailingLoadStore accepts saves but never returns readable state.
type graceFailingLoadStore struct {
	memoryStore
}

func (s *graceFailingLoadStore) Load() (TokenState, error) {
	return TokenState{}, errGraceStoreUnreadable
}

var errGraceStoreUnreadable = errors.New("grace test: store unreadable")

// waitForInconclusiveRefresh waits for the abandoned attempt's goroutine to
// record its outcome, which happens after AccessToken has already returned to
// its cancelled caller.
func waitForInconclusiveRefresh(t *testing.T, client *Client) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		marked := client.refreshInconclusiveLocked(client.stateRevision)
		client.mu.Unlock()
		if marked {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("abandoned attempt was not recorded as inconclusive")
}

var errGraceStoreUnwritable = errors.New("grace test: store unwritable")
