package pkceflow

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type refreshResult struct {
	state TokenState
	err   error
}

type observedDoneContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func newObservedDoneContext(ctx context.Context) *observedDoneContext {
	return &observedDoneContext{
		Context:  ctx,
		observed: make(chan struct{}),
	}
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() {
		close(c.observed)
	})
	return c.Context.Done()
}

type refreshEndpointGate struct {
	entered     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
	requests    atomic.Int32
	oauthError  string
	status      int
}

func newRefreshEndpointGate() *refreshEndpointGate {
	return &refreshEndpointGate{
		entered: make(chan struct{}, 8),
		release: make(chan struct{}),
	}
}

func (g *refreshEndpointGate) unblock() {
	g.releaseOnce.Do(func() {
		close(g.release)
	})
}

func (g *refreshEndpointGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if got := r.Form.Get("grant_type"); got != "refresh_token" {
		http.Error(w, "unexpected grant type", http.StatusBadRequest)
		return
	}

	request := g.requests.Add(1)
	g.entered <- struct{}{}
	select {
	case <-g.release:
	case <-r.Context().Done():
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if g.oauthError != "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":%q}`, g.oauthError)
		return
	}
	if g.status != 0 {
		w.WriteHeader(g.status)
		_, _ = io.WriteString(w, `{"message":"token endpoint unavailable"}`)
		return
	}
	_, _ = fmt.Fprintf(
		w,
		`{"access_token":"access-%d","refresh_token":"refresh-%d","token_type":"Bearer","expires_in":3600}`,
		request,
		request,
	)
}

type abandonedAttemptTransport struct {
	entered     chan struct{}
	cancelled   chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
	requests    atomic.Int32
}

func newAbandonedAttemptTransport() *abandonedAttemptTransport {
	return &abandonedAttemptTransport{
		entered:   make(chan struct{}),
		cancelled: make(chan struct{}),
		release:   make(chan struct{}),
	}
}

func (t *abandonedAttemptTransport) unblock() {
	t.releaseOnce.Do(func() {
		close(t.release)
	})
}

func (t *abandonedAttemptTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.requests.Add(1) == 1 {
		close(t.entered)
		<-request.Context().Done()
		close(t.cancelled)
		<-t.release
		return nil, request.Context().Err()
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(
			`{"access_token":"access-retry","refresh_token":"refresh-retry","token_type":"Bearer","expires_in":3600}`,
		)),
		Request: request,
	}, nil
}

type recordingTestEmitter struct {
	mu     sync.Mutex
	events []string
}

func (e *recordingTestEmitter) Emit(event string, _ any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *recordingTestEmitter) count(event string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	var count int
	for _, candidate := range e.events {
		if candidate == event {
			count++
		}
	}
	return count
}

func (e *recordingTestEmitter) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.events...)
}

type blockingEventEmitter struct {
	mu          sync.Mutex
	events      []string
	blockEvent  string
	entered     chan struct{}
	enteredOnce sync.Once
	release     chan struct{}
	releaseOnce sync.Once
	loggedOut   chan struct{}
	logoutOnce  sync.Once
}

func newBlockingEventEmitter(event string) *blockingEventEmitter {
	return &blockingEventEmitter{
		blockEvent: event,
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
		loggedOut:  make(chan struct{}),
	}
}

func (e *blockingEventEmitter) Emit(event string, _ any) {
	e.mu.Lock()
	e.events = append(e.events, event)
	e.mu.Unlock()

	if event == e.blockEvent {
		e.enteredOnce.Do(func() {
			close(e.entered)
		})
		<-e.release
	}
	if event == EventLoggedOut {
		e.logoutOnce.Do(func() {
			close(e.loggedOut)
		})
	}
}

func (e *blockingEventEmitter) unblock() {
	e.releaseOnce.Do(func() {
		close(e.release)
	})
}

func (e *blockingEventEmitter) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.events...)
}

type reentrantLogoutEmitter struct {
	mu        sync.Mutex
	events    []string
	client    *Client
	once      sync.Once
	loggedOut chan struct{}
}

func newReentrantLogoutEmitter() *reentrantLogoutEmitter {
	return &reentrantLogoutEmitter{
		loggedOut: make(chan struct{}),
	}
}

func (e *reentrantLogoutEmitter) Emit(event string, _ any) {
	e.mu.Lock()
	e.events = append(e.events, event)
	e.mu.Unlock()

	if event == EventTokenRefreshed {
		e.once.Do(func() {
			_ = e.client.Logout(context.Background())
		})
	}
	if event == EventLoggedOut {
		close(e.loggedOut)
	}
}

func (e *reentrantLogoutEmitter) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.events...)
}

type blockingLogoutFlow struct {
	entered     chan struct{}
	enteredOnce sync.Once
	release     chan struct{}
	releaseOnce sync.Once
}

func newBlockingLogoutFlow() *blockingLogoutFlow {
	return &blockingLogoutFlow{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (f *blockingLogoutFlow) StartAuthFlow(
	ctx context.Context,
	_ string,
) (string, error) {
	f.enteredOnce.Do(func() {
		close(f.entered)
	})
	select {
	case <-f.release:
		return "", context.Canceled
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (f *blockingLogoutFlow) RedirectURI() string {
	return "http://127.0.0.1:9999/logout"
}

func (f *blockingLogoutFlow) unblock() {
	f.releaseOnce.Do(func() {
		close(f.release)
	})
}

type blockingSaveStore struct {
	inner memoryStore

	mu          sync.Mutex
	block       bool
	entered     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
	operations  []string
}

func (s *blockingSaveStore) arm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.block = true
	s.entered = make(chan struct{}, 1)
	s.release = make(chan struct{})
	s.releaseOnce = sync.Once{}
	s.operations = nil
}

func (s *blockingSaveStore) unblock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.release == nil {
		return
	}
	s.releaseOnce.Do(func() {
		close(s.release)
	})
}

func (s *blockingSaveStore) Save(state TokenState) error { //nolint:gocritic // hugeParam: interface requires value parameter
	s.mu.Lock()
	block := s.block
	entered := s.entered
	release := s.release
	if block {
		s.block = false
	}
	s.mu.Unlock()

	if block {
		entered <- struct{}{}
		<-release
	}
	if err := s.inner.Save(state); err != nil {
		return err
	}
	s.mu.Lock()
	s.operations = append(s.operations, "save")
	s.mu.Unlock()
	return nil
}

func (s *blockingSaveStore) Load() (TokenState, error) {
	return s.inner.Load()
}

func (s *blockingSaveStore) Delete() error {
	if err := s.inner.Delete(); err != nil {
		return err
	}
	s.mu.Lock()
	s.operations = append(s.operations, "delete")
	s.mu.Unlock()
	return nil
}

func (s *blockingSaveStore) operationSnapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.operations...)
}

func newRefreshConcurrencyClient(
	t *testing.T,
	store TokenPersistence,
	emitter EventEmitter,
) (*Client, TokenState, *refreshEndpointGate) {
	t.Helper()

	gate := newRefreshEndpointGate()
	server := httptest.NewServer(gate)
	t.Cleanup(server.Close)
	t.Cleanup(gate.unblock)

	if store == nil {
		store = &memoryStore{}
	}
	if emitter == nil {
		emitter = noopEmitter{}
	}

	now := time.Now()
	state := TokenState{
		AccessToken:  "access-old",
		RefreshToken: "refresh-old",
		IDToken:      "id-token-old",
		ExpiresAt:    now.Add(time.Minute),
		LastAuthAt:   now,
	}
	if err := store.Save(state); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	client := &Client{
		config:        Config{},
		store:         store,
		emitter:       emitter,
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:         state,
		stateRevision: 1,
		oauth2: &oauth2.Config{
			ClientID: "test-client",
			Endpoint: oauth2.Endpoint{
				TokenURL:  server.URL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		provider: &oidc.Provider{},
		verifier: &oidc.IDTokenVerifier{},
	}

	return client, state, gate
}

func waitForTestSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal(message)
	}
}

func waitForRefreshResult(t *testing.T, result <-chan refreshResult, message string) refreshResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal(message)
		return refreshResult{}
	}
}

func waitForTestError(t *testing.T, result <-chan error, message string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal(message)
		return nil
	}
}

func waitForTestString(t *testing.T, result <-chan string, message string) string {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal(message)
		return ""
	}
}

func waitForTestWaitGroup(t *testing.T, group *sync.WaitGroup, message string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	waitForTestSignal(t, done, message)
}

func TestRefreshSharesSuccessfulAttemptPerRevision(t *testing.T) {
	client, snapshot, endpoint := newRefreshConcurrencyClient(t, nil, nil)

	first := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(context.Background(), &snapshot)
		first <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, endpoint.entered, "first refresh did not reach token endpoint")

	waiterCtx := newObservedDoneContext(context.Background())
	second := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(waiterCtx, &snapshot)
		second <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, waiterCtx.observed, "second refresh did not join the active attempt")

	endpoint.unblock()
	firstResult := waitForRefreshResult(t, first, "first refresh did not return")
	secondResult := waitForRefreshResult(t, second, "second refresh did not return")
	if firstResult.err != nil {
		t.Fatalf("first refresh: %v", firstResult.err)
	}
	if secondResult.err != nil {
		t.Fatalf("second refresh: %v", secondResult.err)
	}
	if got := endpoint.requests.Load(); got != 1 {
		t.Fatalf("refresh requests = %d, want 1", got)
	}
	if firstResult.state != secondResult.state {
		t.Fatalf("refresh results differ: first=%+v second=%+v", firstResult.state, secondResult.state)
	}
}

func TestRefreshSharesFailedAttemptPerRevision(t *testing.T) {
	tests := []struct {
		name          string
		oauthError    string
		status        int
		wantPermanent bool
	}{
		{
			name:          "permanent OAuth failure",
			oauthError:    "invalid_grant",
			wantPermanent: true,
		},
		{
			name:       "temporary OAuth failure",
			oauthError: "temporarily_unavailable",
		},
		{
			name:   "non-standard service failure",
			status: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, snapshot, endpoint := newRefreshConcurrencyClient(t, nil, nil)
			endpoint.oauthError = tt.oauthError
			endpoint.status = tt.status

			first := make(chan refreshResult, 1)
			go func() {
				state, err := client.refresh(context.Background(), &snapshot)
				first <- refreshResult{state: state, err: err}
			}()
			waitForTestSignal(t, endpoint.entered, "first refresh did not reach token endpoint")

			waiterCtx := newObservedDoneContext(context.Background())
			second := make(chan refreshResult, 1)
			go func() {
				state, err := client.refresh(waiterCtx, &snapshot)
				second <- refreshResult{state: state, err: err}
			}()
			waitForTestSignal(t, waiterCtx.observed, "second refresh did not join the failed attempt")

			endpoint.unblock()
			firstResult := waitForRefreshResult(t, first, "first failed refresh did not return")
			secondResult := waitForRefreshResult(t, second, "second failed refresh did not return")
			if firstResult.err == nil || secondResult.err == nil {
				t.Fatalf("shared errors = (%v, %v), want both non-nil", firstResult.err, secondResult.err)
			}
			if firstResult.err.Error() != secondResult.err.Error() {
				t.Fatalf("shared errors differ: first=%v second=%v", firstResult.err, secondResult.err)
			}
			if got := IsPermanentError(firstResult.err); got != tt.wantPermanent {
				t.Fatalf("IsPermanentError = %v, want %v", got, tt.wantPermanent)
			}
			if got := endpoint.requests.Load(); got != 1 {
				t.Fatalf("overlapping refresh requests = %d, want 1", got)
			}

			_, laterErr := client.refresh(context.Background(), &snapshot)
			if laterErr == nil {
				t.Fatal("later refresh error = nil, want retry failure")
			}
			if got := endpoint.requests.Load(); got != 2 {
				t.Fatalf("requests after later retry = %d, want 2", got)
			}
		})
	}
}

func TestRefreshWaiterHonorsCancellation(t *testing.T) {
	client, snapshot, endpoint := newRefreshConcurrencyClient(t, nil, nil)

	first := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(context.Background(), &snapshot)
		first <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, endpoint.entered, "first refresh did not reach token endpoint")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	waiterCtx := newObservedDoneContext(ctx)
	second := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(waiterCtx, &snapshot)
		second <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, waiterCtx.observed, "second refresh did not begin waiting")
	cancel()

	secondResult := waitForRefreshResult(t, second, "cancelled refresh waiter did not return")
	if secondResult.err != context.Canceled {
		t.Fatalf("waiting refresh error = %v, want context.Canceled", secondResult.err)
	}
	if got := endpoint.requests.Load(); got != 1 {
		t.Fatalf("refresh requests before leader release = %d, want 1", got)
	}

	endpoint.unblock()
	if result := waitForRefreshResult(t, first, "first refresh did not return"); result.err != nil {
		t.Fatalf("first refresh: %v", result.err)
	}
}

func TestRefreshAttemptSurvivesLeaderCancellationForLiveWaiter(t *testing.T) {
	client, snapshot, endpoint := newRefreshConcurrencyClient(t, nil, nil)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	t.Cleanup(cancelLeader)
	first := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(leaderCtx, &snapshot)
		first <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, endpoint.entered, "leader refresh did not reach token endpoint")

	waiterCtx := newObservedDoneContext(context.Background())
	second := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(waiterCtx, &snapshot)
		second <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, waiterCtx.observed, "live waiter did not join the leader attempt")

	cancelLeader()
	firstResult := waitForRefreshResult(t, first, "cancelled refresh leader did not return")
	if firstResult.err != context.Canceled {
		t.Fatalf("leader refresh error = %v, want context.Canceled", firstResult.err)
	}
	if got := endpoint.requests.Load(); got != 1 {
		t.Fatalf("requests after leader cancellation = %d, want 1", got)
	}

	endpoint.unblock()
	secondResult := waitForRefreshResult(t, second, "live refresh waiter did not return")
	if secondResult.err != nil {
		t.Fatalf("live refresh waiter: %v", secondResult.err)
	}
	if secondResult.state.AccessToken == "" {
		t.Fatal("live refresh waiter returned an empty access token")
	}
	if got := endpoint.requests.Load(); got != 1 {
		t.Fatalf("requests after shared attempt completed = %d, want 1", got)
	}
}

func TestNewCallerWaitsForAbandonedAttemptToFinish(t *testing.T) {
	client, snapshot, _ := newRefreshConcurrencyClient(t, nil, nil)
	transport := newAbandonedAttemptTransport()
	t.Cleanup(transport.unblock)
	client.httpClient = &http.Client{Transport: transport}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	t.Cleanup(cancelLeader)
	first := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(leaderCtx, &snapshot)
		first <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, transport.entered, "leader refresh did not reach custom transport")

	cancelLeader()
	firstResult := waitForRefreshResult(t, first, "cancelled refresh leader did not return")
	if firstResult.err != context.Canceled {
		t.Fatalf("leader refresh error = %v, want context.Canceled", firstResult.err)
	}
	waitForTestSignal(t, transport.cancelled, "abandoned attempt context was not cancelled")

	waiterCtx := newObservedDoneContext(context.Background())
	second := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(waiterCtx, &snapshot)
		second <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, waiterCtx.observed, "new caller did not wait for the abandoned attempt")
	if got := transport.requests.Load(); got != 1 {
		t.Fatalf("requests before abandoned attempt finished = %d, want 1", got)
	}

	transport.unblock()
	secondResult := waitForRefreshResult(t, second, "new caller did not retry after abandoned attempt")
	if secondResult.err != nil {
		t.Fatalf("new caller refresh: %v", secondResult.err)
	}
	if secondResult.state.AccessToken != "access-retry" {
		t.Fatalf("new caller access token = %q, want access-retry", secondResult.state.AccessToken)
	}
	if got := transport.requests.Load(); got != 2 {
		t.Fatalf("requests after abandoned attempt finished = %d, want 2", got)
	}
}

func TestRefreshCannotResurrectLoggedOutSession(t *testing.T) {
	emitter := &recordingTestEmitter{}
	client, snapshot, endpoint := newRefreshConcurrencyClient(t, nil, emitter)

	result := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(context.Background(), &snapshot)
		result <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, endpoint.entered, "refresh did not reach token endpoint")

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	endpoint.unblock()

	got := waitForRefreshResult(t, result, "superseded refresh did not return")
	if got.err != nil {
		t.Fatalf("refresh: %v", got.err)
	}
	if !got.state.IsZero() {
		t.Fatalf("superseded refresh state = %+v, want zero", got.state)
	}

	client.mu.Lock()
	inMemory := client.state
	client.mu.Unlock()
	if !inMemory.IsZero() {
		t.Fatalf("in-memory state resurrected: %+v", inMemory)
	}
	persisted, err := client.store.Load()
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if !persisted.IsZero() {
		t.Fatalf("persisted state resurrected: %+v", persisted)
	}
	if got := emitter.count(EventTokenRefreshed); got != 0 {
		t.Fatalf("token-refreshed events = %d, want 0", got)
	}
}

func TestStaleRefreshFailureIsSuppressedAfterLogout(t *testing.T) {
	client, snapshot, endpoint := newRefreshConcurrencyClient(t, nil, nil)
	endpoint.oauthError = "invalid_grant"

	result := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(context.Background(), &snapshot)
		result <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, endpoint.entered, "refresh did not reach token endpoint")

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	endpoint.unblock()

	got := waitForRefreshResult(t, result, "superseded failed refresh did not return")
	if got.err != nil {
		t.Fatalf("superseded refresh failure = %v, want nil", got.err)
	}
	if !got.state.IsZero() {
		t.Fatalf("superseded refresh state = %+v, want zero", got.state)
	}
}

func TestStateAndPersistenceCommitsStayOrdered(t *testing.T) {
	store := &blockingSaveStore{}
	client, snapshot, endpoint := newRefreshConcurrencyClient(t, store, nil)
	endpoint.unblock()
	store.arm()
	t.Cleanup(store.unblock)

	refreshDone := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(context.Background(), &snapshot)
		refreshDone <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, store.entered, "refresh did not reach persistence Save")

	if client.stateCommitMu.TryLock() {
		client.stateCommitMu.Unlock()
		t.Fatal("refresh Save did not hold the state commit lock")
	}

	logoutStarted := make(chan struct{})
	logoutDone := make(chan error, 1)
	go func() {
		close(logoutStarted)
		logoutDone <- client.Logout(context.Background())
	}()
	waitForTestSignal(t, logoutStarted, "Logout goroutine did not start")

	store.unblock()
	if result := waitForRefreshResult(t, refreshDone, "refresh did not finish"); result.err != nil {
		t.Fatalf("refresh: %v", result.err)
	}
	if err := waitForTestError(t, logoutDone, "Logout did not finish"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if got, want := store.operationSnapshot(), []string{"save", "delete"}; !slices.Equal(got, want) {
		t.Fatalf("persistence operation order = %v, want %v", got, want)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if !persisted.IsZero() {
		t.Fatalf("persisted state after ordered Logout = %+v, want zero", persisted)
	}
}

func TestRefreshEventsFollowStateCommitOrder(t *testing.T) {
	emitter := newBlockingEventEmitter(EventTokenRefreshed)
	t.Cleanup(emitter.unblock)
	client, snapshot, endpoint := newRefreshConcurrencyClient(t, nil, emitter)
	endpoint.unblock()

	refreshDone := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(context.Background(), &snapshot)
		refreshDone <- refreshResult{state: state, err: err}
	}()
	waitForTestSignal(t, emitter.entered, "refresh event did not reach emitter")

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout while refresh event blocked: %v", err)
	}
	emitter.unblock()
	waitForTestSignal(t, emitter.loggedOut, "queued Logout event was not delivered")

	if result := waitForRefreshResult(t, refreshDone, "refresh did not return after emitter release"); result.err != nil {
		t.Fatalf("refresh: %v", result.err)
	}
	if got, want := emitter.snapshot(), []string{EventTokenRefreshed, EventLoggedOut}; !slices.Equal(got, want) {
		t.Fatalf("event order = %v, want %v", got, want)
	}
	persisted, err := client.store.Load()
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if !persisted.IsZero() {
		t.Fatalf("persisted state after Logout = %+v, want zero", persisted)
	}
}

func TestEventEmitterCanReenterClientWithoutDeadlock(t *testing.T) {
	emitter := newReentrantLogoutEmitter()
	client, snapshot, endpoint := newRefreshConcurrencyClient(t, nil, emitter)
	emitter.client = client
	snapshot.ExpiresAt = time.Now().Add(time.Second)
	client.stateCommitMu.Lock()
	client.mu.Lock()
	client.setStateLocked(&snapshot)
	client.mu.Unlock()
	if err := client.store.Save(snapshot); err != nil {
		client.stateCommitMu.Unlock()
		t.Fatalf("persist expiring state: %v", err)
	}
	client.stateCommitMu.Unlock()
	endpoint.unblock()

	result := make(chan string, 1)
	go func() {
		result <- client.AccessToken(context.Background())
	}()
	if got := waitForTestString(t, result, "AccessToken did not return"); got != "" {
		t.Fatalf("AccessToken after reentrant Logout = %q, want empty", got)
	}
	waitForTestSignal(t, emitter.loggedOut, "reentrant Logout event was not delivered")

	if got, want := emitter.snapshot(), []string{EventTokenRefreshed, EventLoggedOut}; !slices.Equal(got, want) {
		t.Fatalf("event order = %v, want %v", got, want)
	}
	persisted, err := client.store.Load()
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if !persisted.IsZero() {
		t.Fatalf("persisted state after reentrant Logout = %+v, want zero", persisted)
	}
}

func TestLogoutEventDoesNotWaitForRPLogoutFlow(t *testing.T) {
	emitter := &recordingTestEmitter{}
	client, _, _ := newRefreshConcurrencyClient(t, nil, emitter)
	flow := newBlockingLogoutFlow()
	t.Cleanup(flow.unblock)
	client.flow = flow
	client.mu.Lock()
	client.endSessionEndpoint = "https://idp.example.test/logout"
	client.mu.Unlock()

	logoutDone := make(chan error, 1)
	go func() {
		logoutDone <- client.Logout(context.Background())
	}()
	waitForTestSignal(t, flow.entered, "RP logout flow did not start")

	if got, want := emitter.snapshot(), []string{EventLoggedOut}; !slices.Equal(got, want) {
		t.Fatalf("events while RP logout is pending = %v, want %v", got, want)
	}
	flow.unblock()
	if err := waitForTestError(t, logoutDone, "Logout did not finish"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
}

func TestStaleRefreshDerivedEventIsSuppressed(t *testing.T) {
	emitter := &recordingTestEmitter{}
	client, _, _ := newRefreshConcurrencyClient(t, nil, emitter)

	client.mu.Lock()
	staleRevision := client.stateRevision
	client.mu.Unlock()
	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if client.emitEventIfRevision(staleRevision, EventSessionExpired, nil) {
		t.Fatal("stale refresh-derived event was accepted")
	}
	if got, want := emitter.snapshot(), []string{EventLoggedOut}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestRefreshLoopConcurrentStartsCancelSupersededRunners(t *testing.T) {
	client := &Client{}
	t.Cleanup(client.StopRefreshLoop)
	started := make(chan context.Context, 32)
	run := func(ctx context.Context) {
		started <- ctx
		<-ctx.Done()
	}

	const starts = 32
	begin := make(chan struct{})
	handles := make(chan *refreshLoopHandle, starts)
	var wg sync.WaitGroup
	wg.Add(starts)
	for range starts {
		go func() {
			defer wg.Done()
			<-begin
			handles <- client.startRefreshLoop(context.Background(), run)
		}()
	}
	close(begin)
	waitForTestWaitGroup(t, &wg, "concurrent Start calls did not finish")
	close(handles)

	client.mu.Lock()
	current := client.refreshRun
	client.mu.Unlock()
	if current == nil {
		t.Fatal("no current refresh runner after concurrent starts")
	}

	var all []*refreshLoopHandle
	for handle := range handles {
		all = append(all, handle)
		if handle != current && handle.ctx.Err() == nil {
			t.Fatal("superseded refresh runner context was not cancelled")
		}
	}

	for {
		select {
		case ctx := <-started:
			if ctx == current.ctx {
				goto currentStarted
			}
		case <-time.After(2 * time.Second):
			t.Fatal("current refresh runner did not start")
		}
	}

currentStarted:
	client.StopRefreshLoop()
	for _, handle := range all {
		waitForTestSignal(t, handle.done, "refresh runner did not stop")
	}
}

func TestRefreshLoopConcurrentStartStopLeavesNoLiveRunner(t *testing.T) {
	client := &Client{}
	t.Cleanup(client.StopRefreshLoop)
	run := func(ctx context.Context) {
		<-ctx.Done()
	}

	const operations = 64
	begin := make(chan struct{})
	handles := make(chan *refreshLoopHandle, operations)
	var wg sync.WaitGroup
	wg.Add(operations * 2)
	for range operations {
		go func() {
			defer wg.Done()
			<-begin
			handles <- client.startRefreshLoop(context.Background(), run)
		}()
		go func() {
			defer wg.Done()
			<-begin
			client.StopRefreshLoop()
		}()
	}
	close(begin)
	waitForTestWaitGroup(t, &wg, "concurrent Start/Stop calls did not finish")
	close(handles)

	client.StopRefreshLoop()
	for handle := range handles {
		if handle.ctx.Err() == nil {
			t.Fatal("refresh runner remained uncancelled after final Stop")
		}
		waitForTestSignal(t, handle.done, "refresh runner did not stop")
	}

	client.mu.Lock()
	current := client.refreshRun
	client.mu.Unlock()
	if current != nil {
		t.Fatal("refresh loop handle was not cleared after all runners stopped")
	}
}

func TestRefreshLoopReplacementDoesNotWaitForStuckPredecessor(t *testing.T) {
	client := &Client{}
	firstStarted := make(chan struct{})
	allowFirstExit := make(chan struct{})
	var allowFirstExitOnce sync.Once
	releaseFirst := func() {
		allowFirstExitOnce.Do(func() {
			close(allowFirstExit)
		})
	}
	t.Cleanup(func() {
		client.StopRefreshLoop()
		releaseFirst()
	})
	secondStarted := make(chan struct{})
	var calls atomic.Int32

	run := func(ctx context.Context) {
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-ctx.Done()
			<-allowFirstExit
			return
		}
		close(secondStarted)
		<-ctx.Done()
	}

	first := client.startRefreshLoop(context.Background(), run)
	waitForTestSignal(t, firstStarted, "first refresh runner did not start")
	second := client.startRefreshLoop(context.Background(), run)
	waitForTestSignal(t, secondStarted, "replacement refresh runner waited for its predecessor")
	if first.ctx.Err() == nil {
		t.Fatal("predecessor context was not cancelled")
	}

	client.StopRefreshLoop()
	waitForTestSignal(t, second.done, "replacement refresh runner did not stop")
	releaseFirst()
	waitForTestSignal(t, first.done, "first refresh runner did not exit")
}
