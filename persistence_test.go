package pkceflow

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type scriptedPersistenceResult struct {
	apply bool
	err   error
}

type scriptedPersistenceCall struct {
	operation string
	state     TokenState
	result    chan scriptedPersistenceResult
}

func (c *scriptedPersistenceCall) respond(apply bool, err error) {
	c.result <- scriptedPersistenceResult{apply: apply, err: err}
}

type scriptedPersistenceStore struct {
	mu    sync.Mutex
	state TokenState
	armed bool
	calls chan *scriptedPersistenceCall
}

type persistenceRecordedEvent struct {
	name string
	data any
}

type persistenceEventRecorder struct {
	mu     sync.Mutex
	events []persistenceRecordedEvent
}

func (r *persistenceEventRecorder) Emit(name string, data any) {
	r.mu.Lock()
	r.events = append(r.events, persistenceRecordedEvent{name: name, data: data})
	r.mu.Unlock()
}

func (r *persistenceEventRecorder) count(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	var count int
	for _, event := range r.events {
		if event.name == name {
			count++
		}
	}
	return count
}

func (r *persistenceEventRecorder) snapshot() []persistenceRecordedEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.events)
}

func newScriptedPersistenceStore() *scriptedPersistenceStore {
	return &scriptedPersistenceStore{
		calls: make(chan *scriptedPersistenceCall, 16),
	}
}

func (s *scriptedPersistenceStore) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

func (s *scriptedPersistenceStore) Save(state TokenState) error { //nolint:gocritic // hugeParam: interface requires value parameter
	s.mu.Lock()
	if !s.armed {
		s.state = state
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	call := &scriptedPersistenceCall{
		operation: "save",
		state:     state,
		result:    make(chan scriptedPersistenceResult, 1),
	}
	s.calls <- call
	result := <-call.result
	if result.apply {
		s.mu.Lock()
		s.state = state
		s.mu.Unlock()
	}
	return result.err
}

func (s *scriptedPersistenceStore) Load() (TokenState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, nil
}

func (s *scriptedPersistenceStore) Delete() error {
	s.mu.Lock()
	armed := s.armed
	s.mu.Unlock()
	if !armed {
		s.mu.Lock()
		s.state = TokenState{}
		s.mu.Unlock()
		return nil
	}

	call := &scriptedPersistenceCall{
		operation: "delete",
		result:    make(chan scriptedPersistenceResult, 1),
	}
	s.calls <- call
	result := <-call.result
	if result.apply {
		s.mu.Lock()
		s.state = TokenState{}
		s.mu.Unlock()
	}
	return result.err
}

func (s *scriptedPersistenceStore) nextCall(
	t *testing.T,
	message string,
) *scriptedPersistenceCall {
	t.Helper()
	select {
	case call := <-s.calls:
		return call
	case <-time.After(2 * time.Second):
		t.Fatal(message)
		return nil
	}
}

func (s *scriptedPersistenceStore) assertNoCall(t *testing.T) {
	t.Helper()
	select {
	case call := <-s.calls:
		t.Fatalf("unexpected persistence %s call", call.operation)
	default:
	}
}

func TestPersistenceRetryDelayUsesCappedExponentialBackoff(t *testing.T) {
	tests := []struct {
		failures uint
		want     time.Duration
	}{
		{failures: 1, want: time.Second},
		{failures: 2, want: 2 * time.Second},
		{failures: 3, want: 4 * time.Second},
		{failures: 6, want: 32 * time.Second},
		{failures: 7, want: time.Minute},
		{failures: 100, want: time.Minute},
	}
	for _, tt := range tests {
		if got := persistenceRetryDelay(tt.failures); got != tt.want {
			t.Errorf(
				"persistenceRetryDelay(%d) = %s, want %s",
				tt.failures,
				got,
				tt.want,
			)
		}
	}
}

func TestRotatedRefreshSaveFailureRecoversCurrentGeneration(t *testing.T) {
	store := newScriptedPersistenceStore()
	emitter := &persistenceEventRecorder{}
	client, snapshot, endpoint := newRefreshConcurrencyClient(t, store, emitter)
	var logs bytes.Buffer
	client.logger = slog.New(slog.NewTextHandler(&logs, nil))
	store.arm()
	endpoint.unblock()

	result := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(context.Background(), &snapshot)
		result <- refreshResult{state: state, err: err}
	}()

	initialSave := store.nextCall(t, "refresh did not attempt persistence")
	if initialSave.operation != "save" {
		t.Fatalf("initial persistence operation = %q, want save", initialSave.operation)
	}
	if initialSave.state.RefreshToken != "refresh-1" {
		t.Fatalf(
			"initial persisted refresh token = %q, want rotated token",
			initialSave.state.RefreshToken,
		)
	}
	persistenceErr := errors.New(
		"failed access-1 refresh-1 id-token-old persistence",
	)
	initialSave.respond(false, persistenceErr)

	got := waitForRefreshResult(t, result, "refresh did not return after failed Save")
	if got.err != nil {
		t.Fatalf("refresh error = %v, want nil", got.err)
	}
	if got.state.AccessToken != "access-1" ||
		got.state.RefreshToken != "refresh-1" {
		t.Fatalf("refreshed state = %+v, want rotated generation", got.state)
	}
	if endpoint.requests.Load() != 1 {
		t.Fatalf("token endpoint requests = %d, want 1", endpoint.requests.Load())
	}
	if got := emitter.count(EventTokenRefreshed); got != 1 {
		t.Fatalf("token-refreshed events = %d, want 1", got)
	}

	client.mu.Lock()
	inMemory := client.state
	dirty := client.persistenceRetry
	client.mu.Unlock()
	if inMemory != got.state {
		t.Fatalf("in-memory state = %+v, want %+v", inMemory, got.state)
	}
	if !dirty.valid || dirty.revision == 0 || dirty.failures != 1 {
		t.Fatalf("dirty persistence state = %+v, want first failed revision", dirty)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("Load after failed Save: %v", err)
	}
	if persisted != snapshot {
		t.Fatalf("persisted state = %+v, want previous generation", persisted)
	}

	restoredDirty, err := client.RestoreSession()
	if err != nil {
		t.Fatalf("RestoreSession dirty state: %v", err)
	}
	if !restoredDirty {
		t.Fatal("RestoreSession rejected the authoritative dirty in-memory state")
	}
	client.mu.Lock()
	afterRestore := client.state
	client.mu.Unlock()
	if afterRestore != got.state {
		t.Fatalf("RestoreSession rolled state back to %+v", afterRestore)
	}

	action := client.nextPersistenceRetryAction(dirty.retryAt)
	if !action.claimed || action.revision != dirty.revision {
		t.Fatalf("retry action = %+v, want dirty revision claim", action)
	}
	retryDone := make(chan struct{})
	go func() {
		defer close(retryDone)
		client.retryPersistence(context.Background(), action)
	}()
	retrySave := store.nextCall(t, "persistence recovery did not retry Save")
	if retrySave.operation != "save" || retrySave.state != got.state {
		t.Fatalf("retry call = %+v, want refreshed state Save", retrySave)
	}
	retrySave.respond(true, nil)
	waitForTestSignal(t, retryDone, "persistence retry did not finish")

	client.mu.Lock()
	dirty = client.persistenceRetry
	client.mu.Unlock()
	if dirty.valid {
		t.Fatalf("persistence remained dirty after recovery: %+v", dirty)
	}
	persisted, err = store.Load()
	if err != nil {
		t.Fatalf("Load after recovery: %v", err)
	}
	if persisted != got.state {
		t.Fatalf("persisted recovered state = %+v, want %+v", persisted, got.state)
	}
	if endpoint.requests.Load() != 1 {
		t.Fatalf("recovery repeated token grant: requests = %d", endpoint.requests.Load())
	}
	if got := emitter.count(EventTokenRefreshed); got != 1 {
		t.Fatalf("recovery emitted %d token-refreshed events, want 1 total", got)
	}
	for _, event := range emitter.snapshot() {
		if event.data != nil {
			t.Fatalf("persistence-related auth event exposed payload: %+v", event)
		}
	}

	fresh := &Client{
		store:   store,
		emitter: noopEmitter{},
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	restoredFresh, err := fresh.RestoreSession()
	if err != nil {
		t.Fatalf("fresh RestoreSession: %v", err)
	}
	if !restoredFresh {
		t.Fatal("fresh Client could not restore recovered state")
	}
	fresh.mu.Lock()
	restored := fresh.state
	fresh.mu.Unlock()
	if restored != got.state {
		t.Fatalf("fresh Client restored %+v, want %+v", restored, got.state)
	}

	for _, secret := range []string{"access-1", "refresh-1", "id-token-old"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("persistence log exposed %q: %s", secret, logs.String())
		}
	}
}

func TestPersistenceRecoveryPausesAcrossStopAndResumesOnStart(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	clock := newManualRefreshClock(now)
	store := newScriptedPersistenceStore()
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    now.Add(time.Hour),
		LastAuthAt:   now,
	}
	if err := store.Save(state); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	store.arm()
	client := &Client{
		store:         store,
		emitter:       noopEmitter{},
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:         clock,
		state:         state,
		stateRevision: 1,
	}
	client.recordPersistenceSaveResult(1, errors.New("unavailable"), now)

	client.StartRefreshLoop(context.Background())
	client.mu.Lock()
	firstHandle := client.refreshRun
	client.mu.Unlock()
	if firstHandle == nil {
		t.Fatal("StartRefreshLoop did not install a runner")
	}
	firstTimer := clock.nextTimer(t)
	if want := now.Add(time.Second); !firstTimer.deadline.Equal(want) {
		t.Fatalf("retry deadline = %s, want %s", firstTimer.deadline, want)
	}
	client.StopRefreshLoop()
	firstTimer.waitUntilStopped(t)
	waitForTestSignal(t, firstHandle.done, "stopped persistence supervisor did not exit")
	store.assertNoCall(t)

	clock.set(firstTimer.deadline)
	client.StartRefreshLoop(context.Background())
	client.mu.Lock()
	secondHandle := client.refreshRun
	client.mu.Unlock()
	if secondHandle == nil || secondHandle == firstHandle {
		t.Fatal("StartRefreshLoop did not install a replacement runner")
	}
	retry := store.nextCall(t, "resumed supervisor did not retry overdue Save")
	if retry.operation != "save" || retry.state != state {
		t.Fatalf("resumed persistence call = %+v, want state Save", retry)
	}
	retry.respond(true, nil)
	client.StopRefreshLoop()
	waitForTestSignal(t, secondHandle.done, "resumed persistence supervisor did not exit")

	client.mu.Lock()
	dirty := client.persistenceRetry
	client.mu.Unlock()
	if dirty.valid {
		t.Fatalf("persistence remained dirty after resumed success: %+v", dirty)
	}
	store.assertNoCall(t)
}

func TestPersistenceRetryFailureAndCancellationPreserveGeneration(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 15, 0, 0, time.UTC)
	clock := newManualRefreshClock(now)
	store := newScriptedPersistenceStore()
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    now.Add(time.Hour),
		LastAuthAt:   now,
	}
	if err := store.Save(state); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	store.arm()
	client := &Client{
		store:         store,
		emitter:       noopEmitter{},
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:         clock,
		state:         state,
		stateRevision: 1,
	}
	client.recordPersistenceSaveResult(1, errors.New("initial failure"), now)
	client.mu.Lock()
	firstDue := client.persistenceRetry.retryAt
	client.mu.Unlock()
	clock.set(firstDue)
	firstAction := client.nextPersistenceRetryAction(firstDue)
	if waiting := client.nextPersistenceRetryAction(firstDue); waiting.claimed ||
		!waiting.due.IsZero() {
		t.Fatalf("second observer action = %+v, want claim wait", waiting)
	}

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		client.retryPersistence(context.Background(), firstAction)
	}()
	firstSave := store.nextCall(t, "first persistence retry did not call Save")
	firstSave.respond(true, errors.New("reported failure after publication"))
	waitForTestSignal(t, firstDone, "failed persistence retry did not finish")

	client.mu.Lock()
	dirty := client.persistenceRetry
	client.mu.Unlock()
	if !dirty.valid || dirty.failures != 2 {
		t.Fatalf("dirty state after retry failure = %+v, want two failures", dirty)
	}
	if want := firstDue.Add(2 * time.Second); !dirty.retryAt.Equal(want) {
		t.Fatalf("next retry = %s, want %s", dirty.retryAt, want)
	}

	clock.set(dirty.retryAt)
	canceledAction := client.nextPersistenceRetryAction(dirty.retryAt)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client.retryPersistence(ctx, canceledAction)
	store.assertNoCall(t)

	client.mu.Lock()
	afterCancel := client.persistenceRetry
	client.mu.Unlock()
	if !afterCancel.valid ||
		afterCancel.failures != dirty.failures ||
		afterCancel.claimID != 0 ||
		!afterCancel.retryAt.Equal(dirty.retryAt) {
		t.Fatalf("canceled retry changed dirty state: before=%+v after=%+v", dirty, afterCancel)
	}

	recoveryAction := client.nextPersistenceRetryAction(afterCancel.retryAt)
	recoveryDone := make(chan struct{})
	go func() {
		defer close(recoveryDone)
		client.retryPersistence(context.Background(), recoveryAction)
	}()
	recoverySave := store.nextCall(t, "retry after cancellation did not resume")
	recoverySave.respond(true, nil)
	waitForTestSignal(t, recoveryDone, "recovery after cancellation did not finish")

	client.mu.Lock()
	recovered := client.persistenceRetry
	client.mu.Unlock()
	if recovered.valid {
		t.Fatalf("persistence remained dirty after recovery: %+v", recovered)
	}
}

func TestPersistenceRetryBeforeLogoutLeavesDeletedState(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 30, 0, 0, time.UTC)
	store := newScriptedPersistenceStore()
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		IDToken:      "id",
		ExpiresAt:    now.Add(time.Hour),
		LastAuthAt:   now,
	}
	if err := store.Save(state); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	store.arm()
	emitter := &recordingTestEmitter{}
	client := &Client{
		store:         store,
		emitter:       emitter,
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:         newManualRefreshClock(now),
		state:         state,
		stateRevision: 1,
	}
	client.recordPersistenceSaveResult(1, errors.New("unavailable"), now)
	client.mu.Lock()
	retryAt := client.persistenceRetry.retryAt
	client.mu.Unlock()
	action := client.nextPersistenceRetryAction(retryAt)

	retryDone := make(chan struct{})
	go func() {
		defer close(retryDone)
		client.retryPersistence(context.Background(), action)
	}()
	retrySave := store.nextCall(t, "retry did not reach Save")

	logoutDone := make(chan error, 1)
	go func() {
		logoutDone <- client.Logout(context.Background())
	}()
	retrySave.respond(true, nil)
	deleteCall := store.nextCall(t, "Logout did not delete after retry Save")
	if deleteCall.operation != "delete" {
		t.Fatalf("operation after retry Save = %q, want delete", deleteCall.operation)
	}
	deleteCall.respond(true, nil)
	waitForTestSignal(t, retryDone, "retry did not finish")
	if err := waitForTestError(t, logoutDone, "Logout did not finish"); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !persisted.IsZero() {
		t.Fatalf("persisted state after Logout = %+v, want zero", persisted)
	}
	client.mu.Lock()
	inMemory := client.state
	dirty := client.persistenceRetry
	client.mu.Unlock()
	if !inMemory.IsZero() || dirty.valid {
		t.Fatalf("Logout left state=%+v dirty=%+v", inMemory, dirty)
	}
	if got, want := emitter.snapshot(), []string{EventLoggedOut}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}

	client.retryPersistence(context.Background(), action)
	store.assertNoCall(t)
}

func TestPersistenceRetryInFlightBeforeNewLoginPersistsLoginLast(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 45, 0, 0, time.UTC)
	store := newScriptedPersistenceStore()
	oldState := TokenState{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    now.Add(time.Hour),
		LastAuthAt:   now,
	}
	if err := store.Save(oldState); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	store.arm()
	client := &Client{
		store:         store,
		emitter:       noopEmitter{},
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:         newManualRefreshClock(now),
		state:         oldState,
		stateRevision: 1,
	}
	client.recordPersistenceSaveResult(1, errors.New("old Save failed"), now)
	client.mu.Lock()
	retryAt := client.persistenceRetry.retryAt
	client.mu.Unlock()
	action := client.nextPersistenceRetryAction(retryAt)

	retryDone := make(chan struct{})
	go func() {
		defer close(retryDone)
		client.retryPersistence(context.Background(), action)
	}()
	oldRetry := store.nextCall(t, "old generation retry did not reach Save")
	if oldRetry.operation != "save" || oldRetry.state != oldState {
		t.Fatalf("old retry = %+v, want old state Save", oldRetry)
	}

	operation := client.beginLifecycleOperation(context.Background(), lifecycleLogin)
	defer client.finishLifecycleOperation(operation)
	newState := TokenState{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		IDToken:      "new-id",
		ExpiresAt:    now.Add(2 * time.Hour),
		LastAuthAt:   now.Add(time.Minute),
	}
	type commitResult struct {
		committed bool
		err       error
	}
	loginStarted := make(chan struct{})
	loginDone := make(chan commitResult, 1)
	go func() {
		close(loginStarted)
		committed, err := client.commitLoginState(operation, &newState)
		loginDone <- commitResult{committed: committed, err: err}
	}()
	waitForTestSignal(t, loginStarted, "new Login commit did not start")
	store.assertNoCall(t)

	oldRetry.respond(true, nil)
	loginSave := store.nextCall(t, "new Login did not persist after old retry")
	if loginSave.operation != "save" || loginSave.state != newState {
		t.Fatalf("operation after old retry = %+v, want new Login Save", loginSave)
	}
	loginSave.respond(true, nil)
	waitForTestSignal(t, retryDone, "old retry did not finish")
	committed := <-loginDone
	if !committed.committed || committed.err != nil {
		t.Fatalf("new Login commit = %+v, want success", committed)
	}

	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if persisted != newState {
		t.Fatalf("persisted state = %+v, want newer Login state", persisted)
	}
	client.mu.Lock()
	current := client.state
	dirty := client.persistenceRetry
	client.mu.Unlock()
	if current != newState || dirty.valid {
		t.Fatalf("final state=%+v dirty=%+v, want durable newer Login", current, dirty)
	}
}

func TestNewerRefreshSupersedesClaimedDirtyGeneration(t *testing.T) {
	store := newScriptedPersistenceStore()
	emitter := &recordingTestEmitter{}
	client, snapshot, endpoint := newRefreshConcurrencyClient(t, store, emitter)
	store.arm()
	endpoint.unblock()

	firstDone := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(context.Background(), &snapshot)
		firstDone <- refreshResult{state: state, err: err}
	}()
	firstSave := store.nextCall(t, "first refresh did not reach Save")
	firstSave.respond(false, errors.New("first generation unavailable"))
	first := waitForRefreshResult(t, firstDone, "first refresh did not finish")
	if first.err != nil {
		t.Fatalf("first refresh: %v", first.err)
	}
	client.mu.Lock()
	firstDirty := client.persistenceRetry
	client.mu.Unlock()
	oldAction := client.nextPersistenceRetryAction(firstDirty.retryAt)

	secondDone := make(chan refreshResult, 1)
	go func() {
		state, err := client.refresh(context.Background(), &first.state)
		secondDone <- refreshResult{state: state, err: err}
	}()
	secondSave := store.nextCall(t, "second refresh did not reach Save")
	if secondSave.state.RefreshToken != "refresh-2" {
		t.Fatalf(
			"second Save refresh token = %q, want refresh-2",
			secondSave.state.RefreshToken,
		)
	}
	secondSave.respond(true, nil)
	second := waitForRefreshResult(t, secondDone, "second refresh did not finish")
	if second.err != nil {
		t.Fatalf("second refresh: %v", second.err)
	}

	client.retryPersistence(context.Background(), oldAction)
	store.assertNoCall(t)
	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if persisted != second.state {
		t.Fatalf("persisted state = %+v, want second refresh %+v", persisted, second.state)
	}
	client.mu.Lock()
	dirty := client.persistenceRetry
	client.mu.Unlock()
	if dirty.valid {
		t.Fatalf("newer successful refresh remained dirty: %+v", dirty)
	}
	if endpoint.requests.Load() != 2 {
		t.Fatalf("token endpoint requests = %d, want 2", endpoint.requests.Load())
	}
	if got := emitter.count(EventTokenRefreshed); got != 2 {
		t.Fatalf("token-refreshed events = %d, want 2", got)
	}
}

func TestRefreshLoopReplacementDoesNotDuplicatePersistenceRetry(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 50, 0, 0, time.UTC)
	clock := newManualRefreshClock(now)
	store := newScriptedPersistenceStore()
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    now.Add(time.Hour),
		LastAuthAt:   now,
	}
	if err := store.Save(state); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	store.arm()
	client := &Client{
		store:         store,
		emitter:       noopEmitter{},
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:         clock,
		state:         state,
		stateRevision: 1,
	}
	t.Cleanup(client.StopRefreshLoop)
	client.recordPersistenceSaveResult(1, errors.New("unavailable"), now)

	client.StartRefreshLoop(context.Background())
	client.mu.Lock()
	firstHandle := client.refreshRun
	client.mu.Unlock()
	firstTimer := clock.nextTimer(t)

	client.StartRefreshLoop(context.Background())
	client.mu.Lock()
	secondHandle := client.refreshRun
	client.mu.Unlock()
	firstTimer.waitUntilStopped(t)
	waitForTestSignal(t, firstHandle.done, "first replaced loop did not stop")
	secondTimer := clock.nextTimer(t)
	clock.fire(t, secondTimer)
	save := store.nextCall(t, "replacement loop did not retry Save")

	client.StartRefreshLoop(context.Background())
	client.mu.Lock()
	thirdHandle := client.refreshRun
	client.mu.Unlock()
	if thirdHandle == nil || thirdHandle == secondHandle {
		t.Fatal("second replacement did not install a new loop")
	}
	store.assertNoCall(t)
	save.respond(true, nil)
	waitForTestSignal(t, secondHandle.done, "in-flight replaced loop did not finish")
	client.StopRefreshLoop()
	waitForTestSignal(t, thirdHandle.done, "final replacement loop did not stop")
	store.assertNoCall(t)

	client.mu.Lock()
	dirty := client.persistenceRetry
	client.mu.Unlock()
	if dirty.valid {
		t.Fatalf("persistence remained dirty after single retry: %+v", dirty)
	}
}

func TestNewLoginSaveFailureOwnsPersistenceRecovery(t *testing.T) {
	now := time.Date(2026, time.August, 3, 13, 0, 0, 0, time.UTC)
	store := newScriptedPersistenceStore()
	oldState := TokenState{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    now.Add(time.Hour),
		LastAuthAt:   now,
	}
	if err := store.Save(oldState); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	store.arm()
	client := &Client{
		store:         store,
		emitter:       noopEmitter{},
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:         newManualRefreshClock(now),
		state:         oldState,
		stateRevision: 1,
	}
	client.recordPersistenceSaveResult(1, errors.New("old Save failed"), now)
	client.mu.Lock()
	oldRetryAt := client.persistenceRetry.retryAt
	client.mu.Unlock()
	oldAction := client.nextPersistenceRetryAction(oldRetryAt)

	operation := client.beginLifecycleOperation(context.Background(), lifecycleLogin)
	defer client.finishLifecycleOperation(operation)
	newState := TokenState{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		IDToken:      "new-id",
		ExpiresAt:    now.Add(2 * time.Hour),
		LastAuthAt:   now.Add(time.Minute),
	}
	type commitResult struct {
		committed bool
		err       error
	}
	commitDone := make(chan commitResult, 1)
	go func() {
		committed, err := client.commitLoginState(operation, &newState)
		commitDone <- commitResult{committed: committed, err: err}
	}()

	loginSave := store.nextCall(t, "new Login did not attempt Save")
	if loginSave.operation != "save" || loginSave.state != newState {
		t.Fatalf("Login persistence call = %+v, want new state Save", loginSave)
	}
	loginErr := errors.New("new login persistence unavailable")
	loginSave.respond(false, loginErr)
	committed := <-commitDone
	if !committed.committed || !errors.Is(committed.err, loginErr) {
		t.Fatalf("Login commit result = %+v, want committed persistence error", committed)
	}

	client.mu.Lock()
	current := client.state
	revision := client.stateRevision
	dirty := client.persistenceRetry
	client.mu.Unlock()
	if current != newState {
		t.Fatalf("current state = %+v, want newer Login state", current)
	}
	if !dirty.valid || dirty.revision != revision || dirty.revision == oldAction.revision {
		t.Fatalf("dirty owner = %+v, want newer Login revision %d", dirty, revision)
	}

	client.retryPersistence(context.Background(), oldAction)
	store.assertNoCall(t)

	newAction := client.nextPersistenceRetryAction(dirty.retryAt)
	retryDone := make(chan struct{})
	go func() {
		defer close(retryDone)
		client.retryPersistence(context.Background(), newAction)
	}()
	newRetry := store.nextCall(t, "new Login generation was not retried")
	if newRetry.operation != "save" || newRetry.state != newState {
		t.Fatalf("new generation retry = %+v, want new state Save", newRetry)
	}
	newRetry.respond(true, nil)
	waitForTestSignal(t, retryDone, "new generation retry did not finish")

	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if persisted != newState {
		t.Fatalf("persisted state = %+v, want newer Login state", persisted)
	}
}

type secretErrorPersistenceStore struct {
	err error
}

func (s *secretErrorPersistenceStore) Save(TokenState) error {
	return s.err
}

func (s *secretErrorPersistenceStore) Load() (TokenState, error) {
	return TokenState{}, s.err
}

func (s *secretErrorPersistenceStore) Delete() error {
	return s.err
}

func TestPersistenceErrorsAreRedacted(t *testing.T) {
	secrets := []string{"secret-access", "secret-refresh", "secret-id"}
	var logs bytes.Buffer
	store := &secretErrorPersistenceStore{err: errors.New(strings.Join(secrets, " "))}
	client := &Client{
		store:   store,
		emitter: noopEmitter{},
		logger:  slog.New(slog.NewTextHandler(&logs, nil)),
		state: TokenState{
			AccessToken:  "access",
			RefreshToken: "refresh",
			IDToken:      "id",
		},
		stateRevision: 1,
	}

	restored, restoreErr := client.RestoreSession()
	if restoreErr == nil {
		t.Fatal("RestoreSession did not return the Load error")
	}
	if restored {
		t.Fatal("RestoreSession succeeded despite Load error")
	}
	if !errors.Is(restoreErr, store.err) {
		t.Fatalf("RestoreSession error = %v, want wrapped persistence error", restoreErr)
	}
	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	for _, secret := range secrets {
		if strings.Contains(restoreErr.Error(), secret) {
			t.Fatalf("RestoreSession error exposed %q: %v", secret, restoreErr)
		}
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("persistence logs exposed %q: %s", secret, logs.String())
		}
	}
}

type typedRestoreFailure struct {
	detail string
}

func (e *typedRestoreFailure) Error() string {
	return e.detail
}

type restoreResultStore struct {
	state TokenState
	err   error
}

func (s *restoreResultStore) Save(state TokenState) error { //nolint:gocritic // hugeParam: interface requires value parameter
	s.state = state
	return nil
}

func (s *restoreResultStore) Load() (TokenState, error) {
	return s.state, s.err
}

func (s *restoreResultStore) Delete() error {
	s.state = TokenState{}
	return nil
}

func TestRestoreSessionLoadErrorPreservesStateAndCause(t *testing.T) {
	existing := TokenState{
		AccessToken:  "current-access",
		RefreshToken: "current-refresh",
		IDToken:      "current-id",
		ExpiresAt:    time.Date(2026, time.August, 6, 14, 0, 0, 0, time.UTC),
		LastAuthAt:   time.Date(2026, time.August, 6, 13, 0, 0, 0, time.UTC),
	}
	loaded := TokenState{
		AccessToken:  "untrusted-access",
		RefreshToken: "untrusted-refresh",
		IDToken:      "untrusted-id",
	}
	cause := &typedRestoreFailure{detail: "backend detail with untrusted-access"}
	client := &Client{
		store:         &restoreResultStore{state: loaded, err: cause},
		emitter:       noopEmitter{},
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:         existing,
		stateRevision: 17,
	}

	restored, err := client.RestoreSession()
	if err == nil {
		t.Fatal("RestoreSession returned nil error for backend failure")
	}
	if restored {
		t.Fatal("RestoreSession restored state returned with an error")
	}
	if err == cause {
		t.Fatal("RestoreSession returned the unredacted backend error directly")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(%v, cause) = false", err)
	}
	var typed *typedRestoreFailure
	if !errors.As(err, &typed) || typed != cause {
		t.Fatalf("errors.As(%v) = %v, want original cause", err, typed)
	}
	if strings.Contains(err.Error(), cause.detail) {
		t.Fatalf("RestoreSession error exposed backend detail: %v", err)
	}

	client.mu.Lock()
	state := client.state
	revision := client.stateRevision
	client.mu.Unlock()
	if state != existing || revision != 17 {
		t.Fatalf("RestoreSession error changed state=%+v revision=%d", state, revision)
	}
}

type blockingRestoreStore struct {
	mu      sync.Mutex
	state   TokenState
	err     error
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingRestoreStore) Save(state TokenState) error { //nolint:gocritic // hugeParam: interface requires value parameter
	s.mu.Lock()
	s.state = state
	s.mu.Unlock()
	return nil
}

func (s *blockingRestoreStore) Load() (TokenState, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, s.err
}

func (s *blockingRestoreStore) Delete() error {
	s.mu.Lock()
	s.state = TokenState{}
	s.mu.Unlock()
	return nil
}

func TestRestoreSessionSerializesLoadErrorAgainstLogout(t *testing.T) {
	cause := errors.New("load unavailable")
	store := &blockingRestoreStore{
		state: TokenState{
			AccessToken:  "stored-access",
			RefreshToken: "stored-refresh",
		},
		err:     cause,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	client := &Client{
		store:   store,
		emitter: noopEmitter{},
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		state: TokenState{
			AccessToken:  "current-access",
			RefreshToken: "current-refresh",
		},
		stateRevision: 1,
	}

	type restoreOutcome struct {
		restored bool
		err      error
	}
	restoreDone := make(chan restoreOutcome, 1)
	go func() {
		restored, err := client.RestoreSession()
		restoreDone <- restoreOutcome{restored: restored, err: err}
	}()
	waitForTestSignal(t, store.entered, "RestoreSession did not enter Load")

	logoutDone := make(chan error, 1)
	go func() {
		logoutDone <- client.Logout(context.Background())
	}()
	select {
	case err := <-logoutDone:
		t.Fatalf("Logout completed before RestoreSession released Load: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(store.release)
	result := <-restoreDone
	if result.restored || !errors.Is(result.err, cause) {
		t.Fatalf("RestoreSession result = %+v, want false and wrapped cause", result)
	}
	if err := waitForTestError(t, logoutDone, "Logout did not finish after Load returned"); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	client.mu.Lock()
	state := client.state
	blocked := client.restoreBlocked
	client.mu.Unlock()
	if !state.IsZero() || !blocked {
		t.Fatalf("final state=%+v restoreBlocked=%v, want logged out", state, blocked)
	}
}

func TestFailedLogoutDeleteBlocksSameClientRestore(t *testing.T) {
	now := time.Date(2026, time.August, 3, 14, 0, 0, 0, time.UTC)
	store := newScriptedPersistenceStore()
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		IDToken:      "id",
		ExpiresAt:    now.Add(time.Hour),
		LastAuthAt:   now,
	}
	if err := store.Save(state); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	store.arm()
	client := &Client{
		store:         store,
		emitter:       noopEmitter{},
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:         state,
		stateRevision: 1,
	}

	logoutDone := make(chan error, 1)
	go func() {
		logoutDone <- client.Logout(context.Background())
	}()
	deleteCall := store.nextCall(t, "Logout did not attempt Delete")
	deleteCall.respond(false, errors.New("Delete failed"))
	if err := waitForTestError(t, logoutDone, "Logout did not finish"); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("Load persisted state: %v", err)
	}
	if persisted != state {
		t.Fatalf("failed Delete changed persisted state: %+v", persisted)
	}
	restored, err := client.RestoreSession()
	if err != nil {
		t.Fatalf("RestoreSession after Logout: %v", err)
	}
	if restored {
		t.Fatal("same Client restored state after local Logout")
	}
	client.mu.Lock()
	inMemory := client.state
	blocked := client.restoreBlocked
	client.mu.Unlock()
	if !inMemory.IsZero() || !blocked {
		t.Fatalf("post-Logout state=%+v restoreBlocked=%v", inMemory, blocked)
	}
}

func TestPreRecoveryRestartOutcomesAreExplicit(t *testing.T) {
	now := time.Date(2026, time.August, 3, 14, 15, 0, 0, time.UTC)
	oldState := TokenState{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    now.Add(time.Hour),
		LastAuthAt:   now,
	}
	newState := TokenState{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		ExpiresAt:    now.Add(2 * time.Hour),
		LastAuthAt:   now.Add(time.Minute),
	}
	tests := []struct {
		name      string
		persisted TokenState
		wantFound bool
	}{
		{name: "old generation", persisted: oldState, wantFound: true},
		{name: "new generation", persisted: newState, wantFound: true},
		{name: "no readable generation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newScriptedPersistenceStore()
			if !tt.persisted.IsZero() {
				if err := store.Save(tt.persisted); err != nil {
					t.Fatalf("seed persisted outcome: %v", err)
				}
			}
			fresh := &Client{
				store:   store,
				emitter: noopEmitter{},
				logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			got, err := fresh.RestoreSession()
			if err != nil {
				t.Fatalf("RestoreSession: %v", err)
			}
			if got != tt.wantFound {
				t.Fatalf("RestoreSession = %v, want %v", got, tt.wantFound)
			}
			fresh.mu.Lock()
			restored := fresh.state
			fresh.mu.Unlock()
			if restored != tt.persisted {
				t.Fatalf("restored state = %+v, want %+v", restored, tt.persisted)
			}
		})
	}
}
