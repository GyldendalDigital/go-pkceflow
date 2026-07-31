package pkceflow

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type manualRefreshClock struct {
	mu      sync.Mutex
	now     time.Time
	created chan *manualRefreshTimer
}

func newManualRefreshClock(now time.Time) *manualRefreshClock {
	return &manualRefreshClock{
		now:     now,
		created: make(chan *manualRefreshTimer, 64),
	}
}

func (c *manualRefreshClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualRefreshClock) NewTimer(delay time.Duration) refreshTimer {
	c.mu.Lock()
	timer := &manualRefreshTimer{
		deadline: c.now.Add(delay),
		ch:       make(chan time.Time, 1),
		stopped:  make(chan struct{}),
	}
	c.mu.Unlock()
	c.created <- timer
	return timer
}

func (c *manualRefreshClock) set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

func (c *manualRefreshClock) nextTimer(t *testing.T) *manualRefreshTimer {
	t.Helper()
	select {
	case timer := <-c.created:
		return timer
	case <-time.After(2 * time.Second):
		t.Fatal("refresh loop did not create a timer")
		return nil
	}
}

func (c *manualRefreshClock) fire(t *testing.T, timer *manualRefreshTimer) {
	t.Helper()
	c.set(timer.deadline)
	if !timer.fire() {
		t.Fatalf("cannot fire stopped or completed timer for %s", timer.deadline)
	}
}

type manualRefreshTimer struct {
	mu       sync.Mutex
	deadline time.Time
	ch       chan time.Time
	stopped  chan struct{}
	didStop  bool
	fired    bool
}

func (t *manualRefreshTimer) channel() <-chan time.Time {
	return t.ch
}

func (t *manualRefreshTimer) stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.didStop || t.fired {
		return false
	}
	t.didStop = true
	close(t.stopped)
	return true
}

func (t *manualRefreshTimer) fire() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.didStop || t.fired {
		return false
	}
	t.fired = true
	t.ch <- t.deadline
	return true
}

func (t *manualRefreshTimer) waitUntilStopped(testingT *testing.T) {
	testingT.Helper()
	select {
	case <-t.stopped:
	case <-time.After(2 * time.Second):
		testingT.Fatal("refresh timer was not stopped")
	}
}

type scriptedRefreshLoop struct {
	calls   chan refreshLoopAction
	results chan refreshLoopAttemptResult
}

func newScriptedRefreshLoop() *scriptedRefreshLoop {
	return &scriptedRefreshLoop{
		calls:   make(chan refreshLoopAction, 16),
		results: make(chan refreshLoopAttemptResult, 16),
	}
}

func (s *scriptedRefreshLoop) attempt(
	ctx context.Context,
	action refreshLoopAction,
) refreshLoopAttemptResult {
	select {
	case s.calls <- action:
	case <-ctx.Done():
		return refreshLoopAttemptCanceledAfterStart
	}

	select {
	case result := <-s.results:
		return result
	case <-ctx.Done():
		return refreshLoopAttemptCanceledAfterStart
	}
}

func (s *scriptedRefreshLoop) nextCall(t *testing.T) refreshLoopAction {
	t.Helper()
	select {
	case call := <-s.calls:
		return call
	case <-time.After(2 * time.Second):
		t.Fatal("refresh loop did not attempt a refresh")
		return refreshLoopAction{}
	}
}

type refreshLoopEventRecorder struct {
	events chan string
}

func newRefreshLoopEventRecorder() *refreshLoopEventRecorder {
	return &refreshLoopEventRecorder{events: make(chan string, 16)}
}

func (r *refreshLoopEventRecorder) Emit(name string, _ any) {
	r.events <- name
}

func newRefreshLoopTestClient(
	clock *manualRefreshClock,
	state *TokenState,
	gracePeriod time.Duration,
	emitter EventEmitter,
) *Client {
	if emitter == nil {
		emitter = noopEmitter{}
	}
	return &Client{
		config:        Config{GracePeriod: gracePeriod},
		store:         &memoryStore{},
		emitter:       emitter,
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:         clock,
		state:         *state,
		stateRevision: 1,
		oauth2:        &oauth2.Config{},
		verifier:      &oidc.IDTokenVerifier{},
	}
}

func startRefreshLoopTest(
	client *Client,
	script *scriptedRefreshLoop,
) (context.CancelFunc, <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.runRefreshLoop(ctx, script.attempt)
	}()
	return cancel, done
}

func stopRefreshLoopTest(
	t *testing.T,
	cancel context.CancelFunc,
	done <-chan struct{},
) {
	t.Helper()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh loop did not stop")
	}
}

func TestRefreshStageTimeUsesOriginalLifetimeThresholds(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	state := TokenState{
		LastAuthAt: authenticatedAt,
		ExpiresAt:  authenticatedAt.Add(100 * time.Second),
	}

	tests := []struct {
		stage uint
		want  time.Time
	}{
		{stage: 1, want: authenticatedAt.Add(50 * time.Second)},
		{stage: 2, want: authenticatedAt.Add(75 * time.Second)},
		{stage: 3, want: authenticatedAt.Add(87500 * time.Millisecond)},
	}
	for _, tt := range tests {
		got, ok := refreshStageTime(&state, tt.stage)
		if !ok {
			t.Fatalf("stage %d was not schedulable", tt.stage)
		}
		if !got.Equal(tt.want) {
			t.Errorf("stage %d due = %s, want %s", tt.stage, got, tt.want)
		}
	}
}

func TestRefreshStageTimeRejectsInvalidLifetime(t *testing.T) {
	now := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	tests := []TokenState{
		{LastAuthAt: now},
		{ExpiresAt: now.Add(time.Minute)},
		{LastAuthAt: now, ExpiresAt: now},
		{LastAuthAt: now.Add(time.Second), ExpiresAt: now},
	}
	for i := range tests {
		if _, ok := refreshStageTime(&tests[i], 1); ok {
			t.Errorf("case %d unexpectedly produced a refresh threshold", i)
		}
	}
}

func TestRefreshLoopShortLifetimeKeepsExactFirstThreshold(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(8 * time.Second),
	}
	client := newRefreshLoopTestClient(newManualRefreshClock(authenticatedAt), &state, 0, nil)

	action := client.nextRefreshLoopAction(authenticatedAt)
	want := authenticatedAt.Add(4 * time.Second)
	if action.kind != refreshLoopWait || !action.due.Equal(want) {
		t.Fatalf("first action = %#v, want wait until %s", action, want)
	}
}

func TestRefreshLoopInvalidLifetimeMetadataRemainsIdle(t *testing.T) {
	now := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		state TokenState
	}{
		{
			name: "zero expiry",
			state: TokenState{
				AccessToken:  "access",
				RefreshToken: "refresh",
				LastAuthAt:   now,
			},
		},
		{
			name: "zero authentication time",
			state: TokenState{
				AccessToken:  "access",
				RefreshToken: "refresh",
				ExpiresAt:    now.Add(time.Hour),
			},
		},
		{
			name: "non-positive lifetime",
			state: TokenState{
				AccessToken:  "access",
				RefreshToken: "refresh",
				LastAuthAt:   now.Add(time.Hour),
				ExpiresAt:    now.Add(time.Hour),
			},
		},
	}
	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			client := newRefreshLoopTestClient(
				newManualRefreshClock(now),
				&tt.state,
				0,
				nil,
			)
			action := client.nextRefreshLoopAction(now)
			if action.kind != refreshLoopWait || !action.due.IsZero() {
				t.Fatalf("action = %#v, want idle wait", action)
			}
			if client.refreshSchedule.claimID != 0 {
				t.Fatalf("invalid lifetime claimed attempt %d", client.refreshSchedule.claimID)
			}
		})
	}
}

func TestRefreshLoopTemporaryFailuresFollowThresholds(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	clock := newManualRefreshClock(authenticatedAt)
	client := newRefreshLoopTestClient(clock, &TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(100 * time.Second),
	}, 0, nil)
	script := newScriptedRefreshLoop()
	cancel, done := startRefreshLoopTest(client, script)
	defer stopRefreshLoopTest(t, cancel, done)

	first := clock.nextTimer(t)
	if want := authenticatedAt.Add(50 * time.Second); !first.deadline.Equal(want) {
		t.Fatalf("first deadline = %s, want %s", first.deadline, want)
	}
	select {
	case call := <-script.calls:
		t.Fatalf("eager refresh at stage %d", call.stage)
	default:
	}

	clock.fire(t, first)
	if call := script.nextCall(t); call.stage != 1 {
		t.Fatalf("first attempt stage = %d, want 1", call.stage)
	}
	script.results <- refreshLoopAttemptTemporary

	second := clock.nextTimer(t)
	if want := authenticatedAt.Add(75 * time.Second); !second.deadline.Equal(want) {
		t.Fatalf("second deadline = %s, want %s", second.deadline, want)
	}
	clock.fire(t, second)
	if call := script.nextCall(t); call.stage != 2 {
		t.Fatalf("second attempt stage = %d, want 2", call.stage)
	}
	script.results <- refreshLoopAttemptTemporary

	third := clock.nextTimer(t)
	if want := authenticatedAt.Add(87500 * time.Millisecond); !third.deadline.Equal(want) {
		t.Fatalf("third deadline = %s, want %s", third.deadline, want)
	}
	clock.fire(t, third)
	if call := script.nextCall(t); call.stage != 3 {
		t.Fatalf("third attempt stage = %d, want 3", call.stage)
	}
}

func TestRefreshLoopMinimumIntervalCanExhaustGeneration(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(40 * time.Second),
	}
	client := newRefreshLoopTestClient(newManualRefreshClock(authenticatedAt), &state, 0, nil)

	action := client.nextRefreshLoopAction(authenticatedAt.Add(20 * time.Second))
	if action.kind != refreshLoopAttempt || action.stage != 1 {
		t.Fatalf("midpoint action = %#v, want stage-1 attempt", action)
	}
	client.finishRefreshLoopAttempt(
		action,
		refreshLoopAttemptTemporary,
		authenticatedAt.Add(35*time.Second),
	)

	next := client.nextRefreshLoopAction(authenticatedAt.Add(35 * time.Second))
	if next.kind != refreshLoopWait || !next.due.IsZero() {
		t.Fatalf("exhausted generation action = %#v, want parked wait", next)
	}
	if client.refreshSchedule.disposition != refreshLoopBlockedExpired {
		t.Fatalf(
			"disposition = %d, want expired block",
			client.refreshSchedule.disposition,
		)
	}
}

func TestRefreshLoopMinimumIntervalStartsAtFailureCompletion(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(100 * time.Second),
	}
	client := newRefreshLoopTestClient(newManualRefreshClock(authenticatedAt), &state, 0, nil)

	firstDue := authenticatedAt.Add(50 * time.Second)
	action := client.nextRefreshLoopAction(firstDue)
	completedAt := authenticatedAt.Add(74 * time.Second)
	client.finishRefreshLoopAttempt(
		action,
		refreshLoopAttemptTemporary,
		completedAt,
	)

	next := client.nextRefreshLoopAction(completedAt)
	want := completedAt.Add(minRefreshInterval)
	if next.kind != refreshLoopWait || !next.due.Equal(want) {
		t.Fatalf("next action = %#v, want wait until %s", next, want)
	}
}

func TestRefreshLoopSuccessResetsScheduleFromNewState(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	clock := newManualRefreshClock(authenticatedAt)
	client := newRefreshLoopTestClient(clock, &TokenState{
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(100 * time.Second),
	}, 0, nil)
	script := newScriptedRefreshLoop()
	cancel, done := startRefreshLoopTest(client, script)
	defer stopRefreshLoopTest(t, cancel, done)

	first := clock.nextTimer(t)
	clock.fire(t, first)
	_ = script.nextCall(t)

	nextState := TokenState{
		AccessToken:  "access-2",
		RefreshToken: "refresh-2",
		LastAuthAt:   authenticatedAt.Add(50 * time.Second),
		ExpiresAt:    authenticatedAt.Add(250 * time.Second),
	}
	client.mu.Lock()
	client.advanceStateLocked(&nextState)
	client.mu.Unlock()
	script.results <- refreshLoopAttemptSucceeded

	reset := clock.nextTimer(t)
	if want := authenticatedAt.Add(150 * time.Second); !reset.deadline.Equal(want) {
		t.Fatalf("reset deadline = %s, want %s", reset.deadline, want)
	}
}

func TestRefreshLoopStateChangeReplacesPendingTimer(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	clock := newManualRefreshClock(authenticatedAt)
	client := newRefreshLoopTestClient(clock, &TokenState{
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(100 * time.Second),
	}, 0, nil)
	script := newScriptedRefreshLoop()
	cancel, done := startRefreshLoopTest(client, script)
	defer stopRefreshLoopTest(t, cancel, done)

	stale := clock.nextTimer(t)
	nextState := TokenState{
		AccessToken:  "access-2",
		RefreshToken: "refresh-2",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(200 * time.Second),
	}
	client.mu.Lock()
	client.advanceStateLocked(&nextState)
	client.mu.Unlock()

	current := clock.nextTimer(t)
	if want := authenticatedAt.Add(100 * time.Second); !current.deadline.Equal(want) {
		t.Fatalf("replacement deadline = %s, want %s", current.deadline, want)
	}
	stale.waitUntilStopped(t)
}

func TestRefreshLoopWakesAfterStateAndInitChanges(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)

	t.Run("state", func(t *testing.T) {
		clock := newManualRefreshClock(authenticatedAt)
		client := newRefreshLoopTestClient(clock, &TokenState{}, 0, nil)
		script := newScriptedRefreshLoop()
		cancel, done := startRefreshLoopTest(client, script)
		defer stopRefreshLoopTest(t, cancel, done)

		state := TokenState{
			AccessToken:  "access",
			RefreshToken: "refresh",
			LastAuthAt:   authenticatedAt,
			ExpiresAt:    authenticatedAt.Add(100 * time.Second),
		}
		client.mu.Lock()
		client.advanceStateLocked(&state)
		client.mu.Unlock()

		timer := clock.nextTimer(t)
		if want := authenticatedAt.Add(50 * time.Second); !timer.deadline.Equal(want) {
			t.Fatalf("deadline after state wake = %s, want %s", timer.deadline, want)
		}
	})

	t.Run("init", func(t *testing.T) {
		clock := newManualRefreshClock(authenticatedAt.Add(60 * time.Second))
		client := newRefreshLoopTestClient(clock, &TokenState{
			AccessToken:  "access",
			RefreshToken: "refresh",
			LastAuthAt:   authenticatedAt,
			ExpiresAt:    authenticatedAt.Add(100 * time.Second),
		}, 0, nil)
		client.oauth2 = nil
		client.verifier = nil
		script := newScriptedRefreshLoop()
		cancel, done := startRefreshLoopTest(client, script)
		defer stopRefreshLoopTest(t, cancel, done)

		client.mu.Lock()
		client.oauth2 = &oauth2.Config{}
		client.verifier = &oidc.IDTokenVerifier{}
		client.signalRefreshLoopLocked()
		client.mu.Unlock()

		call := script.nextCall(t)
		if call.stage != 1 {
			t.Fatalf("overdue attempt stage = %d, want 1", call.stage)
		}
	})
}

func TestRefreshLoopPermanentFailureSurvivesRestartAndEmitsAtGraceEnd(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	clock := newManualRefreshClock(authenticatedAt)
	emitter := newRefreshLoopEventRecorder()
	client := newRefreshLoopTestClient(clock, &TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(100 * time.Second),
	}, 200*time.Second, emitter)
	script := newScriptedRefreshLoop()

	cancel, done := startRefreshLoopTest(client, script)
	first := clock.nextTimer(t)
	clock.fire(t, first)
	_ = script.nextCall(t)
	script.results <- refreshLoopAttemptPermanent

	graceTimer := clock.nextTimer(t)
	graceEnd := authenticatedAt.Add(200 * time.Second)
	if !graceTimer.deadline.Equal(graceEnd) {
		t.Fatalf("grace deadline = %s, want %s", graceTimer.deadline, graceEnd)
	}
	select {
	case event := <-emitter.events:
		t.Fatalf("event %q emitted before grace end", event)
	default:
	}
	stopRefreshLoopTest(t, cancel, done)

	restarted := newScriptedRefreshLoop()
	cancel, done = startRefreshLoopTest(client, restarted)
	defer stopRefreshLoopTest(t, cancel, done)
	restartedTimer := clock.nextTimer(t)
	if !restartedTimer.deadline.Equal(graceEnd) {
		t.Fatalf(
			"restart grace deadline = %s, want %s",
			restartedTimer.deadline,
			graceEnd,
		)
	}
	clock.fire(t, restartedTimer)

	select {
	case event := <-emitter.events:
		if event != EventSessionExpired {
			t.Fatalf("event = %q, want %q", event, EventSessionExpired)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session-expired event was not emitted at grace end")
	}
	select {
	case call := <-restarted.calls:
		t.Fatalf("permanently blocked generation retried at stage %d", call.stage)
	default:
	}
	select {
	case event := <-emitter.events:
		t.Fatalf("duplicate terminal event %q", event)
	default:
	}
}

func TestRefreshLoopIntegrityFailureEmitsImmediatelyAndFailsClosed(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	clock := newManualRefreshClock(authenticatedAt)
	emitter := newRefreshLoopEventRecorder()
	client := newRefreshLoopTestClient(clock, &TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(100 * time.Second),
	}, time.Hour, emitter)
	script := newScriptedRefreshLoop()
	cancel, done := startRefreshLoopTest(client, script)
	defer stopRefreshLoopTest(t, cancel, done)

	first := clock.nextTimer(t)
	clock.fire(t, first)
	_ = script.nextCall(t)
	script.results <- refreshLoopAttemptIntegrity

	select {
	case event := <-emitter.events:
		if event != EventSessionExpired {
			t.Fatalf("event = %q, want %q", event, EventSessionExpired)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("integrity failure did not emit session-expired")
	}
	if token := client.AccessToken(context.Background()); token != "" {
		t.Fatalf("AccessToken after integrity failure = %q, want empty", token)
	}
	if status := client.AuthStatus(); status != (AuthStatusResult{}) {
		t.Fatalf("AuthStatus after integrity failure = %+v, want unusable", status)
	}
}

func TestRefreshLoopExpiryParksWithoutEventAndLeavesGraceToAuthStatus(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	expiresAt := authenticatedAt.Add(time.Hour)

	tests := []struct {
		name      string
		grace     time.Duration
		wantGrace bool
	}{
		{name: "grace disabled"},
		{name: "grace active", grace: 24 * time.Hour, wantGrace: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newManualRefreshClock(expiresAt)
			emitter := newRefreshLoopEventRecorder()
			client := newRefreshLoopTestClient(clock, &TokenState{
				AccessToken:  "access",
				RefreshToken: "refresh",
				LastAuthAt:   authenticatedAt,
				ExpiresAt:    expiresAt,
			}, tt.grace, emitter)

			action := client.nextRefreshLoopAction(expiresAt)
			if action.kind != refreshLoopWait || !action.due.IsZero() {
				t.Fatalf("expiry action = %#v, want parked wait", action)
			}
			if client.refreshSchedule.disposition != refreshLoopBlockedExpired {
				t.Fatalf(
					"disposition = %d, want expired block",
					client.refreshSchedule.disposition,
				)
			}
			select {
			case event := <-emitter.events:
				t.Fatalf("expiry emitted event %q", event)
			default:
			}
			status := client.AuthStatus()
			if status.GraceMode != tt.wantGrace || status.CanUseApp != tt.wantGrace {
				t.Fatalf("AuthStatus = %+v, want grace=%v", status, tt.wantGrace)
			}
		})
	}
}

func TestRefreshLoopCancellationPreservesCorrectStage(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(100 * time.Second),
	}
	client := newRefreshLoopTestClient(newManualRefreshClock(authenticatedAt), &state, 0, nil)
	due := authenticatedAt.Add(50 * time.Second)

	beforeStart := client.nextRefreshLoopAction(due)
	client.finishRefreshLoopAttempt(
		beforeStart,
		refreshLoopAttemptCanceledBeforeStart,
		due,
	)
	if client.refreshSchedule.nextStage != 1 ||
		!client.refreshSchedule.retryNotBefore.IsZero() {
		t.Fatalf(
			"pre-start cancellation changed schedule: %+v",
			client.refreshSchedule,
		)
	}

	afterStart := client.nextRefreshLoopAction(due)
	client.finishRefreshLoopAttempt(
		afterStart,
		refreshLoopAttemptCanceledAfterStart,
		due,
	)
	if client.refreshSchedule.nextStage != 2 {
		t.Fatalf(
			"post-start cancellation stage = %d, want 2",
			client.refreshSchedule.nextStage,
		)
	}
	if want := due.Add(minRefreshInterval); !client.refreshSchedule.retryNotBefore.Equal(want) {
		t.Fatalf(
			"retry-not-before = %s, want %s",
			client.refreshSchedule.retryNotBefore,
			want,
		)
	}
}

func TestRefreshLoopAttemptClaimHasSingleOwner(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(100 * time.Second),
	}
	client := newRefreshLoopTestClient(newManualRefreshClock(authenticatedAt), &state, 0, nil)
	due := authenticatedAt.Add(50 * time.Second)

	const observers = 16
	start := make(chan struct{})
	actions := make(chan refreshLoopAction, observers)
	var group sync.WaitGroup
	group.Add(observers)
	for range observers {
		go func() {
			defer group.Done()
			<-start
			actions <- client.nextRefreshLoopAction(due)
		}()
	}
	close(start)
	group.Wait()
	close(actions)

	var claimed *refreshLoopAction
	for action := range actions {
		switch action.kind {
		case refreshLoopAttempt:
			if claimed != nil {
				t.Fatalf("multiple attempt claims: %#v and %#v", *claimed, action)
			}
			claimedAction := action
			claimed = &claimedAction
		case refreshLoopWait:
		default:
			t.Fatalf("unexpected concurrent action: %#v", action)
		}
	}
	if claimed == nil {
		t.Fatal("no observer claimed the due refresh attempt")
	}

	client.finishRefreshLoopAttempt(
		*claimed,
		refreshLoopAttemptTemporary,
		due,
	)
	if client.refreshSchedule.nextStage != 2 {
		t.Fatalf(
			"completed claim advanced to stage %d, want 2",
			client.refreshSchedule.nextStage,
		)
	}
}

func TestRefreshLoopTerminalEventClaimHasSingleOwner(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(100 * time.Second),
	}
	client := newRefreshLoopTestClient(newManualRefreshClock(authenticatedAt), &state, 0, nil)
	client.refreshSchedule = refreshLoopSchedule{
		valid:        true,
		revision:     client.stateRevision,
		nextStage:    1,
		disposition:  refreshLoopBlockedPermanent,
		eventAt:      authenticatedAt,
		eventEmitted: false,
	}

	const observers = 16
	start := make(chan struct{})
	actions := make(chan refreshLoopAction, observers)
	var group sync.WaitGroup
	group.Add(observers)
	for range observers {
		go func() {
			defer group.Done()
			<-start
			actions <- client.nextRefreshLoopAction(authenticatedAt)
		}()
	}
	close(start)
	group.Wait()
	close(actions)

	var emits int
	for action := range actions {
		if action.kind == refreshLoopEmitSessionExpired {
			emits++
		}
	}
	if emits != 1 {
		t.Fatalf("terminal event claims = %d, want 1", emits)
	}
}

func TestRefreshLoopSharedIntegrityFailureDoesNotRearmClaimedEvent(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(100 * time.Second),
	}
	client := newRefreshLoopTestClient(
		newManualRefreshClock(authenticatedAt),
		&state,
		time.Hour,
		nil,
	)
	due := authenticatedAt.Add(50 * time.Second)

	background := client.nextRefreshLoopAction(due)
	client.finishRefreshLoopAttempt(
		background,
		refreshLoopAttemptIntegrity,
		due,
	)
	terminal := client.nextRefreshLoopAction(due)
	if terminal.kind != refreshLoopEmitSessionExpired {
		t.Fatalf("terminal action = %#v, want session-expired emission", terminal)
	}

	// Model the AccessToken participant observing the same shared integrity
	// failure after the background supervisor has claimed the terminal event.
	client.blockRefreshIntegrity(background.revision, due)

	next := client.nextRefreshLoopAction(due)
	if next.kind != refreshLoopWait || !next.due.IsZero() {
		t.Fatalf("same integrity failure re-armed terminal event: %#v", next)
	}
	if !client.refreshSchedule.eventEmitted {
		t.Fatal("manual integrity transition cleared the claimed event marker")
	}
}

func TestRefreshLoopAttemptStartedBeforeExpiryMayResetAfterExpiry(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	expiresAt := authenticatedAt.Add(100 * time.Second)
	clock := newManualRefreshClock(authenticatedAt)
	client := newRefreshLoopTestClient(clock, &TokenState{
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    expiresAt,
	}, 0, nil)
	script := newScriptedRefreshLoop()
	cancel, done := startRefreshLoopTest(client, script)
	defer stopRefreshLoopTest(t, cancel, done)

	first := clock.nextTimer(t)
	clock.fire(t, first)
	_ = script.nextCall(t)

	completedAt := expiresAt.Add(time.Second)
	clock.set(completedAt)
	nextState := TokenState{
		AccessToken:  "access-2",
		RefreshToken: "refresh-2",
		LastAuthAt:   completedAt,
		ExpiresAt:    completedAt.Add(100 * time.Second),
	}
	client.mu.Lock()
	client.advanceStateLocked(&nextState)
	client.mu.Unlock()
	script.results <- refreshLoopAttemptSucceeded

	reset := clock.nextTimer(t)
	if want := completedAt.Add(50 * time.Second); !reset.deadline.Equal(want) {
		t.Fatalf("post-expiry success deadline = %s, want %s", reset.deadline, want)
	}
}

func TestAdvanceStateLockedForcesSemanticGeneration(t *testing.T) {
	now := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   now,
		ExpiresAt:    now.Add(time.Hour),
	}
	client := newRefreshLoopTestClient(newManualRefreshClock(now), &state, 0, nil)
	client.refreshSchedule = refreshLoopSchedule{
		valid:       true,
		revision:    client.stateRevision,
		nextStage:   3,
		disposition: refreshLoopBlockedPermanent,
	}
	before := client.stateRevision

	client.mu.Lock()
	client.advanceStateLocked(&state)
	client.mu.Unlock()

	if client.stateRevision != before+1 {
		t.Fatalf(
			"state revision = %d, want %d",
			client.stateRevision,
			before+1,
		)
	}
	if client.refreshSchedule != (refreshLoopSchedule{}) {
		t.Fatalf("schedule was not reset: %+v", client.refreshSchedule)
	}
}

func TestRefreshLoopProductionRefreshClassifiesPermanentOAuthFailure(t *testing.T) {
	authenticatedAt := time.Now().UTC().Truncate(time.Second)
	clock := newManualRefreshClock(authenticatedAt)
	emitter := newRefreshLoopEventRecorder()
	client, state, endpoint := newRefreshConcurrencyClient(t, nil, emitter)
	state.LastAuthAt = authenticatedAt
	state.ExpiresAt = authenticatedAt.Add(100 * time.Second)
	client.mu.Lock()
	client.state = state
	client.clock = clock
	client.mu.Unlock()
	endpoint.oauthError = "invalid_grant"
	endpoint.unblock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.refreshLoop(ctx)
	}()
	defer stopRefreshLoopTest(t, cancel, done)

	first := clock.nextTimer(t)
	clock.fire(t, first)
	select {
	case <-endpoint.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("production refresh did not reach the token endpoint")
	}
	select {
	case event := <-emitter.events:
		if event != EventSessionExpired {
			t.Fatalf("event = %q, want %q", event, EventSessionExpired)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("permanent OAuth failure did not emit session-expired")
	}
	if requests := endpoint.requests.Load(); requests != 1 {
		t.Fatalf("token endpoint requests = %d, want 1", requests)
	}
}

func TestRefreshLoopProductionIntegrityFailureEmitsOnceAndStops(t *testing.T) {
	authenticatedAt := time.Now().UTC().Truncate(time.Second)
	clock := newManualRefreshClock(authenticatedAt)
	emitter := newRefreshLoopEventRecorder()
	client, state, endpoint := newRefreshConcurrencyClient(t, nil, emitter)
	state.LastAuthAt = authenticatedAt
	state.ExpiresAt = authenticatedAt.Add(100 * time.Second)
	client.mu.Lock()
	client.state = state
	client.clock = clock
	client.config.GracePeriod = time.Hour
	client.verifier = oidc.NewVerifier(
		"https://issuer.example",
		&oidc.StaticKeySet{},
		&oidc.Config{ClientID: "test-client"},
	)
	client.mu.Unlock()
	endpoint.idToken = "not.a.jwt"
	endpoint.unblock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.refreshLoop(ctx)
	}()
	defer stopRefreshLoopTest(t, cancel, done)

	first := clock.nextTimer(t)
	clock.fire(t, first)
	select {
	case <-endpoint.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("production refresh did not reach the token endpoint")
	}
	select {
	case event := <-emitter.events:
		if event != EventSessionExpired {
			t.Fatalf("event = %q, want %q", event, EventSessionExpired)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("integrity failure did not emit session-expired")
	}
	select {
	case event := <-emitter.events:
		t.Fatalf("unexpected second event after integrity failure: %q", event)
	default:
	}
	if requests := endpoint.requests.Load(); requests != 1 {
		t.Fatalf("token endpoint requests = %d, want 1", requests)
	}
	if token := client.AccessToken(context.Background()); token != "" {
		t.Fatalf("AccessToken after production integrity failure = %q", token)
	}
	if status := client.AuthStatus(); status != (AuthStatusResult{}) {
		t.Fatalf("AuthStatus after production integrity failure = %+v", status)
	}
}

func TestAccessTokenPermanentFailureParksSchedulerGeneration(t *testing.T) {
	authenticatedAt := time.Now().UTC().Truncate(time.Second)
	clock := newManualRefreshClock(authenticatedAt.Add(80 * time.Second))
	client, state, endpoint := newRefreshConcurrencyClient(t, nil, nil)
	state.LastAuthAt = authenticatedAt
	state.ExpiresAt = authenticatedAt.Add(100 * time.Second)
	client.mu.Lock()
	client.state = state
	client.clock = clock
	client.config.GracePeriod = time.Hour
	client.mu.Unlock()
	endpoint.oauthError = "invalid_grant"
	endpoint.unblock()

	if token := client.AccessToken(context.Background()); token != state.AccessToken {
		t.Fatalf("AccessToken in grace = %q, want %q", token, state.AccessToken)
	}
	if client.refreshSchedule.disposition != refreshLoopBlockedPermanent {
		t.Fatalf(
			"disposition = %d, want permanent block",
			client.refreshSchedule.disposition,
		)
	}
	if requests := endpoint.requests.Load(); requests != 1 {
		t.Fatalf("token endpoint requests = %d, want 1", requests)
	}

	if token := client.AccessToken(context.Background()); token != state.AccessToken {
		t.Fatalf("second AccessToken in grace = %q, want %q", token, state.AccessToken)
	}
	if requests := endpoint.requests.Load(); requests != 1 {
		t.Fatalf("repeated token endpoint requests = %d, want 1", requests)
	}
}

func TestRefreshLoopGrantAdmissionRejectsExpiryAndIntegrityBlock(t *testing.T) {
	authenticatedAt := time.Now().UTC().Truncate(time.Second)

	t.Run("expiry", func(t *testing.T) {
		clock := newManualRefreshClock(authenticatedAt)
		client, state, endpoint := newRefreshConcurrencyClient(t, nil, nil)
		state.LastAuthAt = authenticatedAt
		state.ExpiresAt = authenticatedAt.Add(100 * time.Second)
		client.mu.Lock()
		client.state = state
		client.clock = clock
		client.mu.Unlock()
		endpoint.unblock()

		action := client.nextRefreshLoopAction(
			authenticatedAt.Add(50 * time.Second),
		)
		clock.set(state.ExpiresAt)
		result := client.doRefresh(context.Background(), action)
		if result != refreshLoopAttemptExpiredBeforeStart {
			t.Fatalf("attempt result = %d, want expired-before-start", result)
		}
		client.finishRefreshLoopAttempt(action, result, state.ExpiresAt)
		if client.refreshSchedule.disposition != refreshLoopBlockedExpired {
			t.Fatalf(
				"disposition = %d, want expired block",
				client.refreshSchedule.disposition,
			)
		}
		if requests := endpoint.requests.Load(); requests != 0 {
			t.Fatalf("token endpoint requests = %d, want 0", requests)
		}
	})

	t.Run("integrity", func(t *testing.T) {
		clock := newManualRefreshClock(authenticatedAt)
		client, state, endpoint := newRefreshConcurrencyClient(t, nil, nil)
		state.LastAuthAt = authenticatedAt
		state.ExpiresAt = authenticatedAt.Add(100 * time.Second)
		client.mu.Lock()
		client.state = state
		client.clock = clock
		client.mu.Unlock()
		endpoint.unblock()

		due := authenticatedAt.Add(50 * time.Second)
		action := client.nextRefreshLoopAction(due)
		client.blockRefreshIntegrity(action.revision, due)
		result := client.doRefresh(context.Background(), action)
		if result != refreshLoopAttemptIntegrity {
			t.Fatalf("attempt result = %d, want integrity block", result)
		}
		client.finishRefreshLoopAttempt(action, result, due)
		if requests := endpoint.requests.Load(); requests != 0 {
			t.Fatalf("token endpoint requests = %d, want 0", requests)
		}

		_, started, err := client.refreshForRevision(
			context.Background(),
			&state,
			action.revision,
		)
		if !isSessionIntegrityError(err) {
			t.Fatalf("manual refresh error = %v, want integrity failure", err)
		}
		if started {
			t.Fatal("integrity-blocked manual refresh started or joined a grant")
		}
	})
}

func TestRefreshLoopGrantAdmissionRejectsLostClaim(t *testing.T) {
	authenticatedAt := time.Now().UTC().Truncate(time.Second)
	clock := newManualRefreshClock(authenticatedAt)
	client, state, endpoint := newRefreshConcurrencyClient(t, nil, nil)
	state.LastAuthAt = authenticatedAt
	state.ExpiresAt = authenticatedAt.Add(100 * time.Second)
	client.mu.Lock()
	client.state = state
	client.clock = clock
	client.mu.Unlock()
	endpoint.unblock()

	due := authenticatedAt.Add(50 * time.Second)
	action := client.nextRefreshLoopAction(due)
	client.mu.Lock()
	client.refreshSchedule.claimID++
	client.signalRefreshLoopLocked()
	client.mu.Unlock()

	if result := client.doRefresh(context.Background(), action); result != refreshLoopAttemptSucceeded {
		t.Fatalf("superseded attempt result = %d, want no-error supersession", result)
	}
	if requests := endpoint.requests.Load(); requests != 0 {
		t.Fatalf("token endpoint requests = %d, want 0", requests)
	}
}

func TestRefreshLoopProductionSuccessCommitsNewGeneration(t *testing.T) {
	authenticatedAt := time.Now().UTC().Truncate(time.Second)
	clock := newManualRefreshClock(authenticatedAt)
	emitter := newRefreshLoopEventRecorder()
	client, state, endpoint := newRefreshConcurrencyClient(t, nil, emitter)
	state.LastAuthAt = authenticatedAt
	state.ExpiresAt = authenticatedAt.Add(100 * time.Second)
	client.mu.Lock()
	client.state = state
	client.clock = clock
	beforeRevision := client.stateRevision
	client.mu.Unlock()
	endpoint.unblock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.refreshLoop(ctx)
	}()
	defer stopRefreshLoopTest(t, cancel, done)

	first := clock.nextTimer(t)
	clock.fire(t, first)
	select {
	case <-endpoint.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("production refresh did not reach the token endpoint")
	}
	select {
	case event := <-emitter.events:
		if event != EventTokenRefreshed {
			t.Fatalf("event = %q, want %q", event, EventTokenRefreshed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("successful production refresh did not emit token-refreshed")
	}

	client.mu.Lock()
	gotState := client.state
	gotRevision := client.stateRevision
	client.mu.Unlock()
	if gotState.AccessToken != "access-1" || gotState.RefreshToken != "refresh-1" {
		t.Fatalf("refreshed state = %+v, want first endpoint token pair", gotState)
	}
	if gotRevision != beforeRevision+1 {
		t.Fatalf("state revision = %d, want %d", gotRevision, beforeRevision+1)
	}
}
