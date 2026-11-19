package pkceflow

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// hasMonotonicReading reports whether tm carries a monotonic clock reading.
// Time.String documents a final "m=±<value>" field exactly when one is present.
func hasMonotonicReading(tm time.Time) bool {
	return strings.Contains(tm.String(), " m=")
}

// afterSimulatedSleep returns the instant time.Now would report after the
// machine stayed awake for awake and then slept for asleep, on a system whose
// monotonic clock stops during sleep: its wall clock reading has advanced by
// awake+asleep, its monotonic reading by awake only.
//
// The time package cannot build such a Time, so this moves the monotonic
// reading directly. It relies on Time's layout (wall uint64, ext int64, loc
// *Location), where ext holds the monotonic reading whenever one is present,
// and verifies the result, so a layout change fails the test loudly instead of
// letting it test nothing.
func afterSimulatedSleep(
	t *testing.T,
	start time.Time,
	awake time.Duration,
	asleep time.Duration,
) time.Time {
	t.Helper()
	type timeLayout struct {
		wall uint64
		ext  int64
		loc  *time.Location
	}
	if !hasMonotonicReading(start) {
		t.Fatal("start carries no monotonic reading")
	}
	if unsafe.Sizeof(start) != unsafe.Sizeof(timeLayout{}) {
		t.Fatal("time.Time layout changed; update afterSimulatedSleep")
	}

	woke := start.Add(awake + asleep)
	(*timeLayout)(unsafe.Pointer(&woke)).ext -= int64(asleep)

	if got := woke.Sub(start); got != awake {
		t.Fatalf("simulated monotonic elapsed = %s, want %s", got, awake)
	}
	if got := woke.Round(0).Sub(start.Round(0)); got != awake+asleep {
		t.Fatalf("simulated wall elapsed = %s, want %s", got, awake+asleep)
	}
	return woke
}

func TestInSessionDeadlinesUseWallClockAfterSleep(t *testing.T) {
	// In-session instants read from time.Now carry monotonic readings, as
	// LastAuthAt and oauth2's Expiry did before they were stripped on entry.
	authenticatedAt := time.Now()
	state := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		IDToken:      "id-token",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(time.Hour),
	}
	// Awake for ten minutes, then asleep for two hours: the wall clock is past
	// both the access-token expiry and the 90-minute grace end, while the
	// monotonic clock says only ten minutes have passed.
	woke := afterSimulatedSleep(t, authenticatedAt, 10*time.Minute, 2*time.Hour)
	if !woke.Before(state.ExpiresAt) {
		t.Fatal("precondition: a monotonic comparison must still see the token as valid")
	}

	client := newRefreshLoopTestClient(
		newManualRefreshClock(woke),
		&state,
		90*time.Minute,
		nil,
	)

	if status := client.AuthStatus(); status != (AuthStatusResult{}) {
		t.Fatalf("AuthStatus after sleep = %+v, want expired and past grace", status)
	}
	// Discovery never ran, so AccessToken judges the stored deadlines alone.
	if token := client.AccessToken(context.Background()); token != "" {
		t.Fatalf("AccessToken after sleep = %q, want none", token)
	}
	action := client.nextRefreshLoopAction(client.now())
	if action.kind != refreshLoopWait || !action.due.IsZero() {
		t.Fatalf("refresh loop action after sleep = %#v, want parked wait", action)
	}
	if client.refreshSchedule.disposition != refreshLoopBlockedExpired {
		t.Fatalf(
			"disposition after sleep = %d, want expired block",
			client.refreshSchedule.disposition,
		)
	}
}

func TestRefreshLoopRunsRefreshDueDuringSleepWithinCheckInterval(t *testing.T) {
	authenticatedAt := time.Date(2026, time.November, 19, 8, 0, 0, 0, time.UTC)
	clock := newManualRefreshClock(authenticatedAt)
	client := newRefreshLoopTestClient(clock, &TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(2 * time.Hour),
	}, 0, nil)
	script := newScriptedRefreshLoop()
	cancel, done := startRefreshLoopTest(client, script)
	defer stopRefreshLoopTest(t, cancel, done)

	// The first threshold is an hour away, so the wait is capped.
	first := clock.nextTimer(t)
	if want := authenticatedAt.Add(wallClockCheckInterval); !first.deadline.Equal(want) {
		t.Fatalf("first timer deadline = %s, want capped %s", first.deadline, want)
	}

	// A check that finds the threshold still ahead re-arms without attempting.
	clock.fire(t, first)
	second := clock.nextTimer(t)
	if want := authenticatedAt.Add(2 * wallClockCheckInterval); !second.deadline.Equal(want) {
		t.Fatalf("second timer deadline = %s, want capped %s", second.deadline, want)
	}
	select {
	case call := <-script.calls:
		t.Fatalf("attempt at stage %d before its threshold", call.stage)
	default:
	}

	// The machine sleeps past the threshold. Timers run on the monotonic
	// clock, so the pending timer has not advanced; after waking it fires
	// within one check interval, at a wall time past the threshold.
	clock.set(authenticatedAt.Add(90 * time.Minute))
	if !second.fire() {
		t.Fatal("pending timer was stopped before it could fire")
	}
	if call := script.nextCall(t); call.stage != 1 {
		t.Fatalf("attempt stage after sleep = %d, want 1", call.stage)
	}
}

func TestRefreshLoopEmitsGraceEndDueDuringSleepWithinCheckInterval(t *testing.T) {
	authenticatedAt := time.Date(2026, time.November, 19, 8, 0, 0, 0, time.UTC)
	gracePeriod := 30 * 24 * time.Hour
	clock := newManualRefreshClock(authenticatedAt)
	emitter := newRefreshLoopEventRecorder()
	client := newRefreshLoopTestClient(clock, &TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		LastAuthAt:   authenticatedAt,
		ExpiresAt:    authenticatedAt.Add(100 * time.Second),
	}, gracePeriod, emitter)
	script := newScriptedRefreshLoop()
	cancel, done := startRefreshLoopTest(client, script)
	defer stopRefreshLoopTest(t, cancel, done)

	first := clock.nextTimer(t)
	clock.fire(t, first)
	_ = script.nextCall(t)
	script.results <- refreshLoopAttemptPermanent

	// The refused client registration parks the generation until grace end,
	// thirty days away, so the wait is capped.
	graceWait := clock.nextTimer(t)
	if want := first.deadline.Add(wallClockCheckInterval); !graceWait.deadline.Equal(want) {
		t.Fatalf("grace-end timer deadline = %s, want capped %s", graceWait.deadline, want)
	}
	select {
	case event := <-emitter.events:
		t.Fatalf("event %q emitted before grace end", event)
	default:
	}

	// The machine sleeps past grace end; the pending timer has not advanced.
	clock.set(authenticatedAt.Add(gracePeriod + time.Hour))
	if !graceWait.fire() {
		t.Fatal("pending timer was stopped before it could fire")
	}
	select {
	case event := <-emitter.events:
		if event != EventSessionExpired {
			t.Fatalf("event = %q, want %q", event, EventSessionExpired)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session-expired was not emitted within one check interval of waking")
	}
	select {
	case event := <-emitter.events:
		t.Fatalf("duplicate terminal event %q", event)
	default:
	}
	select {
	case call := <-script.calls:
		t.Fatalf("permanently blocked generation retried at stage %d", call.stage)
	default:
	}
}

func TestRefreshStoresExpiryWithoutMonotonicReading(t *testing.T) {
	store := &memoryStore{}
	client, state, endpoint := newRefreshConcurrencyClient(t, store, nil)
	endpoint.unblock()

	if _, err := client.refresh(context.Background(), &state); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	client.mu.Lock()
	current := client.state
	client.mu.Unlock()
	saved, err := store.Load()
	if err != nil {
		t.Fatalf("load saved state: %v", err)
	}
	if current.ExpiresAt.IsZero() {
		t.Fatal("precondition: refreshed state has no expiry")
	}
	for _, instant := range []struct {
		name string
		at   time.Time
	}{
		{"in-memory ExpiresAt", current.ExpiresAt},
		{"in-memory LastAuthAt", current.LastAuthAt},
		{"saved ExpiresAt", saved.ExpiresAt},
		{"saved LastAuthAt", saved.LastAuthAt},
	} {
		if hasMonotonicReading(instant.at) {
			t.Errorf("%s carries a monotonic reading: %s", instant.name, instant.at)
		}
	}
}

func TestRestoreSessionStripsMonotonicReadings(t *testing.T) {
	now := time.Now()
	stored := TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		IDToken:      "id-token",
		ExpiresAt:    now.Add(time.Hour),
		LastAuthAt:   now,
	}
	client := &Client{
		store:   &memoryStore{state: stored},
		emitter: noopEmitter{},
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	restored, err := client.RestoreSession()
	if err != nil || !restored {
		t.Fatalf("RestoreSession = %v, %v; want true, nil", restored, err)
	}

	client.mu.Lock()
	current := client.state
	client.mu.Unlock()
	if hasMonotonicReading(current.ExpiresAt) || hasMonotonicReading(current.LastAuthAt) {
		t.Fatalf(
			"restored instants carry monotonic readings: ExpiresAt %s, LastAuthAt %s",
			current.ExpiresAt,
			current.LastAuthAt,
		)
	}
	if !current.ExpiresAt.Equal(stored.ExpiresAt) ||
		!current.LastAuthAt.Equal(stored.LastAuthAt) {
		t.Fatalf("restore changed the instants: got %+v, want %+v", current, stored)
	}
}
