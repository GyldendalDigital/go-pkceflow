package pkceflow

import (
	"context"
	"errors"
	"time"
)

const minRefreshInterval = 10 * time.Second

type refreshTimer interface {
	channel() <-chan time.Time
	stop() bool
}

type refreshClock interface {
	Now() time.Time
	NewTimer(time.Duration) refreshTimer
}

type systemRefreshClock struct{}

func (systemRefreshClock) Now() time.Time {
	return time.Now()
}

func (systemRefreshClock) NewTimer(delay time.Duration) refreshTimer {
	return &systemRefreshTimer{timer: time.NewTimer(delay)}
}

type systemRefreshTimer struct {
	timer *time.Timer
}

func (t *systemRefreshTimer) channel() <-chan time.Time {
	return t.timer.C
}

func (t *systemRefreshTimer) stop() bool {
	return t.timer.Stop()
}

type refreshLoopDisposition uint8

const (
	refreshLoopActive refreshLoopDisposition = iota
	refreshLoopBlockedExpired
	refreshLoopBlockedPermanent
	refreshLoopBlockedIntegrity
)

// refreshLoopSchedule survives loop replacement and is keyed to one semantic
// token-state revision. Client.mu protects every field.
type refreshLoopSchedule struct {
	valid          bool
	revision       uint64
	nextStage      uint
	retryNotBefore time.Time
	claimID        uint64
	disposition    refreshLoopDisposition
	eventAt        time.Time
	eventEmitted   bool

	// inconclusive records that an attempt for this generation was abandoned
	// after the request went out, so the provider's answer is unknown. A later
	// credential refusal for the same generation is then ambiguous and must not
	// be treated as an authoritative revocation.
	inconclusive bool
}

type refreshLoopHandle struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// StartRefreshLoop starts background token refresh and persistence recovery.
//
// For each token generation, the first attempt occurs when 50% of its original
// lifetime remains. Temporary failures retry at 25%, 12.5%, and later halving
// thresholds, with at least 10 seconds between failed attempts. The loop never
// starts a refresh at or after the access-token expiry.
//
// Expiry parks that token generation without clearing state, forcing Login, or
// emitting EventSessionExpired. A refused client registration also parks the
// generation and emits that event once grace is unavailable or exhausted. A
// session-integrity error parks and emits immediately despite grace. A provider
// refusing the refresh token itself instead replaces the generation with a
// refused session, which withdraws grace immediately and parks quietly because
// it holds no refresh token. New Login, RestoreSession, or successful on-demand
// refresh state wakes the supervisor.
//
// If saving a successful Login or refresh reports an error, the committed state
// remains authoritative in memory. While this loop is active, persistence is
// retried independently after 1s, 2s, 4s, and later exponential delays capped
// at one minute. Recovery does not repeat the token grant or auth event.
//
// Calling StartRefreshLoop again stops the previous runner without resetting
// the current token generation's retry stage, terminal disposition, or pending
// persistence recovery.
// Use StopRefreshLoop for explicit shutdown.
func (c *Client) StartRefreshLoop(ctx context.Context) {
	c.startRefreshLoop(ctx, c.refreshLoop)
}

func (c *Client) startRefreshLoop(
	ctx context.Context,
	run func(context.Context),
) *refreshLoopHandle {
	loopCtx, cancel := context.WithCancel(ctx)
	handle := &refreshLoopHandle{
		ctx:    loopCtx,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	c.mu.Lock()
	previous := c.refreshRun
	c.refreshRun = handle
	if previous != nil {
		previous.cancel()
	}
	c.mu.Unlock()

	go func() {
		defer func() {
			c.mu.Lock()
			if c.refreshRun == handle {
				c.refreshRun = nil
			}
			c.mu.Unlock()
			close(handle.done)
		}()

		if loopCtx.Err() != nil {
			return
		}
		run(loopCtx)
	}()

	return handle
}

// StopRefreshLoop cancels the background refresh and persistence supervisors if
// they are running. It does not forget pending persistence recovery and does not
// wait for a supervisor or an already-running TokenPersistence call to finish.
func (c *Client) StopRefreshLoop() {
	c.mu.Lock()
	handle := c.refreshRun
	if handle != nil {
		handle.cancel()
	}
	c.mu.Unlock()
}

type refreshLoopActionKind uint8

const (
	refreshLoopWait refreshLoopActionKind = iota
	refreshLoopAttempt
	refreshLoopEmitSessionExpired
)

type refreshLoopAction struct {
	kind     refreshLoopActionKind
	revision uint64
	state    *TokenState
	stage    uint
	claimID  uint64
	due      time.Time
	wake     <-chan struct{}
}

type refreshLoopAttemptResult uint8

const (
	refreshLoopAttemptSucceeded refreshLoopAttemptResult = iota
	refreshLoopAttemptTemporary
	refreshLoopAttemptPermanent
	refreshLoopAttemptIntegrity
	refreshLoopAttemptCanceledBeforeStart
	refreshLoopAttemptCanceledAfterStart
	refreshLoopAttemptExpiredBeforeStart
)

type refreshLoopAttemptFunc func(
	context.Context,
	refreshLoopAction,
) refreshLoopAttemptResult

func (c *Client) refreshLoop(ctx context.Context) {
	persistenceDone := make(chan struct{})
	go func() {
		defer close(persistenceDone)
		c.runPersistenceRetryLoop(ctx)
	}()
	c.runRefreshLoop(ctx, c.doRefresh)
	<-persistenceDone
}

func (c *Client) runRefreshLoop(
	ctx context.Context,
	attempt refreshLoopAttemptFunc,
) {
	for {
		if ctx.Err() != nil {
			return
		}

		action := c.nextRefreshLoopAction(c.now())
		switch action.kind {
		case refreshLoopWait:
			if !c.waitForRefreshLoop(ctx, action.wake, action.due) {
				return
			}
		case refreshLoopAttempt:
			result := attempt(ctx, action)
			c.finishRefreshLoopAttempt(action, result, c.now())
			if ctx.Err() != nil {
				return
			}
		case refreshLoopEmitSessionExpired:
			c.emitEventIfRevision(action.revision, EventSessionExpired, nil)
		}
	}
}

func (c *Client) nextRefreshLoopAction(now time.Time) refreshLoopAction {
	c.mu.Lock()
	defer c.mu.Unlock()

	wake := c.refreshWakeLocked()
	state := c.state
	revision := c.stateRevision

	if !c.refreshSchedule.valid || c.refreshSchedule.revision != revision {
		c.refreshSchedule = refreshLoopSchedule{
			valid:       true,
			revision:    revision,
			nextStage:   1,
			disposition: refreshLoopActive,
		}
	}
	schedule := &c.refreshSchedule

	if schedule.claimID != 0 {
		return refreshLoopAction{kind: refreshLoopWait, wake: wake}
	}

	switch schedule.disposition {
	case refreshLoopBlockedExpired:
		return refreshLoopAction{kind: refreshLoopWait, wake: wake}
	case refreshLoopBlockedPermanent, refreshLoopBlockedIntegrity:
		if schedule.eventEmitted {
			return refreshLoopAction{kind: refreshLoopWait, wake: wake}
		}
		if now.Before(schedule.eventAt) {
			return refreshLoopAction{
				kind: refreshLoopWait,
				due:  schedule.eventAt,
				wake: wake,
			}
		}
		schedule.eventEmitted = true
		c.signalRefreshLoopLocked()
		return refreshLoopAction{
			kind:     refreshLoopEmitSessionExpired,
			revision: revision,
		}
	}

	ready := c.oauth2 != nil && c.verifier != nil
	if state.IsZero() || state.RefreshToken == "" || !ready {
		return refreshLoopAction{kind: refreshLoopWait, wake: wake}
	}
	if state.ExpiresAt.IsZero() {
		return refreshLoopAction{kind: refreshLoopWait, wake: wake}
	}
	if !now.Before(state.ExpiresAt) {
		schedule.disposition = refreshLoopBlockedExpired
		c.signalRefreshLoopLocked()
		return refreshLoopAction{
			kind: refreshLoopWait,
			wake: c.refreshWakeLocked(),
		}
	}
	if state.LastAuthAt.IsZero() || !state.LastAuthAt.Before(state.ExpiresAt) {
		return refreshLoopAction{kind: refreshLoopWait, wake: wake}
	}

	due, ok := refreshStageTime(&state, schedule.nextStage)
	if schedule.retryNotBefore.After(due) {
		due = schedule.retryNotBefore
	}
	if !ok || !due.Before(state.ExpiresAt) {
		schedule.disposition = refreshLoopBlockedExpired
		c.signalRefreshLoopLocked()
		return refreshLoopAction{
			kind: refreshLoopWait,
			wake: c.refreshWakeLocked(),
		}
	}
	if now.Before(due) {
		return refreshLoopAction{
			kind: refreshLoopWait,
			due:  due,
			wake: wake,
		}
	}

	c.refreshClaimSeq++
	if c.refreshClaimSeq == 0 {
		c.refreshClaimSeq++
	}
	schedule.claimID = c.refreshClaimSeq
	action := refreshLoopAction{
		kind:     refreshLoopAttempt,
		revision: revision,
		state:    &state,
		stage:    schedule.nextStage,
		claimID:  schedule.claimID,
	}
	c.signalRefreshLoopLocked()
	return action
}

// refreshStageTime returns the absolute threshold for a one-based retry stage.
// Stage 1 leaves half the original lifetime; stage 2 leaves one quarter.
func refreshStageTime(state *TokenState, stage uint) (time.Time, bool) {
	if stage == 0 || state.ExpiresAt.IsZero() || state.LastAuthAt.IsZero() {
		return time.Time{}, false
	}
	lifetime := state.ExpiresAt.Sub(state.LastAuthAt)
	if lifetime <= 0 {
		return time.Time{}, false
	}

	remaining := lifetime
	for range stage {
		remaining /= 2
		if remaining <= 0 {
			return time.Time{}, false
		}
	}
	due := state.ExpiresAt.Add(-remaining)
	return due, due.Before(state.ExpiresAt)
}

func (c *Client) waitForRefreshLoop(
	ctx context.Context,
	wake <-chan struct{},
	due time.Time,
) bool {
	if due.IsZero() {
		select {
		case <-ctx.Done():
			return false
		case <-wake:
			return true
		}
	}

	delay := due.Sub(c.now())
	if delay <= 0 {
		return true
	}
	timer := c.newRefreshTimer(delay)
	defer stopRefreshTimer(timer)

	select {
	case <-ctx.Done():
		return false
	case <-wake:
		return true
	case <-timer.channel():
		return true
	}
}

func (c *Client) newRefreshTimer(delay time.Duration) refreshTimer {
	if c.clock == nil {
		return systemRefreshClock{}.NewTimer(delay)
	}
	return c.clock.NewTimer(delay)
}

func stopRefreshTimer(timer refreshTimer) {
	if timer.stop() {
		return
	}
	select {
	case <-timer.channel():
	default:
	}
}

func (c *Client) doRefresh(
	ctx context.Context,
	action refreshLoopAction,
) refreshLoopAttemptResult {
	_, started, err := c.refreshForSchedule(
		ctx,
		action.state,
		action.revision,
		action.claimID,
	)
	if err == nil {
		return refreshLoopAttemptSucceeded
	}

	if errors.Is(err, errScheduledRefreshExpired) {
		return refreshLoopAttemptExpiredBeforeStart
	}
	if isSessionIntegrityError(err) {
		c.logger.Warn("refresh loop: session integrity failure", "error", err)
		return refreshLoopAttemptIntegrity
	}
	if IsPermanentError(err) {
		c.logger.Warn("refresh loop: permanent refresh failure", "error", err)
		return refreshLoopAttemptPermanent
	}
	if ctx.Err() != nil {
		if started {
			return refreshLoopAttemptCanceledAfterStart
		}
		return refreshLoopAttemptCanceledBeforeStart
	}

	c.logger.Debug("refresh loop: temporary refresh failure", "error", err)
	return refreshLoopAttemptTemporary
}

func (c *Client) finishRefreshLoopAttempt(
	action refreshLoopAction,
	result refreshLoopAttemptResult,
	completedAt time.Time,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	schedule := &c.refreshSchedule
	if !schedule.valid ||
		schedule.revision != action.revision ||
		c.stateRevision != action.revision ||
		schedule.claimID != action.claimID {
		return
	}
	schedule.claimID = 0

	switch result {
	case refreshLoopAttemptTemporary, refreshLoopAttemptCanceledAfterStart:
		c.advanceRefreshStageLocked(schedule, action.stage, completedAt)
	case refreshLoopAttemptPermanent:
		schedule.disposition = refreshLoopBlockedPermanent
		schedule.eventAt = c.sessionExpiredEventTime(action.state, completedAt)
	case refreshLoopAttemptIntegrity:
		schedule.disposition = refreshLoopBlockedIntegrity
		schedule.eventAt = completedAt
	case refreshLoopAttemptCanceledBeforeStart:
		// A later Start resumes the same threshold.
	case refreshLoopAttemptExpiredBeforeStart:
		schedule.disposition = refreshLoopBlockedExpired
	case refreshLoopAttemptSucceeded:
		// A successful refresh normally advanced stateRevision already. This
		// fallback prevents a provider/test double that failed to commit a new
		// generation from spinning at the same overdue threshold.
		c.advanceRefreshStageLocked(schedule, action.stage, completedAt)
	}
	c.signalRefreshLoopLocked()
}

func (c *Client) advanceRefreshStageLocked(
	schedule *refreshLoopSchedule,
	completedStage uint,
	completedAt time.Time,
) {
	nextStage := completedStage + 1
	if nextStage <= completedStage {
		schedule.disposition = refreshLoopBlockedExpired
		return
	}
	schedule.nextStage = nextStage
	schedule.retryNotBefore = completedAt.Add(minRefreshInterval)
}

func (c *Client) sessionExpiredEventTime(
	state *TokenState,
	now time.Time,
) time.Time {
	if c.config.GracePeriod > 0 && !state.LastAuthAt.IsZero() {
		graceEnd := state.LastAuthAt.Add(c.config.GracePeriod)
		if now.Before(graceEnd) {
			return graceEnd
		}
	}
	return now
}

// markRefreshInconclusiveLocked records that this generation had an attempt
// whose outcome is unknown. c.mu must be held.
func (c *Client) markRefreshInconclusiveLocked(revision uint64) {
	if c.stateRevision != revision {
		return
	}
	c.refreshScheduleLocked(revision).inconclusive = true
}

// refreshInconclusiveLocked reports whether this generation has an attempt whose
// outcome was never learned. c.mu must be held.
func (c *Client) refreshInconclusiveLocked(revision uint64) bool {
	return c.refreshSchedule.valid &&
		c.refreshSchedule.revision == revision &&
		c.refreshSchedule.inconclusive
}

// blockRefreshIntegrity makes a manual refresh integrity failure fail closed
// for the same token generation. An active supervisor observes the broadcast
// and remains the sole owner of EventSessionExpired delivery.
func (c *Client) blockRefreshIntegrity(revision uint64, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockRefreshIntegrityLocked(revision, now)
}

func (c *Client) blockRefreshIntegrityLocked(revision uint64, now time.Time) {
	if c.stateRevision != revision {
		return
	}
	schedule := c.refreshScheduleLocked(revision)
	if schedule.disposition != refreshLoopBlockedIntegrity ||
		schedule.eventAt.IsZero() ||
		now.Before(schedule.eventAt) {
		schedule.eventAt = now
	}
	schedule.disposition = refreshLoopBlockedIntegrity
	c.signalRefreshLoopLocked()
}

// blockRefreshPermanent records a permanent error discovered by an on-demand
// refresh so Start/Resume cannot retry the same known-invalid generation.
func (c *Client) blockRefreshPermanent(
	revision uint64,
	state *TokenState,
	now time.Time,
) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockRefreshPermanentLocked(revision, state, now)
}

func (c *Client) blockRefreshPermanentLocked(
	revision uint64,
	state *TokenState,
	now time.Time,
) {
	if c.stateRevision != revision {
		return
	}
	schedule := c.refreshScheduleLocked(revision)
	if schedule.disposition == refreshLoopBlockedIntegrity {
		return
	}
	eventAt := c.sessionExpiredEventTime(state, now)
	if schedule.disposition != refreshLoopBlockedPermanent ||
		schedule.eventAt.IsZero() ||
		eventAt.Before(schedule.eventAt) {
		schedule.eventAt = eventAt
	}
	schedule.disposition = refreshLoopBlockedPermanent
	c.signalRefreshLoopLocked()
}

func (c *Client) refreshScheduleLocked(revision uint64) *refreshLoopSchedule {
	if !c.refreshSchedule.valid || c.refreshSchedule.revision != revision {
		c.refreshSchedule = refreshLoopSchedule{
			valid:       true,
			revision:    revision,
			nextStage:   1,
			disposition: refreshLoopActive,
		}
	}
	return &c.refreshSchedule
}
