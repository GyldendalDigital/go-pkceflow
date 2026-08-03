package pkceflow

import (
	"context"
	"time"
)

const (
	minPersistenceRetryInterval = time.Second
	maxPersistenceRetryInterval = time.Minute
)

// persistenceRetryState records a Save that has not yet returned success for
// the current semantic token generation. Client.mu protects every field.
type persistenceRetryState struct {
	valid    bool
	revision uint64
	failures uint
	retryAt  time.Time
	claimID  uint64
}

type persistenceRetryAction struct {
	claimed  bool
	revision uint64
	claimID  uint64
	due      time.Time
	wake     <-chan struct{}
}

func (c *Client) recordPersistenceSaveResult(
	revision uint64,
	err error,
	completedAt time.Time,
) {
	if err == nil {
		return
	}

	delay := persistenceRetryDelay(1)
	c.mu.Lock()
	if c.stateRevision == revision {
		c.persistenceRetry = persistenceRetryState{
			valid:    true,
			revision: revision,
			failures: 1,
			retryAt:  completedAt.Add(delay),
		}
		c.signalRefreshLoopLocked()
	}
	c.mu.Unlock()
}

func (c *Client) logPersistenceSaveFailure() {
	if c.logger == nil {
		return
	}
	c.logger.Warn(
		"token state persistence failed; retry pending",
		"retry_in",
		minPersistenceRetryInterval,
	)
}

func persistenceRetryDelay(failures uint) time.Duration {
	delay := minPersistenceRetryInterval
	for attempt := uint(1); attempt < failures; attempt++ {
		if delay >= maxPersistenceRetryInterval/2 {
			return maxPersistenceRetryInterval
		}
		delay *= 2
	}
	return delay
}

func (c *Client) runPersistenceRetryLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}

		action := c.nextPersistenceRetryAction(c.now())
		if !action.claimed {
			if !c.waitForRefreshLoop(ctx, action.wake, action.due) {
				return
			}
			continue
		}
		c.retryPersistence(ctx, action)
	}
}

func (c *Client) nextPersistenceRetryAction(now time.Time) persistenceRetryAction {
	c.mu.Lock()
	defer c.mu.Unlock()

	wake := c.refreshWakeLocked()
	pending := &c.persistenceRetry
	if !pending.valid {
		return persistenceRetryAction{wake: wake}
	}
	if pending.revision != c.stateRevision {
		c.persistenceRetry = persistenceRetryState{}
		return persistenceRetryAction{wake: wake}
	}
	if pending.claimID != 0 {
		return persistenceRetryAction{wake: wake}
	}
	if now.Before(pending.retryAt) {
		return persistenceRetryAction{
			due:  pending.retryAt,
			wake: wake,
		}
	}

	c.persistenceClaimSeq++
	if c.persistenceClaimSeq == 0 {
		c.persistenceClaimSeq++
	}
	pending.claimID = c.persistenceClaimSeq
	action := persistenceRetryAction{
		claimed:  true,
		revision: pending.revision,
		claimID:  pending.claimID,
	}
	c.signalRefreshLoopLocked()
	return action
}

func (c *Client) retryPersistence(
	ctx context.Context,
	action persistenceRetryAction,
) {
	c.stateCommitMu.Lock()
	c.mu.Lock()
	if !c.persistenceRetryMatchesLocked(action) {
		c.mu.Unlock()
		c.stateCommitMu.Unlock()
		return
	}
	if ctx.Err() != nil {
		c.persistenceRetry.claimID = 0
		c.signalRefreshLoopLocked()
		c.mu.Unlock()
		c.stateCommitMu.Unlock()
		return
	}
	state := c.state
	c.mu.Unlock()

	err := c.store.Save(state)
	completedAt := c.now()

	var (
		recovered bool
		retryIn   time.Duration
	)
	c.mu.Lock()
	if c.persistenceRetryMatchesLocked(action) {
		if err == nil {
			c.persistenceRetry = persistenceRetryState{}
			recovered = true
		} else {
			if c.persistenceRetry.failures < ^uint(0) {
				c.persistenceRetry.failures++
			}
			retryIn = persistenceRetryDelay(c.persistenceRetry.failures)
			c.persistenceRetry.retryAt = completedAt.Add(retryIn)
			c.persistenceRetry.claimID = 0
		}
		c.signalRefreshLoopLocked()
	}
	c.mu.Unlock()
	c.stateCommitMu.Unlock()

	if c.logger == nil {
		return
	}
	switch {
	case recovered:
		c.logger.Info("token state persistence recovered")
	case retryIn > 0:
		c.logger.Warn(
			"token state persistence retry failed",
			"retry_in",
			retryIn,
		)
	}
}

func (c *Client) persistenceRetryMatchesLocked(
	action persistenceRetryAction,
) bool {
	return c.persistenceRetry.valid &&
		c.persistenceRetry.revision == action.revision &&
		c.persistenceRetry.claimID == action.claimID &&
		c.stateRevision == action.revision
}
