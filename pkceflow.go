package pkceflow

import (
	"context"
	"time"
)

const minRefreshInterval = 10 * time.Second

type refreshLoopHandle struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// StartRefreshLoop starts a background goroutine that refreshes the access token.
//
// The loop attempts an immediate refresh on start (to ensure freshness after
// RestoreSession), then sleeps for max(timeUntilExpiry/2, 10s) between attempts.
//
// A session-integrity error stops the loop and emits EventSessionExpired
// immediately. Other permanent errors stop and emit that event after any
// configured grace period expires. Temporary errors continue retrying.
//
// Calling StartRefreshLoop again stops the previous loop.
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

// StopRefreshLoop cancels the background refresh loop if one is running. It
// does not wait for the loop goroutine to finish.
func (c *Client) StopRefreshLoop() {
	c.mu.Lock()
	handle := c.refreshRun
	if handle != nil {
		handle.cancel()
	}
	c.mu.Unlock()
}

func (c *Client) refreshLoop(ctx context.Context) {
	// Immediate refresh attempt on start
	c.doRefresh(ctx)

	for {
		interval := c.nextRefreshInterval()

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			if !c.doRefresh(ctx) {
				return // permanent error or session expired
			}
		}
	}
}

// doRefresh attempts a single refresh. Returns false if the loop should stop
// (permanent error and no grace period remaining).
func (c *Client) doRefresh(ctx context.Context) bool {
	c.mu.Lock()
	state := c.state
	revision := c.stateRevision
	isInit := c.initialized()
	c.mu.Unlock()

	if state.IsZero() || state.RefreshToken == "" || !isInit {
		return true // nothing to refresh, but don't stop the loop
	}

	_, err := c.refresh(ctx, &state)
	if err == nil {
		return true // success
	}

	if ctx.Err() != nil {
		return false // context cancelled, loop should stop
	}

	c.logger.Debug("refresh loop: refresh failed", "error", err)

	if isSessionIntegrityError(err) {
		return !c.emitEventIfRevision(revision, EventSessionExpired, nil)
	}

	if IsPermanentError(err) {
		// Check if grace period saves us
		if c.config.GracePeriod > 0 && !state.LastAuthAt.IsZero() {
			graceEnd := state.LastAuthAt.Add(c.config.GracePeriod)
			if c.now().Before(graceEnd) {
				return true // still in grace, keep trying
			}
		}
		// Grace expired or disabled -- session is done
		return !c.emitEventIfRevision(revision, EventSessionExpired, nil)
	}

	// Temporary error -- keep retrying (interval will shorten via nextRefreshInterval)
	return true
}

// nextRefreshInterval calculates the adaptive sleep duration.
// sleep = max(timeUntilExpiry / 2, minRefreshInterval)
func (c *Client) nextRefreshInterval() time.Duration {
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()

	if state.IsZero() || state.ExpiresAt.IsZero() {
		return minRefreshInterval
	}

	remaining := time.Until(state.ExpiresAt)
	interval := remaining / 2

	if interval < minRefreshInterval {
		return minRefreshInterval
	}
	return interval
}
