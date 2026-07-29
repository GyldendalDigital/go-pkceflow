package pkceflow

import (
	"context"
	"time"
)

const minRefreshInterval = 10 * time.Second

// StartRefreshLoop starts a background goroutine that refreshes the access token
// before it expires, using DHCP-style adaptive timing.
//
// The loop attempts an immediate refresh on start (to ensure freshness after
// RestoreSession), then sleeps for max(timeUntilExpiry/2, 10s) between attempts.
//
// On permanent error (e.g., refresh token revoked), the loop stops and emits
// EventSessionExpired (unless grace period is still active).
//
// Calling StartRefreshLoop again stops the previous loop.
// Use StopRefreshLoop for explicit shutdown.
func (c *Client) StartRefreshLoop(ctx context.Context) {
	c.StopRefreshLoop() // stop any existing loop

	loopCtx, cancel := context.WithCancel(ctx)

	c.mu.Lock()
	c.refreshCancel = cancel
	c.mu.Unlock()

	go c.refreshLoop(loopCtx)
}

// StopRefreshLoop stops the background refresh loop if one is running.
func (c *Client) StopRefreshLoop() {
	c.mu.Lock()
	cancel := c.refreshCancel
	c.refreshCancel = nil
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
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
		c.emitter.Emit(EventSessionExpired, nil)
		return false
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
		c.emitter.Emit(EventSessionExpired, nil)
		return false
	}

	// Temporary error -- keep retrying (interval will shorten via nextRefreshInterval)
	return true
}

// nextRefreshInterval calculates the DHCP-style sleep duration.
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
