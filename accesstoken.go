package pkceflow

import "context"

// AccessToken returns the current access token if it is valid.
// If the token is expired, it attempts a refresh. If refresh fails
// and grace mode is active, returns the expired token.
// Returns "" if no usable token is available.
// Session-integrity failures, such as a refreshed ID token for a different
// subject, never return the expired token from grace mode.
//
// AccessToken never returns an error: a failed refresh is logged at debug level
// and surfaces as an empty string. A successful refresh emits
// EventTokenRefreshed, whether triggered here or by the background loop. Only
// the background refresh loop emits EventSessionExpired on a permanent failure.
// A persistence failure does not roll back a successful refresh; StartRefreshLoop
// retries that committed generation separately.
// Grace is evaluated after any attempted refresh has completed.
// A permanent failure discovered here still parks that token generation so a
// later Start or Resume does not retry a known-invalid refresh token.
// Consumers that need to distinguish "expired" from "never authenticated"
// should consult AuthStatus.
func (c *Client) AccessToken(ctx context.Context) string {
	c.mu.Lock()
	state := c.state
	revision := c.stateRevision
	integrityBlocked := c.refreshIntegrityBlockedLocked()
	permanentlyBlocked := c.refreshPermanentlyBlockedLocked()
	c.mu.Unlock()

	if state.IsZero() || integrityBlocked {
		return ""
	}

	now := c.now()

	// Token still valid (with buffer)
	if now.Before(state.ExpiresAt.Add(-tokenExpiryBuffer)) {
		return state.AccessToken
	}

	// Token expired; try refresh if we have a refresh token and are initialized
	if state.RefreshToken != "" && !permanentlyBlocked {
		c.mu.Lock()
		isInit := c.initialized()
		c.mu.Unlock()

		if isInit {
			newState, _, err := c.refreshForRevision(ctx, &state, revision)
			if err == nil {
				return newState.AccessToken
			}
			c.logger.Debug("token refresh failed in AccessToken", "error", err)
			if isSessionIntegrityError(err) {
				c.blockRefreshIntegrity(revision, c.now())
				return ""
			}
			if IsPermanentError(err) {
				c.blockRefreshPermanent(revision, &state, c.now())
			}
		}
	}

	// Refresh failed or not possible; check grace period
	graceNow := c.now()
	if c.config.GracePeriod > 0 && !state.LastAuthAt.IsZero() {
		graceEnd := state.LastAuthAt.Add(c.config.GracePeriod)
		if graceNow.Before(graceEnd) {
			return state.AccessToken
		}
	}

	return ""
}

// TokenFn returns a function that retrieves the current access token.
// This is intended for injecting into HTTP clients:
//
//	tokenFn := client.TokenFn(ctx)
//	req.Header.Set("Authorization", "Bearer "+tokenFn())
func (c *Client) TokenFn(ctx context.Context) func() string {
	return func() string {
		return c.AccessToken(ctx)
	}
}
