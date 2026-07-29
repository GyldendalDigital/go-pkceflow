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
// Consumers that need to distinguish "expired" from "never authenticated"
// should consult AuthStatus.
func (c *Client) AccessToken(ctx context.Context) string {
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()

	if state.IsZero() {
		return ""
	}

	now := c.now()

	// Token still valid (with buffer)
	if now.Before(state.ExpiresAt.Add(-tokenExpiryBuffer)) {
		return state.AccessToken
	}

	// Token expired; try refresh if we have a refresh token and are initialized
	if state.RefreshToken != "" {
		c.mu.Lock()
		isInit := c.initialized()
		c.mu.Unlock()

		if isInit {
			newState, err := c.refresh(ctx, &state)
			if err == nil {
				return newState.AccessToken
			}
			c.logger.Debug("token refresh failed in AccessToken", "error", err)
			if isSessionIntegrityError(err) {
				return ""
			}
		}
	}

	// Refresh failed or not possible; check grace period
	if c.config.GracePeriod > 0 && !state.LastAuthAt.IsZero() {
		graceEnd := state.LastAuthAt.Add(c.config.GracePeriod)
		if now.Before(graceEnd) {
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
