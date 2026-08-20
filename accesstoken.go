package pkceflow

import (
	"context"
	"time"
)

// AccessToken returns the current access token if it is valid.
// If the token is expired, it attempts a refresh. If refresh fails
// and grace mode is active, returns the expired token.
// Returns "" if no usable token is available.
//
// Grace does not survive an authoritative refusal. Session-integrity failures,
// such as a refreshed ID token for a different subject, never return the
// expired token. Neither does a provider refusing the refresh token itself
// (invalid_grant): that commits and persists a refused session, so the refusal
// also survives a restart, and EventSessionExpired is emitted at once. A refused
// *client registration* (invalid_client, unauthorized_client) keeps grace,
// because the user cannot resolve it and a fresh Login would fail too.
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
			if isSessionIntegrityError(err) {
				c.logger.Warn("token refresh failed a session integrity check")
				c.blockRefreshIntegrity(revision, c.now())
				return ""
			}
			if IsPermanentError(err) {
				c.logger.Warn("token refresh permanently failed", "error", err)
				c.blockRefreshPermanent(revision, &state, c.now())
			} else {
				c.logger.Debug("token refresh failed in AccessToken", "error", err)
			}
		}
	}

	// Refresh failed or was not possible. Decide grace against the current
	// generation rather than the snapshot taken above: a refused credential
	// commits a new generation from the refresh path, and a concurrent Login may
	// have installed a usable session while this call was in flight.
	return c.usableAccessToken(c.now())
}

// usableAccessToken returns the access token if it is still valid, or the
// expired one if grace covers it. It returns "" when no usable token exists.
func (c *Client) usableAccessToken(now time.Time) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state.IsZero() || c.refreshIntegrityBlockedLocked() {
		return ""
	}
	if now.Before(c.state.ExpiresAt.Add(-tokenExpiryBuffer)) {
		return c.state.AccessToken
	}
	if c.config.GracePeriod > 0 && !c.state.LastAuthAt.IsZero() {
		if now.Before(c.state.LastAuthAt.Add(c.config.GracePeriod)) {
			return c.state.AccessToken
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
