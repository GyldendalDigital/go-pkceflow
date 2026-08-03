package pkceflow

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/url"
)

// Logout clears the authentication state and optionally triggers RP-Initiated Logout.
// If the IdP supports end_session_endpoint and an ID token is available,
// the user is redirected to the IdP's logout page via the AuthFlowHandler.
// In-memory state is always cleared and persistent deletion is attempted,
// regardless of RP-Initiated Logout success. Persistence deletion failures are
// logged and do not change the returned result.
//
// Logout supersedes an older Login before clearing state. A concurrent Logout
// returns after the active Logout's local commit, without waiting for its
// provider round trip. A newer Login may cancel a pending best-effort RP browser
// round trip after local logout has committed; it cannot recall a provider page
// that was already opened.
func (c *Client) Logout(ctx context.Context) error {
	// Apply logout timeout
	if c.config.LogoutTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.LogoutTimeout)
		defer cancel()
	}

	c.lifecycleMu.Lock()
	if c.lifecycleOperation != nil && c.lifecycleOperation.kind == lifecycleLogout {
		c.lifecycleMu.Unlock()
		return nil
	}
	operation := c.beginLifecycleOperationLocked(ctx, lifecycleLogout)
	defer c.finishLifecycleOperation(operation)

	c.stateCommitMu.Lock()
	c.mu.Lock()
	idToken := c.state.IDToken
	endSessionEndpoint := c.endSessionEndpoint
	// Clear in-memory state immediately.
	c.setStateLocked(&TokenState{})
	c.mu.Unlock()
	persistErr := c.store.Delete()
	shouldDrain := c.enqueueEvent(EventLoggedOut, nil)
	c.stateCommitMu.Unlock()
	c.lifecycleMu.Unlock()

	if persistErr != nil {
		c.logger.Warn("failed to delete persisted tokens", "error", persistErr)
	}
	if shouldDrain {
		c.drainEvents()
	}

	// RP-Initiated Logout if supported
	if endSessionEndpoint != "" && idToken != "" {
		c.doRPLogout(operation, endSessionEndpoint, idToken)
	}

	return nil
}

// doRPLogout performs RP-Initiated Logout via the flow handler. Non-cancellation
// failures are logged as warnings and all failures are swallowed: local logout
// has already succeeded, so a failed browser round-trip must not surface as a
// logout error.
func (c *Client) doRPLogout(
	operation *lifecycleOperation,
	endSessionEndpoint string,
	idToken string,
) {
	if !c.lifecycleOperationCurrent(operation) {
		return
	}

	// Resolve the post-logout redirect URI and the flow used to capture the
	// callback. Handlers that support a distinct logout redirect implement
	// LogoutFlowHandler; otherwise fall back to the login redirect and flow.
	postLogoutURI := c.flow.RedirectURI()
	startFlow := c.flow.StartAuthFlow
	if lh, ok := c.flow.(LogoutFlowHandler); ok {
		if uri := lh.PostLogoutRedirectURI(); uri != "" {
			postLogoutURI = uri
		}
		startFlow = lh.StartLogoutFlow
	}

	// Generate state for CSRF protection and callback correlation.
	state, err := randomState()
	if err != nil {
		c.logger.Warn("failed to generate logout state", "error", err)
		return
	}

	logoutURL, err := buildLogoutURL(endSessionEndpoint, idToken, postLogoutURI, state)
	if err != nil {
		c.logger.Warn("failed to build logout URL", "error", err)
		return
	}

	callbackURL, err := c.runLifecycleFlow(operation, func(flowCtx context.Context) (string, error) {
		return startFlow(flowCtx, logoutURL)
	})
	if err != nil {
		if err != ErrFlowCancelled {
			// Handler errors are intentionally omitted: a handler may echo the
			// logout URL, which contains the ID token hint.
			c.logger.Warn("RP-Initiated Logout flow failed")
		}
		return
	}

	// Best-effort state validation. A mismatch is logged but does not fail
	// logout: local state is already cleared. Some IdPs do not redirect back
	// (they show a confirmation page), in which case callbackURL is empty.
	if callbackURL == "" {
		return
	}
	parsed, perr := url.Parse(callbackURL)
	if perr != nil || !parsed.IsAbs() {
		c.logger.Warn("failed to parse logout callback URL")
		return
	}
	query, qerr := url.ParseQuery(parsed.RawQuery)
	if qerr != nil {
		c.logger.Warn("failed to parse logout callback query")
		return
	}
	states, present := query["state"]
	if !present {
		return
	}
	if len(states) != 1 ||
		states[0] == "" ||
		subtle.ConstantTimeCompare([]byte(state), []byte(states[0])) != 1 {
		c.logger.Warn("logout callback state mismatch")
	}
}

// buildLogoutURL constructs the RP-Initiated Logout URL.
func buildLogoutURL(endpoint, idToken, postLogoutRedirectURI, state string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("pkceflow: invalid end_session_endpoint: %w", err)
	}

	q := u.Query()
	q.Set("id_token_hint", idToken)
	q.Set("state", state)
	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}
