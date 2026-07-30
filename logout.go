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
func (c *Client) Logout(ctx context.Context) error {
	// Apply logout timeout
	if c.config.LogoutTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.LogoutTimeout)
		defer cancel()
	}

	c.mu.Lock()
	idToken := c.state.IDToken
	endSessionEndpoint := c.endSessionEndpoint
	// Clear in-memory state immediately
	c.state = TokenState{}
	c.mu.Unlock()

	// Delete persisted tokens
	if err := c.store.Delete(); err != nil {
		c.logger.Warn("failed to delete persisted tokens", "error", err)
	}

	// RP-Initiated Logout if supported
	if endSessionEndpoint != "" && idToken != "" {
		c.doRPLogout(ctx, endSessionEndpoint, idToken)
	}

	c.emitter.Emit(EventLoggedOut, nil)
	return nil
}

// doRPLogout performs RP-Initiated Logout via the flow handler. All failures are
// logged as warnings and swallowed: local logout has already succeeded, so a
// failed browser round-trip must not surface as a logout error.
func (c *Client) doRPLogout(ctx context.Context, endSessionEndpoint, idToken string) {
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

	callbackURL, err := startFlow(ctx, logoutURL)
	if err != nil {
		c.logger.Warn("RP-Initiated Logout failed", "error", err)
		return
	}

	// Best-effort state validation. A mismatch is logged but does not fail
	// logout: local state is already cleared. Some IdPs do not redirect back
	// (they show a confirmation page), in which case callbackURL is empty.
	if callbackURL == "" {
		return
	}
	parsed, perr := url.Parse(callbackURL)
	if perr != nil {
		c.logger.Warn("failed to parse logout callback URL", "error", perr)
		return
	}
	returned := parsed.Query().Get("state")
	if returned != "" && subtle.ConstantTimeCompare([]byte(state), []byte(returned)) != 1 {
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
