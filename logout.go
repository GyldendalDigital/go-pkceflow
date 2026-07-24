package pkceflow

import (
	"context"
	"fmt"
	"net/url"
)

// Logout clears the authentication state and optionally triggers RP-Initiated Logout.
// If the IdP supports end_session_endpoint and an ID token is available,
// the user is redirected to the IdP's logout page via the AuthFlowHandler.
// Local state is always cleared regardless of RP-Initiated Logout success.
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
		logoutURL, err := buildLogoutURL(endSessionEndpoint, idToken, c.flow.RedirectURI())
		if err != nil {
			c.logger.Warn("failed to build logout URL", "error", err)
		} else {
			if _, err := c.flow.StartAuthFlow(ctx, logoutURL); err != nil {
				c.logger.Warn("RP-Initiated Logout failed", "error", err)
			}
		}
	}

	c.emitter.Emit(EventLoggedOut, nil)
	return nil
}

// buildLogoutURL constructs the RP-Initiated Logout URL.
func buildLogoutURL(endpoint, idToken, postLogoutRedirectURI string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("pkceflow: invalid end_session_endpoint: %w", err)
	}

	q := u.Query()
	q.Set("id_token_hint", idToken)
	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}
