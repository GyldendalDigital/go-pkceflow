package pkceflow

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Logout clears the authentication state, revokes the refresh token, and
// optionally triggers RP-Initiated Logout.
//
// When discovery advertised a revocation_endpoint and a refresh token is held,
// Logout posts it there (RFC 7009) after the local commit and before the browser
// round trip. Revocation is best effort: it never changes Logout's result, and a
// failure is logged without token or response-body text. This matters most with
// offline_access, which the default scopes request: providers do not necessarily
// invalidate an offline grant at end_session, so without revocation a copy of the
// token store taken before logout could stay redeemable.
//
// If the IdP supports end_session_endpoint and an ID token is available,
// the user is redirected to the IdP's logout page via the AuthFlowHandler.
// In-memory state is always cleared and persistent deletion is attempted,
// regardless of RP-Initiated Logout success. Persistence deletion failures are
// logged and do not change the returned result. RestoreSession will not reload
// state into the same locally logged-out Client even if deletion failed; a new
// process cannot share that in-memory tombstone.
//
// Revocation carries its own short budget in addition to LogoutTimeout, so it
// cannot consume the allowance meant for the browser round trip. A Logout whose
// caller context is already cancelled still revokes; one superseded by a newer
// Login does not, because a session-bound refresh token could otherwise tear
// down the session that Login just established.
//
// Logout supersedes an older Login before clearing state. A concurrent Logout
// returns after the active Logout's local commit, without waiting for its
// provider round trip. A newer Login may cancel a pending best-effort RP browser
// round trip after local logout has committed; it cannot recall a provider page
// that was already opened.
func (c *Client) Logout(ctx context.Context) error {
	// Apply logout timeout. Revocation runs before the browser round trip and
	// carries its own budget, so add it here rather than letting it eat into
	// LogoutTimeout, which is documented as the RP-Initiated Logout budget. A
	// blackholed revocation endpoint would otherwise silently consume the whole
	// allowance and skip the provider-session logout.
	if c.config.LogoutTimeout > 0 {
		budget := c.config.LogoutTimeout
		c.mu.Lock()
		revoking := c.revocationEndpoint != "" && c.state.RefreshToken != ""
		c.mu.Unlock()
		if revoking {
			budget += revocationTimeout
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
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
	refreshToken := c.state.RefreshToken
	endSessionEndpoint := c.endSessionEndpoint
	revocationEndpoint := c.revocationEndpoint
	// Clear in-memory state immediately.
	c.setStateLocked(&TokenState{})
	c.persistenceRetry = persistenceRetryState{}
	c.restoreBlocked = true
	c.signalRefreshLoopLocked()
	c.mu.Unlock()
	persistErr := c.store.Delete()
	shouldDrain := c.enqueueEvent(EventLoggedOut, nil)
	c.stateCommitMu.Unlock()
	c.lifecycleMu.Unlock()

	if persistErr != nil {
		c.logger.Warn("failed to delete persisted tokens")
	}
	if shouldDrain {
		c.drainEvents()
	}

	// Revoke before the browser round trip: that round trip is user-interactive
	// and unbounded, so the reverse order would starve revocation.
	c.revokeRefreshToken(operation, revocationEndpoint, refreshToken)

	// RP-Initiated Logout if supported
	if endSessionEndpoint != "" && idToken != "" {
		c.doRPLogout(operation, endSessionEndpoint, idToken)
	}

	return nil
}

// revocationTimeout bounds the revocation request. It is deliberately short and
// independent of LogoutTimeout: the request runs before the RP-Initiated Logout
// browser round trip, so a blackholed revocation endpoint must not consume the
// whole logout budget and leave the provider session standing.
const revocationTimeout = 3 * time.Second

// revokeRefreshToken posts the refresh token to the provider's revocation
// endpoint (RFC 7009). Every failure is swallowed: local logout has already
// committed, and RFC 7009 makes revocation advisory enough that a provider must
// answer 200 even for a token it does not recognize.
func (c *Client) revokeRefreshToken(
	operation *lifecycleOperation,
	endpoint string,
	refreshToken string,
) {
	if endpoint == "" || refreshToken == "" {
		return
	}
	// Ownership, not liveness: a caller that cancelled its context still gets
	// its token revoked, but a Logout superseded by a newer Login must not
	// revoke, because on providers whose refresh tokens are session-bound that
	// could tear down the session the new Login just established.
	if !c.lifecycleOperationOwned(operation) {
		c.logger.Warn("skipping refresh token revocation: logout was superseded")
		return
	}
	if !c.revocationEndpointAllowed(endpoint) {
		return
	}

	// Detach from the operation context so a cancelled caller still revokes,
	// then apply this request's own budget.
	ctx, cancel := context.WithTimeout(
		context.WithoutCancel(operation.ctx),
		revocationTimeout,
	)
	defer cancel()

	form := url.Values{
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
		// Public native client: the client ID goes in the body and there is no
		// secret (RFC 6749 section 3.2.1).
		"client_id": {c.config.ClientID},
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		c.logger.Warn("failed to build the token revocation request")
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.revocationHTTPClient().Do(req)
	if err != nil {
		// The error carries the endpoint URL, which may hold a query string, so
		// log a fixed message rather than the error.
		c.logger.Warn("refresh token revocation request failed")
		return
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort revocation
	_, _ = io.Copy(io.Discard, resp.Body)

	// Redirects arrive as ordinary responses because they are not followed, so
	// anything outside 2xx means the token was not confirmed revoked.
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		c.logger.Warn("token revocation was not confirmed", "status", resp.StatusCode)
	}
}

// revocationHTTPClient returns the configured client with redirects disabled.
//
// Go replays a request body on 307 and 308, cross-origin included, and the
// revocation endpoint comes from the discovery document. Following a redirect
// could therefore hand the refresh token to another host. The caller's client is
// never mutated.
func (c *Client) revocationHTTPClient() *http.Client {
	base := c.httpClient
	if base == nil {
		base = http.DefaultClient
	}
	noRedirect := *base
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &noRedirect
}

// revocationEndpointAllowed rejects a discovery-supplied endpoint that is unfit
// to receive a refresh token. It does not require the same origin as the token
// endpoint: providers legitimately host revocation elsewhere, as Google does.
func (c *Client) revocationEndpointAllowed(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || !u.IsAbs() || u.Host == "" ||
		u.User != nil || u.Fragment != "" {
		c.logger.Warn("skipping token revocation: unusable revocation_endpoint")
		return false
	}
	// Plaintext is tolerated only when the issuer itself is plaintext, which in
	// practice means a local test provider.
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" && strings.HasPrefix(c.config.IssuerURL, "http://") {
		return true
	}
	c.logger.Warn("skipping token revocation: revocation_endpoint is not https")
	return false
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
