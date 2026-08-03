package pkceflow

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"

	"golang.org/x/oauth2"
)

// Login starts the OIDC Authorization Code flow with PKCE.
// It opens the authorization URL via the configured AuthFlowHandler,
// waits for the callback, exchanges the code for tokens, validates
// the ID token, persists the result, and emits EventLoggedIn.
//
// On one Client, an admitted Login supersedes any older Login or pending RP
// logout. The older Login returns ErrFlowCancelled and cannot persist a late
// callback or token response. A context that is already cancelled at entry
// returns ErrFlowCancelled without superseding an active operation.
//
// Requires Init() to have been called first.
func (c *Client) Login(ctx context.Context) error {
	c.mu.Lock()
	if !c.initialized() {
		c.mu.Unlock()
		return ErrNotInitialized
	}
	oauthCfg := *c.oauth2
	verifier := c.verifier
	c.mu.Unlock()

	// Apply login timeout
	if c.config.LoginTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.LoginTimeout)
		defer cancel()
	}
	if ctx.Err() != nil {
		return ErrFlowCancelled
	}

	operation := c.beginLifecycleOperation(ctx, lifecycleLogin)
	if operation == nil {
		return ErrFlowCancelled
	}
	defer c.finishLifecycleOperation(operation)

	// Route token exchange and ID-token (JWKS) verification through the
	// configured HTTP client, if any.
	ctx = c.httpContext(operation.ctx)

	// Generate PKCE verifier
	pkceVerifier := oauth2.GenerateVerifier()

	// Generate random state for CSRF protection (32 bytes, base64url)
	state, err := randomState()
	if err != nil {
		return c.lifecycleOperationError(operation, err)
	}

	// Generate a random nonce for OIDC replay protection. It is sent on the
	// authorization request and validated against the ID token nonce claim.
	nonce, err := randomState()
	if err != nil {
		return c.lifecycleOperationError(operation, err)
	}

	// Build authorization URL
	authOpts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	}
	for k, v := range c.config.ExtraAuthParams {
		authOpts = append(authOpts, oauth2.SetAuthURLParam(k, v))
	}
	authURL := oauthCfg.AuthCodeURL(state, authOpts...)

	// Delegate to the flow handler (opens browser, waits for callback)
	callbackURL, err := c.runLifecycleFlow(operation, func(flowCtx context.Context) (string, error) {
		return c.flow.StartAuthFlow(flowCtx, authURL)
	})
	if err != nil {
		if err == ErrFlowCancelled {
			return ErrFlowCancelled
		}
		return c.lifecycleOperationError(
			operation,
			fmt.Errorf("pkceflow: auth flow failed: %w", err),
		)
	}

	// Parse callback URL
	parsed, err := url.Parse(callbackURL)
	if err != nil || !parsed.IsAbs() {
		return c.lifecycleOperationError(
			operation,
			fmt.Errorf("pkceflow: invalid callback URL"),
		)
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return c.lifecycleOperationError(
			operation,
			fmt.Errorf("pkceflow: invalid callback URL query"),
		)
	}

	// Validate state before processing either success or error responses. OAuth
	// authorization errors carry state too; accepting an error first would let
	// an unrelated callback bypass CSRF correlation.
	returnedStates := query["state"]
	if len(returnedStates) != 1 || returnedStates[0] == "" {
		return c.lifecycleOperationError(operation, ErrStateMismatch)
	}
	returnedState := returnedStates[0]
	if subtle.ConstantTimeCompare([]byte(state), []byte(returnedState)) != 1 {
		return c.lifecycleOperationError(operation, ErrStateMismatch)
	}

	// Check for error from IdP only after the callback has been correlated.
	if errCode := query.Get("error"); errCode != "" {
		return c.lifecycleOperationError(operation, &AuthError{
			Code:    errCode,
			Message: query.Get("error_description"),
		})
	}

	// Exchange authorization code for tokens
	codes := query["code"]
	if len(codes) != 1 || codes[0] == "" {
		return c.lifecycleOperationError(
			operation,
			fmt.Errorf("pkceflow: callback missing authorization code"),
		)
	}
	code := codes[0]
	if !c.lifecycleOperationCurrent(operation) {
		return ErrFlowCancelled
	}

	exchangeOpts := []oauth2.AuthCodeOption{
		oauth2.VerifierOption(pkceVerifier),
	}
	for k, v := range c.config.ExtraTokenParams {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam(k, v))
	}

	token, err := oauthCfg.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return c.lifecycleOperationError(
			operation,
			fmt.Errorf("pkceflow: token exchange failed: %w", asAuthError(err)),
		)
	}
	if !c.lifecycleOperationCurrent(operation) {
		return ErrFlowCancelled
	}

	// Extract and validate ID token
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return c.lifecycleOperationError(
			operation,
			fmt.Errorf("pkceflow: no id_token in token response"),
		)
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return c.lifecycleOperationError(
			operation,
			fmt.Errorf("pkceflow: ID token validation failed: %w", err),
		)
	}

	// Validate the nonce claim (constant-time) to detect token replay or
	// injection. OIDC Core requires the nonce to be present and to match the
	// value that was sent on the authorization request.
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(idToken.Nonce)) != 1 {
		return c.lifecycleOperationError(
			operation,
			fmt.Errorf("pkceflow: %w", ErrNonceMismatch),
		)
	}

	// Build and persist token state
	now := c.now()
	newState := TokenState{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      rawIDToken,
		ExpiresAt:    token.Expiry,
		LastAuthAt:   now,
	}

	committed, persistErr := c.commitLoginState(operation, &newState)
	if !committed {
		return ErrFlowCancelled
	}

	if persistErr != nil {
		c.logger.Warn("failed to persist tokens after login", "error", persistErr)
	}
	return nil
}

// commitLoginState linearizes Login against lifecycle replacement and every
// other token-state commit. Cancellation is checked again after waiting for the
// commit lock because persistence can keep that lock occupied for an arbitrary
// amount of time.
func (c *Client) commitLoginState(
	operation *lifecycleOperation,
	newState *TokenState,
) (bool, error) {
	c.lifecycleMu.Lock()
	if !c.lifecycleOperationCurrentLocked(operation) {
		c.lifecycleMu.Unlock()
		return false, nil
	}
	c.stateCommitMu.Lock()
	if !c.lifecycleOperationCurrentLocked(operation) {
		c.stateCommitMu.Unlock()
		c.lifecycleMu.Unlock()
		return false, nil
	}

	c.mu.Lock()
	c.advanceStateLocked(newState)
	c.mu.Unlock()
	persistErr := c.store.Save(*newState)
	shouldDrain := c.enqueueEvent(EventLoggedIn, nil)
	c.stateCommitMu.Unlock()
	c.lifecycleMu.Unlock()

	if shouldDrain {
		c.drainEvents()
	}
	return true, persistErr
}

// randomState generates a cryptographically random state value (32 bytes,
// base64url-encoded) used for CSRF protection and callback correlation in both
// the login and logout flows.
func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("pkceflow: failed to generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
