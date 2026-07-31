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

	// Route token exchange and ID-token (JWKS) verification through the
	// configured HTTP client, if any.
	ctx = c.httpContext(ctx)

	// Generate PKCE verifier
	pkceVerifier := oauth2.GenerateVerifier()

	// Generate random state for CSRF protection (32 bytes, base64url)
	state, err := randomState()
	if err != nil {
		return err
	}

	// Generate a random nonce for OIDC replay protection. It is sent on the
	// authorization request and validated against the ID token nonce claim.
	nonce, err := randomState()
	if err != nil {
		return err
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
	callbackURL, err := c.flow.StartAuthFlow(ctx, authURL)
	if err != nil {
		if ctx.Err() != nil {
			return ErrFlowCancelled
		}
		return fmt.Errorf("pkceflow: auth flow failed: %w", err)
	}

	// Parse callback URL
	parsed, err := url.Parse(callbackURL)
	if err != nil || !parsed.IsAbs() {
		return fmt.Errorf("pkceflow: invalid callback URL")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return fmt.Errorf("pkceflow: invalid callback URL query")
	}

	// Validate state before processing either success or error responses. OAuth
	// authorization errors carry state too; accepting an error first would let
	// an unrelated callback bypass CSRF correlation.
	returnedStates := query["state"]
	if len(returnedStates) != 1 || returnedStates[0] == "" {
		return ErrStateMismatch
	}
	returnedState := returnedStates[0]
	if subtle.ConstantTimeCompare([]byte(state), []byte(returnedState)) != 1 {
		return ErrStateMismatch
	}

	// Check for error from IdP only after the callback has been correlated.
	if errCode := query.Get("error"); errCode != "" {
		return &AuthError{
			Code:    errCode,
			Message: query.Get("error_description"),
		}
	}

	// Exchange authorization code for tokens
	codes := query["code"]
	if len(codes) != 1 || codes[0] == "" {
		return fmt.Errorf("pkceflow: callback missing authorization code")
	}
	code := codes[0]

	exchangeOpts := []oauth2.AuthCodeOption{
		oauth2.VerifierOption(pkceVerifier),
	}
	for k, v := range c.config.ExtraTokenParams {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam(k, v))
	}

	token, err := oauthCfg.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return fmt.Errorf("pkceflow: token exchange failed: %w", asAuthError(err))
	}

	// Extract and validate ID token
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return fmt.Errorf("pkceflow: no id_token in token response")
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return fmt.Errorf("pkceflow: ID token validation failed: %w", err)
	}

	// Validate the nonce claim (constant-time) to detect token replay or
	// injection. OIDC Core requires the nonce to be present and to match the
	// value that was sent on the authorization request.
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(idToken.Nonce)) != 1 {
		return fmt.Errorf("pkceflow: %w", ErrNonceMismatch)
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

	c.stateCommitMu.Lock()
	c.mu.Lock()
	c.advanceStateLocked(&newState)
	c.mu.Unlock()
	persistErr := c.store.Save(newState)
	shouldDrain := c.enqueueEvent(EventLoggedIn, nil)
	c.stateCommitMu.Unlock()

	if persistErr != nil {
		c.logger.Warn("failed to persist tokens after login", "error", persistErr)
	}
	if shouldDrain {
		c.drainEvents()
	}
	return nil
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
