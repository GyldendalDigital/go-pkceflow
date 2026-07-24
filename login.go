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

	// Generate PKCE verifier
	pkceVerifier := oauth2.GenerateVerifier()

	// Generate random state for CSRF protection (32 bytes, base64url)
	state, err := randomState()
	if err != nil {
		return err
	}

	// Build authorization URL
	authOpts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(pkceVerifier),
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
	if err != nil {
		return fmt.Errorf("pkceflow: invalid callback URL: %w", err)
	}
	query := parsed.Query()

	// Check for error from IdP
	if errCode := query.Get("error"); errCode != "" {
		return &AuthError{
			Code:    errCode,
			Message: query.Get("error_description"),
		}
	}

	// Validate state (constant-time comparison for CSRF protection)
	returnedState := query.Get("state")
	if subtle.ConstantTimeCompare([]byte(state), []byte(returnedState)) != 1 {
		return ErrStateMismatch
	}

	// Exchange authorization code for tokens
	code := query.Get("code")
	if code == "" {
		return fmt.Errorf("pkceflow: callback missing authorization code")
	}

	exchangeOpts := []oauth2.AuthCodeOption{
		oauth2.VerifierOption(pkceVerifier),
	}
	for k, v := range c.config.ExtraTokenParams {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam(k, v))
	}

	token, err := oauthCfg.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return fmt.Errorf("pkceflow: token exchange failed: %w", err)
	}

	// Extract and validate ID token
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return fmt.Errorf("pkceflow: no id_token in token response")
	}

	if _, err := verifier.Verify(ctx, rawIDToken); err != nil {
		return fmt.Errorf("pkceflow: ID token validation failed: %w", err)
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

	c.mu.Lock()
	c.state = newState
	c.mu.Unlock()

	if err := c.store.Save(newState); err != nil {
		c.logger.Warn("failed to persist tokens after login", "error", err)
	}

	c.emitter.Emit(EventLoggedIn, nil)
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
