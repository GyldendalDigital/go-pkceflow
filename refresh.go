package pkceflow

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

// refresh performs a single token refresh using the refresh token.
// It implements double-check locking: if the state has changed since the
// snapshot was taken (another goroutine already refreshed), it returns
// the current state without making a network call.
func (c *Client) refresh(ctx context.Context, snapshot *TokenState) (TokenState, error) {
	c.mu.Lock()
	// Double-check: if state changed since snapshot, someone else refreshed
	if c.state.AccessToken != snapshot.AccessToken {
		current := c.state
		c.mu.Unlock()
		return current, nil
	}
	if c.oauth2 == nil {
		c.mu.Unlock()
		return TokenState{}, ErrNotInitialized
	}
	oauthCfg := *c.oauth2
	verifier := c.verifier
	if verifier == nil {
		c.mu.Unlock()
		return TokenState{}, ErrNotInitialized
	}
	c.mu.Unlock()

	// Route the refresh through the configured HTTP client, if any.
	ctx = c.httpContext(ctx)

	// Use oauth2.TokenSource to perform the refresh
	oldToken := &oauth2.Token{
		RefreshToken: snapshot.RefreshToken,
	}
	src := oauthCfg.TokenSource(ctx, oldToken)

	newToken, err := src.Token()
	if err != nil {
		return TokenState{}, fmt.Errorf("pkceflow: token refresh failed: %w", asAuthError(err))
	}

	// Preserve new refresh token; fall back to old if absent
	// (some IdPs rotate refresh tokens, others reuse the same one)
	refreshToken := newToken.RefreshToken
	if refreshToken == "" {
		refreshToken = snapshot.RefreshToken
	}

	// Extract ID token if present in extras
	idToken, _ := newToken.Extra("id_token").(string)
	if idToken == "" {
		idToken = snapshot.IDToken
	} else {
		verified, err := verifier.Verify(ctx, idToken)
		if err != nil {
			return TokenState{}, newSessionIntegrityError("refreshed ID token validation failed", err)
		}
		if verified.Subject == "" {
			return TokenState{}, newSessionIntegrityError("refreshed ID token subject is empty", nil)
		}
		if snapshot.IDToken == "" {
			return TokenState{}, newSessionIntegrityError("current ID token unavailable during refresh", nil)
		}
		claims, err := DecodeIDToken(snapshot.IDToken)
		if err != nil {
			return TokenState{}, newSessionIntegrityError("current ID token claims unavailable during refresh", err)
		}
		if claims.Subject == "" {
			return TokenState{}, newSessionIntegrityError("current ID token subject is empty during refresh", nil)
		}
		if verified.Subject != claims.Subject {
			return TokenState{}, newSessionIntegrityError("refreshed ID token subject changed", nil)
		}
	}

	now := c.now()
	newState := TokenState{
		AccessToken:  newToken.AccessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		ExpiresAt:    newToken.Expiry,
		LastAuthAt:   now,
	}

	c.mu.Lock()
	c.state = newState
	c.mu.Unlock()

	if err := c.store.Save(newState); err != nil {
		c.logger.Warn("failed to persist refreshed tokens", "error", err)
	}

	c.emitter.Emit(EventTokenRefreshed, nil)
	return newState, nil
}
