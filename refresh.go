package pkceflow

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
)

var errScheduledRefreshExpired = errors.New(
	"pkceflow: scheduled refresh reached access-token expiry",
)

type refreshAttempt struct {
	revision     uint64
	snapshot     TokenState
	ctx          context.Context
	cancel       context.CancelFunc
	participants int
	done         chan struct{}
	complete     chan struct{}
	state        TokenState
	err          error
}

// refresh performs a single token refresh using the refresh token.
// Concurrent callers for one state revision share the same in-flight result.
// A later call may start a new attempt after a failed attempt has completed.
func (c *Client) refresh(ctx context.Context, snapshot *TokenState) (TokenState, error) {
	state, _, err := c.refreshAtRevision(ctx, snapshot, nil, 0)
	return state, err
}

// refreshForRevision prevents a timer that belonged to an older scheduler
// generation from starting a grant against newer state.
func (c *Client) refreshForRevision(
	ctx context.Context,
	snapshot *TokenState,
	revision uint64,
) (TokenState, bool, error) {
	return c.refreshAtRevision(ctx, snapshot, &revision, 0)
}

func (c *Client) refreshForSchedule(
	ctx context.Context,
	snapshot *TokenState,
	revision uint64,
	claimID uint64,
) (TokenState, bool, error) {
	return c.refreshAtRevision(ctx, snapshot, &revision, claimID)
}

func (c *Client) refreshAtRevision(
	ctx context.Context,
	snapshot *TokenState,
	expectedRevision *uint64,
	expectedClaimID uint64,
) (TokenState, bool, error) {
	attempt, leader, current, err := c.beginRefreshAttempt(
		ctx,
		snapshot,
		expectedRevision,
		expectedClaimID,
	)
	if err != nil || attempt == nil {
		return current, false, err
	}
	if leader {
		go c.runRefreshAttempt(attempt)
	}
	state, err := c.waitForRefreshAttempt(ctx, attempt)
	return state, true, err
}

func (c *Client) runRefreshAttempt(attempt *refreshAttempt) {
	state, shouldDrain, refreshErr := c.performRefresh(
		attempt.ctx,
		&attempt.snapshot,
		attempt.revision,
	)

	// Commit before finishRefreshAttempt so no waiter can start a fresh attempt
	// against the refused generation, and outside performRefresh so the refusal
	// error survives: committing there would advance the revision and make
	// refreshFailure report the refusal as a success.
	if c.commitCredentialRefusal(attempt, refreshErr) {
		shouldDrain = true
	}
	c.finishRefreshAttempt(attempt, &state, refreshErr)
	if shouldDrain {
		c.drainEvents()
	}
	close(attempt.complete)
}

// commitCredentialRefusal installs a refused generation when the provider
// authoritatively refused the refresh token. The refused generation keeps the ID
// token, so Claims still names the user a re-authentication prompt should
// address, and drops every credential and timestamp, which is what withdraws
// grace: AccessToken finds no refresh token and no grace anchor, AuthStatus
// reports the session unusable, and the refresh loop parks.
//
// Persisting it is the point: the in-memory permanent block is keyed to a state
// revision and does not survive a restart, so without a durable mark a revoked
// account regained a fresh grace window on every launch.
//
// It reports whether the caller must drain events.
func (c *Client) commitCredentialRefusal(
	attempt *refreshAttempt,
	refreshErr error,
) bool {
	if !isCredentialRefusedError(refreshErr) {
		return false
	}

	c.stateCommitMu.Lock()
	c.mu.Lock()
	if c.stateRevision != attempt.revision {
		// A newer generation already replaced the refused one.
		c.mu.Unlock()
		c.stateCommitMu.Unlock()
		return false
	}
	if c.refreshInconclusiveLocked(attempt.revision) {
		// An earlier attempt for this generation never learned the provider's
		// answer. On a rotating provider this refusal may mean that attempt
		// spent the token, not that the session was revoked, so keep grace and
		// let the ordinary permanent block park the generation.
		c.mu.Unlock()
		c.stateCommitMu.Unlock()
		// Logged after unlocking: a consumer-supplied handler must not be able
		// to block state commits.
		c.logger.Warn(
			"treating refresh refusal as inconclusive; an earlier attempt for " +
				"this token generation was abandoned in flight",
		)
		return false
	}
	c.mu.Unlock()

	// Persistence runs under stateCommitMu but never mu. A newer persisted
	// generation means another process rotated the token and this refusal
	// concerns a superseded one.
	persisted, loadErr := c.store.Load()
	if loadErr != nil {
		// A read failure is not evidence of rotation, while the refusal is
		// authoritative about the token that was presented. Fail closed. Logged
		// after the commit completes, below, rather than under stateCommitMu.
		defer c.logger.Warn("could not read persisted state while recording a refused refresh token")
	} else if supersededRefreshToken(&persisted, &attempt.snapshot) {
		c.stateCommitMu.Unlock()
		c.logger.Warn(
			"treating refresh refusal as superseded; persisted state holds a " +
				"newer refresh token",
		)
		return false
	}

	refused := TokenState{IDToken: attempt.snapshot.IDToken}

	c.mu.Lock()
	if c.stateRevision != attempt.revision {
		c.mu.Unlock()
		c.stateCommitMu.Unlock()
		return false
	}
	c.advanceStateLocked(&refused)
	committedRevision := c.stateRevision
	c.mu.Unlock()

	persistErr := c.store.Save(refused)
	c.recordPersistenceSaveResult(committedRevision, persistErr, c.now())
	shouldDrain := c.enqueueEvent(EventSessionExpired, nil)
	c.stateCommitMu.Unlock()

	if persistErr != nil {
		c.logPersistenceSaveFailure()
	}
	return shouldDrain
}

// supersededRefreshToken reports whether persisted state demonstrably holds a
// newer refresh token than the one that was refused.
//
// Requiring a later LastAuthAt, not merely a different token, keeps the check
// from firing when the store is *behind* memory after a failed Save: there the
// persisted token is older, and suppressing the refusal would let a genuine
// revocation keep its grace window.
func supersededRefreshToken(persisted, attempted *TokenState) bool {
	return persisted.RefreshToken != "" &&
		persisted.RefreshToken != attempted.RefreshToken &&
		persisted.LastAuthAt.After(attempted.LastAuthAt)
}

func (c *Client) beginRefreshAttempt(
	ctx context.Context,
	snapshot *TokenState,
	expectedRevision *uint64,
	expectedClaimID uint64,
) (*refreshAttempt, bool, TokenState, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, TokenState{}, err
	}

	for {
		c.refreshMu.Lock()
		c.mu.Lock()
		if expectedRevision != nil && c.stateRevision != *expectedRevision {
			current := c.state
			c.mu.Unlock()
			c.refreshMu.Unlock()
			return nil, false, current, nil
		}
		if c.state != *snapshot {
			current := c.state
			c.mu.Unlock()
			c.refreshMu.Unlock()
			return nil, false, current, nil
		}
		revision := c.stateRevision
		if c.refreshIntegrityBlockedLocked() {
			current := c.state
			c.mu.Unlock()
			c.refreshMu.Unlock()
			return nil, false, current, newSessionIntegrityError(
				"token generation is blocked after an integrity failure",
				nil,
			)
		}
		if c.refreshPermanentlyBlockedLocked() {
			current := c.state
			c.mu.Unlock()
			c.refreshMu.Unlock()
			return nil, false, current, errRefreshPermanentlyBlocked
		}
		if expectedClaimID != 0 {
			schedule := c.refreshSchedule
			if !schedule.valid ||
				schedule.revision != revision ||
				schedule.claimID != expectedClaimID ||
				schedule.disposition != refreshLoopActive {
				current := c.state
				c.mu.Unlock()
				c.refreshMu.Unlock()
				return nil, false, current, nil
			}
			if !c.now().Before(snapshot.ExpiresAt) {
				current := c.state
				c.mu.Unlock()
				c.refreshMu.Unlock()
				return nil, false, current, errScheduledRefreshExpired
			}
		}
		if c.oauth2 == nil || c.verifier == nil {
			c.mu.Unlock()
			c.refreshMu.Unlock()
			return nil, false, TokenState{}, ErrNotInitialized
		}
		active := c.refreshAttempt
		if active == nil {
			attemptCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
			attempt := &refreshAttempt{
				revision:     revision,
				snapshot:     *snapshot,
				ctx:          attemptCtx,
				cancel:       cancel,
				participants: 1,
				done:         make(chan struct{}),
				complete:     make(chan struct{}),
			}
			c.refreshAttempt = attempt
			c.mu.Unlock()
			c.refreshMu.Unlock()
			return attempt, true, TokenState{}, nil
		}
		sameRevision := active.revision == revision
		c.mu.Unlock()

		if sameRevision && active.participants > 0 {
			active.participants++
			c.refreshMu.Unlock()
			return active, false, TokenState{}, nil
		}
		c.refreshMu.Unlock()
		select {
		case <-active.done:
		case <-ctx.Done():
			return nil, false, TokenState{}, ctx.Err()
		}
	}
}

func (c *Client) waitForRefreshAttempt(
	ctx context.Context,
	attempt *refreshAttempt,
) (TokenState, error) {
	select {
	case <-attempt.complete:
		c.releaseRefreshParticipant(attempt)
		if attempt.err != nil {
			return attempt.state, attempt.err
		}
		c.mu.Lock()
		current := c.state
		c.mu.Unlock()
		return current, nil
	case <-ctx.Done():
		c.releaseRefreshParticipant(attempt)
		return TokenState{}, ctx.Err()
	}
}

func (c *Client) releaseRefreshParticipant(attempt *refreshAttempt) {
	c.refreshMu.Lock()
	attempt.participants--
	if attempt.participants == 0 && c.refreshAttempt == attempt {
		attempt.cancel()
	}
	c.refreshMu.Unlock()
}

func (c *Client) finishRefreshAttempt(
	attempt *refreshAttempt,
	state *TokenState,
	err error,
) {
	c.refreshMu.Lock()
	if err != nil {
		c.mu.Lock()
		switch {
		case isSessionIntegrityError(err):
			c.blockRefreshIntegrityLocked(attempt.revision, c.now())
		case IsPermanentError(err):
			c.blockRefreshPermanentLocked(
				attempt.revision,
				&attempt.snapshot,
				c.now(),
			)
		case attempt.ctx.Err() != nil && !errors.As(err, new(*AuthError)):
			// The attempt was abandoned while the request was in flight, so the
			// provider's answer is unknown. Keying off the attempt context
			// rather than the error's shape is deliberate: cancellation races
			// between the transport and the peer, so the surfaced error may be
			// a cancellation, an EOF, or a reset. An OAuth error code is the
			// exception: it proves the provider did answer, so the outcome is
			// known even though the attempt was also cancelled.
			c.markRefreshInconclusiveLocked(attempt.revision)
		}
		c.mu.Unlock()
	}
	attempt.state = *state
	attempt.err = err
	if c.refreshAttempt == attempt {
		c.refreshAttempt = nil
	}
	attempt.cancel()
	close(attempt.done)
	c.refreshMu.Unlock()
}

func (c *Client) performRefresh(
	ctx context.Context,
	snapshot *TokenState,
	revision uint64,
) (TokenState, bool, error) {
	c.mu.Lock()
	if c.oauth2 == nil {
		c.mu.Unlock()
		return TokenState{}, false, ErrNotInitialized
	}
	oauthCfg := *c.oauth2
	verifier := c.verifier
	if verifier == nil {
		c.mu.Unlock()
		return TokenState{}, false, ErrNotInitialized
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
		state, refreshErr := c.refreshFailure(
			revision,
			fmt.Errorf("pkceflow: token refresh failed: %w", asAuthError(err)),
		)
		return state, false, refreshErr
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
			state, refreshErr := c.refreshFailure(
				revision,
				newSessionIntegrityError("refreshed ID token validation failed", err),
			)
			return state, false, refreshErr
		}
		if verified.Subject == "" {
			state, refreshErr := c.refreshFailure(
				revision,
				newSessionIntegrityError("refreshed ID token subject is empty", nil),
			)
			return state, false, refreshErr
		}
		if snapshot.IDToken == "" {
			state, refreshErr := c.refreshFailure(
				revision,
				newSessionIntegrityError("current ID token unavailable during refresh", nil),
			)
			return state, false, refreshErr
		}
		claims, err := DecodeIDToken(snapshot.IDToken)
		if err != nil {
			state, refreshErr := c.refreshFailure(
				revision,
				newSessionIntegrityError("current ID token claims unavailable during refresh", err),
			)
			return state, false, refreshErr
		}
		if claims.Subject == "" {
			state, refreshErr := c.refreshFailure(
				revision,
				newSessionIntegrityError("current ID token subject is empty during refresh", nil),
			)
			return state, false, refreshErr
		}
		if verified.Subject != claims.Subject {
			state, refreshErr := c.refreshFailure(
				revision,
				newSessionIntegrityError("refreshed ID token subject changed", nil),
			)
			return state, false, refreshErr
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

	c.stateCommitMu.Lock()
	c.mu.Lock()
	if c.stateRevision != revision {
		current := c.state
		c.mu.Unlock()
		c.stateCommitMu.Unlock()
		return current, false, nil
	}
	c.advanceStateLocked(&newState)
	committedRevision := c.stateRevision
	c.mu.Unlock()
	persistErr := c.store.Save(newState)
	c.recordPersistenceSaveResult(committedRevision, persistErr, c.now())
	shouldDrain := c.enqueueEvent(EventTokenRefreshed, nil)
	c.stateCommitMu.Unlock()

	if persistErr != nil {
		c.logPersistenceSaveFailure()
	}
	return newState, shouldDrain, nil
}

// refreshFailure suppresses stale failures from a refresh request that was
// superseded while its network or verification work was in flight.
func (c *Client) refreshFailure(revision uint64, err error) (TokenState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stateRevision != revision {
		return c.state, nil
	}
	return TokenState{}, err
}
