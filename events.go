package pkceflow

type clientEvent struct {
	name string
	data any
}

// Auth lifecycle events emitted by the Client via EventEmitter.
//
// The typical event sequence for a successful session:
//
//	Init succeeds    -> (no event, Init is silent on success)
//	Login completes  -> EventLoggedIn
//	Token refreshed  -> EventTokenRefreshed (repeats on schedule)
//	User logs out    -> EventLoggedOut
//
// Error scenarios:
//
//	Init fails           -> EventInitFailed (non-fatal, app continues offline)
//	Refresh permanently fails -> EventSessionExpired (user must re-authenticate)
const (
	// EventLoggedIn is emitted after a successful Login() token exchange.
	EventLoggedIn = "oidcauth:logged-in"

	// EventLoggedOut is emitted after Logout() clears auth state.
	EventLoggedOut = "oidcauth:logged-out"

	// EventTokenRefreshed is emitted after any successful token refresh,
	// including one triggered synchronously by AccessToken. It describes the
	// committed in-memory generation and is not repeated if persistence needs
	// to recover that generation in the background.
	EventTokenRefreshed = "oidcauth:token-refreshed" //nolint:gosec // G101 false positive: not a credential

	// EventSessionExpired is emitted when the refresh token is permanently
	// invalid (e.g., revoked) and the grace period (if configured) has expired,
	// or when a refresh response fails session-integrity checks.
	EventSessionExpired = "oidcauth:session-expired"

	// EventInitFailed is emitted when Init() fails to perform OIDC discovery.
	// This is non-fatal: the app can continue offline with cached tokens
	// from RestoreSession().
	EventInitFailed = "oidcauth:init-failed"
)

// enqueueEvent appends an event in commit order. The caller that transitions
// eventDispatching from false to true must call drainEvents after releasing any
// Client state locks.
func (c *Client) enqueueEvent(event string, data any) bool {
	c.eventMu.Lock()
	defer c.eventMu.Unlock()

	c.pendingEvents = append(c.pendingEvents, clientEvent{name: event, data: data})
	if c.eventDispatching {
		return false
	}
	c.eventDispatching = true
	return true
}

// drainEvents serializes emitter calls without holding Client state locks.
// Reentrant Client operations append to the active queue and return; this
// drainer delivers their events after the current callback completes.
func (c *Client) drainEvents() {
	for {
		c.eventMu.Lock()
		if len(c.pendingEvents) == 0 {
			c.eventDispatching = false
			c.eventMu.Unlock()
			return
		}
		event := c.pendingEvents[0]
		c.pendingEvents[0] = clientEvent{}
		c.pendingEvents = c.pendingEvents[1:]
		c.eventMu.Unlock()

		c.emitter.Emit(event.name, event.data)
	}
}

func (c *Client) emitEvent(event string, data any) {
	if c.enqueueEvent(event, data) {
		c.drainEvents()
	}
}

// emitEventIfRevision atomically orders a refresh-derived event against newer
// state commits. A false result means the refresh generation was superseded.
func (c *Client) emitEventIfRevision(revision uint64, event string, data any) bool {
	c.stateCommitMu.Lock()
	c.mu.Lock()
	current := c.stateRevision == revision
	c.mu.Unlock()

	var shouldDrain bool
	if current {
		shouldDrain = c.enqueueEvent(event, data)
	}
	c.stateCommitMu.Unlock()

	if shouldDrain {
		c.drainEvents()
	}
	return current
}
