package pkceflow

import (
	"context"
	"fmt"
)

type lifecycleOperationKind uint8

const (
	lifecycleLogin lifecycleOperationKind = iota + 1
	lifecycleLogout
)

type lifecycleOperation struct {
	id     uint64
	kind   lifecycleOperationKind
	parent context.Context
	ctx    context.Context
	cancel context.CancelFunc
}

// beginLifecycleOperation admits a new operation and supersedes the previous
// one. It returns nil if the context expires while waiting for admission. The
// caller must have checked any other operation-specific entry preconditions.
func (c *Client) beginLifecycleOperation(
	ctx context.Context,
	kind lifecycleOperationKind,
) *lifecycleOperation {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if ctx.Err() != nil {
		return nil
	}
	return c.beginLifecycleOperationLocked(ctx, kind)
}

// beginLifecycleOperationLocked requires lifecycleMu.
func (c *Client) beginLifecycleOperationLocked(
	ctx context.Context,
	kind lifecycleOperationKind,
) *lifecycleOperation {
	if c.lifecycleOperation != nil {
		c.lifecycleOperation.cancel()
	}

	c.lifecycleSeq++
	operationCtx, cancel := context.WithCancel(ctx)
	operation := &lifecycleOperation{
		id:     c.lifecycleSeq,
		kind:   kind,
		parent: ctx,
		ctx:    operationCtx,
		cancel: cancel,
	}
	c.lifecycleOperation = operation
	return operation
}

func (c *Client) finishLifecycleOperation(operation *lifecycleOperation) {
	c.lifecycleMu.Lock()
	if c.lifecycleOperation == operation && c.lifecycleOperation.id == operation.id {
		c.lifecycleOperation = nil
	}
	c.lifecycleMu.Unlock()

	operation.cancel()
}

// lifecycleOperationOwned reports whether operation is still the Client's
// current operation, ignoring context cancellation.
//
// It exists for post-commit work that must still run for a cancelled caller.
// lifecycleOperationCurrent conflates "superseded by a newer operation" with
// "the caller's context ended", and a Logout whose context is already cancelled
// — "log out and quit" — must still revoke its refresh token.
func (c *Client) lifecycleOperationOwned(operation *lifecycleOperation) bool {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	return c.lifecycleOperation == operation
}

func (c *Client) lifecycleOperationCurrent(operation *lifecycleOperation) bool {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	return c.lifecycleOperationCurrentLocked(operation)
}

func (c *Client) lifecycleOperationCurrentLocked(operation *lifecycleOperation) bool {
	return c.lifecycleOperation == operation &&
		c.lifecycleOperation.id == operation.id &&
		operation.parent.Err() == nil &&
		operation.ctx.Err() == nil
}

func (c *Client) lifecycleFlowPermit() chan struct{} {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.lifecycleFlow == nil {
		c.lifecycleFlow = make(chan struct{}, 1)
	}
	return c.lifecycleFlow
}

// flowCancelledCause attaches a context cause to ErrFlowCancelled so callers can
// tell a flow that ran out of time from one that was cancelled, while
// errors.Is(err, ErrFlowCancelled) keeps matching for both.
//
// A nil cause returns the bare sentinel. fmt.Errorf would otherwise format it as
// "%!w(<nil>)" while errors.Is still reported a match, so the mistake would
// survive a table test and surface only in logs.
func flowCancelledCause(cause error) error {
	if cause == nil {
		return ErrFlowCancelled
	}
	return fmt.Errorf("%w: %w", ErrFlowCancelled, cause)
}

// flowCancelledError classifies why an operation stopped being current.
//
// The cause comes from the operation's parent, which is the caller's context
// wrapped with LoginTimeout or LogoutTimeout, so a deadline there means the flow
// ran out of time and a cancellation means the caller gave up. Supersession by a
// newer operation cancels only operation.ctx, leaving the parent clean, so it
// yields the bare sentinel.
//
// It reads Err rather than Cause deliberately: a caller using
// context.WithCancelCause would otherwise have their own error spliced into a
// core error message, and errors.Is(err, context.Canceled) would stop matching.
func (c *Client) flowCancelledError(operation *lifecycleOperation) error {
	return flowCancelledCause(operation.parent.Err())
}

func (c *Client) lifecycleOperationError(
	operation *lifecycleOperation,
	err error,
) error {
	if !c.lifecycleOperationCurrent(operation) {
		return c.flowCancelledError(operation)
	}
	return err
}

// runLifecycleFlow serializes browser handler ownership for one Client. The
// narrow permit lets a cancelled mobile waiter unregister before its replacement
// starts, while independent Clients remain fully concurrent.
func (c *Client) runLifecycleFlow(
	operation *lifecycleOperation,
	start func(context.Context) (string, error),
) (string, error) {
	if !c.lifecycleOperationCurrent(operation) {
		return "", c.flowCancelledError(operation)
	}

	permit := c.lifecycleFlowPermit()
	select {
	case permit <- struct{}{}:
	case <-operation.ctx.Done():
		return "", c.flowCancelledError(operation)
	}
	defer func() { <-permit }()

	if !c.lifecycleOperationCurrent(operation) {
		return "", c.flowCancelledError(operation)
	}
	result, err := start(operation.ctx)
	if !c.lifecycleOperationCurrent(operation) {
		return "", c.flowCancelledError(operation)
	}
	return result, err
}
