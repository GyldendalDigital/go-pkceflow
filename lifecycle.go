package pkceflow

import "context"

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

func (c *Client) lifecycleOperationError(
	operation *lifecycleOperation,
	err error,
) error {
	if !c.lifecycleOperationCurrent(operation) {
		return ErrFlowCancelled
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
		return "", ErrFlowCancelled
	}

	permit := c.lifecycleFlowPermit()
	select {
	case permit <- struct{}{}:
	case <-operation.ctx.Done():
		return "", ErrFlowCancelled
	}
	defer func() { <-permit }()

	if !c.lifecycleOperationCurrent(operation) {
		return "", ErrFlowCancelled
	}
	result, err := start(operation.ctx)
	if !c.lifecycleOperationCurrent(operation) {
		return "", ErrFlowCancelled
	}
	return result, err
}
