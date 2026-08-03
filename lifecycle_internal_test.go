package pkceflow

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestLoginCommitRechecksCancellationAfterStateCommitWait(t *testing.T) {
	client := &Client{
		store:   &memoryStore{},
		emitter: noopEmitter{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	operation := client.beginLifecycleOperation(ctx, lifecycleLogin)
	defer client.finishLifecycleOperation(operation)

	client.stateCommitMu.Lock()
	commitLockHeld := true
	defer func() {
		if commitLockHeld {
			client.stateCommitMu.Unlock()
		}
	}()

	type commitResult struct {
		committed  bool
		persistErr error
	}
	result := make(chan commitResult, 1)
	go func() {
		committed, persistErr := client.commitLoginState(operation, &TokenState{
			AccessToken: "late-access-token",
		})
		result <- commitResult{committed: committed, persistErr: persistErr}
	}()

	waitForLifecycleCommitLock(t, client)
	cancel()
	client.stateCommitMu.Unlock()
	commitLockHeld = false

	select {
	case got := <-result:
		if got.committed {
			t.Fatal("cancelled Login committed after waiting for stateCommitMu")
		}
		if got.persistErr != nil {
			t.Fatalf("commit persistence error = %v, want nil", got.persistErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled Login commit did not return")
	}

	client.mu.Lock()
	state := client.state
	client.mu.Unlock()
	if !state.IsZero() {
		t.Fatalf("cancelled Login installed state: %+v", state)
	}
	persisted, err := client.store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !persisted.IsZero() {
		t.Fatalf("cancelled Login persisted state: %+v", persisted)
	}
	client.eventMu.Lock()
	pendingEvents := len(client.pendingEvents)
	dispatching := client.eventDispatching
	client.eventMu.Unlock()
	if pendingEvents != 0 || dispatching {
		t.Fatalf("cancelled Login queued an event: pending=%d dispatching=%v", pendingEvents, dispatching)
	}
}

func TestCancelledLifecycleWaiterDoesNotSupersedeCurrentOperation(t *testing.T) {
	client := &Client{}
	current := client.beginLifecycleOperation(context.Background(), lifecycleLogout)
	defer client.finishLifecycleOperation(current)

	client.lifecycleMu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	waiterStarted := make(chan struct{})
	result := make(chan *lifecycleOperation, 1)
	go func() {
		close(waiterStarted)
		result <- client.beginLifecycleOperation(ctx, lifecycleLogin)
	}()
	<-waiterStarted
	cancel()
	client.lifecycleMu.Unlock()

	select {
	case admitted := <-result:
		if admitted != nil {
			admitted.cancel()
			t.Fatal("cancelled lifecycle waiter was admitted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled lifecycle waiter did not return")
	}

	select {
	case <-current.ctx.Done():
		t.Fatal("cancelled lifecycle waiter superseded the current operation")
	default:
	}
	if !client.lifecycleOperationCurrent(current) {
		t.Fatal("current lifecycle operation lost ownership")
	}
}

func waitForLifecycleCommitLock(t *testing.T, client *Client) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !client.lifecycleMu.TryLock() {
			return
		}
		client.lifecycleMu.Unlock()
		runtime.Gosched()
	}
	t.Fatal("Login did not reach the blocked state commit")
}
