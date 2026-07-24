package eventbus

import (
	"sync"
	"testing"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
)

// testEmitter captures events for assertions in tests.
type testEmitter struct {
	mu     sync.Mutex
	events []string
}

func (e *testEmitter) Emit(event string, _ any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *testEmitter) has(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.events {
		if ev == name {
			return true
		}
	}
	return false
}

func (e *testEmitter) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.events)
}

func TestDeferredEventBus_BuffersBeforeTarget(t *testing.T) {
	d := &DeferredEventBus{}

	d.Emit("oidcauth:logged-in", nil)
	d.Emit("oidcauth:token-refreshed", nil)

	// Events should be buffered, not lost
	target := &testEmitter{}
	d.SetTarget(target)

	if !target.has("oidcauth:logged-in") {
		t.Error("logged-in not flushed to target")
	}
	if !target.has("oidcauth:token-refreshed") {
		t.Error("token-refreshed not flushed to target")
	}
}

func TestDeferredEventBus_DirectAfterTarget(t *testing.T) {
	d := &DeferredEventBus{}
	target := &testEmitter{}

	d.SetTarget(target)
	d.Emit("oidcauth:logged-out", nil)

	if !target.has("oidcauth:logged-out") {
		t.Error("logged-out not emitted directly to target")
	}
}

func TestDeferredEventBus_FlushClearsBuffer(t *testing.T) {
	d := &DeferredEventBus{}
	d.Emit("event1", nil)
	d.Emit("event2", nil)

	target := &testEmitter{}
	d.SetTarget(target)

	if target.count() != 2 {
		t.Errorf("expected 2 flushed events, got %d", target.count())
	}

	// Emit more after target set
	d.Emit("event3", nil)
	if target.count() != 3 {
		t.Errorf("expected 3 total events, got %d", target.count())
	}
}

func TestDeferredEventBus_ConcurrentSafety(t *testing.T) {
	d := &DeferredEventBus{}
	var wg sync.WaitGroup

	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Emit("concurrent", nil)
		}()
	}

	// Set target while events are being emitted
	target := &testEmitter{}
	d.SetTarget(target)
	wg.Wait()
}

func TestNoopEventBus_DoesNotPanic(t *testing.T) {
	var noop NoopEventBus
	noop.Emit("anything", map[string]string{"key": "value"})
	noop.Emit("", nil)

	// Verify it implements the interface
	var _ pkceflow.EventEmitter = NoopEventBus{}
}
