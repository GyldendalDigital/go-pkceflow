// Package eventbus provides event bus utilities for go-pkceflow.
//
// DeferredEventBus buffers events until a target emitter is set,
// solving startup ordering issues (e.g., Wails services created before the app).
//
// NoopEventBus silently drops all events, useful for headless/CLI usage
// or tests that don't need event assertions.
package eventbus

import (
	"sync"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
)

// DeferredEventBus buffers events until a target EventEmitter is set via SetTarget.
// Once the target is set, buffered events are flushed and subsequent emissions
// go directly to the target. Thread-safe.
//
// The target's Emit is never called while the state mutex is held, so a slow
// target emitter does not block callers from buffering. The target's Emit must
// not call back into the same bus (Emit or SetTarget), which would deadlock.
type DeferredEventBus struct {
	mu       sync.Mutex // guards target and buffered
	sendMu   sync.Mutex // serializes delivery to the target and orders flush before direct sends
	target   pkceflow.EventEmitter
	buffered []bufferedEvent
}

type bufferedEvent struct {
	name string
	data any
}

// Emit buffers the event if no target is set, or emits directly if target is available.
func (d *DeferredEventBus) Emit(event string, data any) {
	d.mu.Lock()
	if d.target == nil {
		d.buffered = append(d.buffered, bufferedEvent{name: event, data: data})
		d.mu.Unlock()
		return
	}
	target := d.target
	d.mu.Unlock()

	// sendMu orders this direct send after any in-progress SetTarget flush, so
	// buffered events are always delivered before later direct emissions.
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	target.Emit(event, data)
}

// SetTarget sets the real emitter and flushes all buffered events to it.
// After this call, Emit() goes directly to the target.
func (d *DeferredEventBus) SetTarget(target pkceflow.EventEmitter) {
	// Hold sendMu across the flush so concurrent direct Emit calls wait until
	// buffered events have been delivered, preserving order.
	d.sendMu.Lock()
	defer d.sendMu.Unlock()

	d.mu.Lock()
	d.target = target
	buffered := d.buffered
	d.buffered = nil
	d.mu.Unlock()

	for _, ev := range buffered {
		target.Emit(ev.name, ev.data)
	}
}

// NoopEventBus implements pkceflow.EventEmitter by silently dropping all events.
// Use when events are not needed (CLI apps, headless testing).
type NoopEventBus struct{}

// Emit does nothing.
func (NoopEventBus) Emit(_ string, _ any) {}
