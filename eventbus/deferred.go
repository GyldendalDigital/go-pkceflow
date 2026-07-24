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
type DeferredEventBus struct {
	mu       sync.Mutex
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
	defer d.mu.Unlock()

	if d.target != nil {
		d.target.Emit(event, data)
		return
	}
	d.buffered = append(d.buffered, bufferedEvent{name: event, data: data})
}

// SetTarget sets the real emitter and flushes all buffered events to it.
// After this call, Emit() goes directly to the target.
func (d *DeferredEventBus) SetTarget(target pkceflow.EventEmitter) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.target = target
	for _, ev := range d.buffered {
		target.Emit(ev.name, ev.data)
	}
	d.buffered = nil
}

// NoopEventBus implements pkceflow.EventEmitter by silently dropping all events.
// Use when events are not needed (CLI apps, headless testing).
type NoopEventBus struct{}

// Emit does nothing.
func (NoopEventBus) Emit(_ string, _ any) {}
