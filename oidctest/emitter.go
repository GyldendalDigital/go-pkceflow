package oidctest

import (
	"sync"
	"time"
)

// Event represents a captured event with its name and associated data.
type Event struct {
	Name string
	Data any
}

// RecordingEmitter implements pkceflow.EventEmitter and captures all emitted events.
// Use HasEvent and Events to inspect what was emitted during a test.
// Safe for concurrent use.
type RecordingEmitter struct {
	mu       sync.Mutex
	events   []Event
	notifyCh chan struct{} // closed on each emit, then replaced
}

// Emit records an event.
func (e *RecordingEmitter) Emit(event string, data any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, Event{Name: event, Data: data})
	// Notify waiters.
	if e.notifyCh != nil {
		close(e.notifyCh)
		e.notifyCh = nil
	}
}

// HasEvent reports whether an event with the given name was emitted.
func (e *RecordingEmitter) HasEvent(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.events {
		if ev.Name == name {
			return true
		}
	}
	return false
}

// Events returns a copy of all captured events.
func (e *RecordingEmitter) Events() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]Event, len(e.events))
	copy(result, e.events)
	return result
}

// Reset clears all captured events.
func (e *RecordingEmitter) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = nil
}

// WaitForEvent blocks until an event with the given name is emitted or the
// timeout expires. Returns true if the event was observed, false on timeout.
// This avoids polling in asynchronous test scenarios.
func (e *RecordingEmitter) WaitForEvent(name string, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		e.mu.Lock()
		for _, ev := range e.events {
			if ev.Name == name {
				e.mu.Unlock()
				return true
			}
		}
		// Set up notification channel for next emit.
		if e.notifyCh == nil {
			e.notifyCh = make(chan struct{})
		}
		ch := e.notifyCh
		e.mu.Unlock()

		select {
		case <-ch:
			// New event emitted; re-check.
		case <-timer.C:
			return false
		}
	}
}
