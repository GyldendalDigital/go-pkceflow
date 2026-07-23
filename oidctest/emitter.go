package oidctest

import (
	"sync"
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
	mu     sync.Mutex
	events []Event
}

// Emit records an event.
func (e *RecordingEmitter) Emit(event string, data any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, Event{Name: event, Data: data})
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
