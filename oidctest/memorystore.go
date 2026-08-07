package oidctest

import (
	"sync"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
)

// MemoryStore implements pkceflow.TokenPersistence in memory.
// Tokens are lost when the process exits. Safe for concurrent use.
type MemoryStore struct {
	mu    sync.Mutex
	state pkceflow.TokenState
}

// Save persists the token state in memory.
func (s *MemoryStore) Save(state pkceflow.TokenState) error { //nolint:gocritic // hugeParam: interface requires value receiver
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	return nil
}

// Load retrieves the in-memory token state.
// Returns zero TokenState if nothing has been saved.
func (s *MemoryStore) Load() (pkceflow.TokenState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, nil
}

// Delete clears the in-memory token state.
func (s *MemoryStore) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = pkceflow.TokenState{}
	return nil
}

// FailingStore implements pkceflow.TokenPersistence with configurable errors.
// Use SetSaveErr, SetLoadErr, and SetDeleteErr to inject errors.
// Safe for concurrent use.
type FailingStore struct {
	mu        sync.Mutex
	state     pkceflow.TokenState
	saveErr   error
	loadErr   error
	deleteErr error
}

// SetSaveErr sets the error returned by Save. Pass nil to clear.
func (s *FailingStore) SetSaveErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveErr = err
}

// SetLoadErr sets the error returned by Load. Pass nil to clear.
func (s *FailingStore) SetLoadErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadErr = err
}

// SetDeleteErr sets the error returned by Delete. Pass nil to clear.
func (s *FailingStore) SetDeleteErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteErr = err
}

// Save returns the injected save error if set, otherwise persists in memory.
func (s *FailingStore) Save(state pkceflow.TokenState) error { //nolint:gocritic // hugeParam: TokenState passed by value to match the TokenPersistence interface
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	s.state = state
	return nil
}

// Load returns the injected load error if set, otherwise retrieves from memory.
func (s *FailingStore) Load() (pkceflow.TokenState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return pkceflow.TokenState{}, s.loadErr
	}
	return s.state, nil
}

// Delete returns the injected delete error if set, otherwise clears memory.
func (s *FailingStore) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.state = pkceflow.TokenState{}
	return nil
}
