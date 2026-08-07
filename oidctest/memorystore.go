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
// Set SaveErr, LoadErr, or DeleteErr to make the corresponding method fail.
// Safe for concurrent use.
type FailingStore struct {
	mu        sync.Mutex
	state     pkceflow.TokenState
	SaveErr   error
	LoadErr   error
	DeleteErr error
}

// Save returns SaveErr if set, otherwise persists in memory.
func (s *FailingStore) Save(state pkceflow.TokenState) error { //nolint:gocritic // hugeParam: interface requires value receiver
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SaveErr != nil {
		return s.SaveErr
	}
	s.state = state
	return nil
}

// Load returns LoadErr if set, otherwise retrieves from memory.
func (s *FailingStore) Load() (pkceflow.TokenState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.LoadErr != nil {
		return pkceflow.TokenState{}, s.LoadErr
	}
	return s.state, nil
}

// Delete returns DeleteErr if set, otherwise clears memory.
func (s *FailingStore) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.DeleteErr != nil {
		return s.DeleteErr
	}
	s.state = pkceflow.TokenState{}
	return nil
}
