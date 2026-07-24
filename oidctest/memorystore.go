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
