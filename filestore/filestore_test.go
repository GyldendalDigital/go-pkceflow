package filestore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()

	store, err := New("test-app", dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state := pkceflow.TokenState{
		AccessToken:  "access-token-123",
		RefreshToken: "refresh-token-456",
		IDToken:      "id-token-789",
		ExpiresAt:    time.Now().Add(time.Hour).Truncate(time.Second),
		LastAuthAt:   time.Now().Truncate(time.Second),
	}

	if err := store.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.AccessToken != state.AccessToken {
		t.Errorf("AccessToken: got %q, want %q", loaded.AccessToken, state.AccessToken)
	}
	if loaded.RefreshToken != state.RefreshToken {
		t.Errorf("RefreshToken: got %q, want %q", loaded.RefreshToken, state.RefreshToken)
	}
	if loaded.IDToken != state.IDToken {
		t.Errorf("IDToken: got %q, want %q", loaded.IDToken, state.IDToken)
	}
	if !loaded.ExpiresAt.Equal(state.ExpiresAt) {
		t.Errorf("ExpiresAt: got %v, want %v", loaded.ExpiresAt, state.ExpiresAt)
	}
	if !loaded.LastAuthAt.Equal(state.LastAuthAt) {
		t.Errorf("LastAuthAt: got %v, want %v", loaded.LastAuthAt, state.LastAuthAt)
	}
}

func TestLoadNoFile(t *testing.T) {
	dir := t.TempDir()

	store, err := New("test-app", dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !state.IsZero() {
		t.Errorf("expected zero state, got %+v", state)
	}
}

func TestLoadCorruptedFile(t *testing.T) {
	dir := t.TempDir()

	store, err := New("test-app", dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Write garbage to the token file.
	if err := os.WriteFile(store.path, []byte("corrupted-data"), filePerm); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load should not error on corruption: %v", err)
	}
	if !state.IsZero() {
		t.Errorf("expected zero state for corrupted file, got %+v", state)
	}
}

func TestLoadReKeyedFile(t *testing.T) {
	dir := t.TempDir()

	// Save with one key.
	store1, err := New("app-one", dir)
	if err != nil {
		t.Fatalf("New store1: %v", err)
	}

	state := pkceflow.TokenState{
		AccessToken:  "token",
		RefreshToken: "refresh",
		IDToken:      "id",
		ExpiresAt:    time.Now().Add(time.Hour).Truncate(time.Second),
		LastAuthAt:   time.Now().Truncate(time.Second),
	}

	if err := store1.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load with a different key (different appID).
	store2, err := New("app-two", dir)
	if err != nil {
		t.Fatalf("New store2: %v", err)
	}

	loaded, err := store2.Load()
	if err != nil {
		t.Fatalf("Load should not error on re-keyed file: %v", err)
	}
	if !loaded.IsZero() {
		t.Errorf("expected zero state for re-keyed file, got %+v", loaded)
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()

	store, err := New("test-app", dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state := pkceflow.TokenState{
		AccessToken:  "token",
		RefreshToken: "refresh",
		IDToken:      "id",
		ExpiresAt:    time.Now().Add(time.Hour).Truncate(time.Second),
		LastAuthAt:   time.Now().Truncate(time.Second),
	}

	if err := store.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := store.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load after Delete: %v", err)
	}
	if !loaded.IsZero() {
		t.Errorf("expected zero state after delete, got %+v", loaded)
	}
}

func TestDeleteNonExistent(t *testing.T) {
	dir := t.TempDir()

	store, err := New("test-app", dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Should not error when file does not exist.
	if err := store.Delete(); err != nil {
		t.Fatalf("Delete non-existent: %v", err)
	}
}

func TestDirectoryAutoCreated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "deep", "dir")

	store, err := New("test-app", dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state := pkceflow.TokenState{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(time.Hour).Truncate(time.Second),
		LastAuthAt:  time.Now().Truncate(time.Second),
	}

	if err := store.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.AccessToken != "token" {
		t.Errorf("AccessToken: got %q, want %q", loaded.AccessToken, "token")
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()

	store, err := New("test-app", dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state := pkceflow.TokenState{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(time.Hour).Truncate(time.Second),
		LastAuthAt:  time.Now().Truncate(time.Second),
	}

	if err := store.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != filePerm {
		t.Errorf("file permission: got %o, want %o", perm, filePerm)
	}
}
