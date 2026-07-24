// Package filestore provides an AES-256-GCM encrypted file-based implementation
// of pkceflow.TokenPersistence.
package filestore

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
)

const (
	tokenFileName = "tokens.enc"
	keyFileName   = ".keyfile"
	dirPerm       = 0o700
	filePerm      = 0o600
	keySize       = 32
)

// Store is an AES-256-GCM encrypted file-based token store.
type Store struct {
	dir  string
	key  [32]byte
	path string
}

// New creates a Store that persists tokens to dir/tokens.enc.
// The encryption key is derived from SHA-256(appID + ":" + machineID).
// If the machine ID is unavailable, a persistent random key file is used instead.
func New(appID, dir string) (*Store, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("filestore: create directory %q: %w", dir, err)
	}

	key, err := deriveKey(appID, dir)
	if err != nil {
		return nil, fmt.Errorf("filestore: derive key: %w", err)
	}

	return &Store{
		dir:  dir,
		key:  key,
		path: filepath.Join(dir, tokenFileName),
	}, nil
}

// Save persists the token state encrypted to disk.
//
//nolint:gocritic // hugeParam: interface requires value parameter
func (s *Store) Save(state pkceflow.TokenState) error {
	plaintext, err := json.Marshal(state) //nolint:gosec // G117: token fields are encrypted before writing to disk
	if err != nil {
		return fmt.Errorf("filestore: marshal token state: %w", err)
	}

	ciphertext, err := encrypt(s.key[:], plaintext)
	if err != nil {
		return fmt.Errorf("filestore: encrypt: %w", err)
	}

	if err := os.WriteFile(s.path, ciphertext, filePerm); err != nil {
		return fmt.Errorf("filestore: write %q: %w", s.path, err)
	}

	return nil
}

// Load retrieves persisted token state. Returns zero TokenState (not error)
// if no state exists or the stored data is corrupted/unreadable.
func (s *Store) Load() (pkceflow.TokenState, error) {
	ciphertext, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return pkceflow.TokenState{}, nil
		}
		return pkceflow.TokenState{}, nil
	}

	plaintext, err := decrypt(s.key[:], ciphertext)
	if err != nil {
		// Corrupted or re-keyed: return zero state to trigger re-login.
		return pkceflow.TokenState{}, nil
	}

	var state pkceflow.TokenState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return pkceflow.TokenState{}, nil
	}

	return state, nil
}

// Delete removes the persisted token file.
func (s *Store) Delete() error {
	err := os.Remove(s.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("filestore: delete %q: %w", s.path, err)
	}
	return nil
}

// deriveKey produces the 32-byte encryption key.
func deriveKey(appID, dir string) ([32]byte, error) {
	mid, err := machineID()
	if err == nil && mid != "" {
		return sha256.Sum256([]byte(appID + ":" + mid)), nil
	}

	// Fallback: use a persisted random key file.
	return fallbackKey(filepath.Join(dir, keyFileName))
}

// DefaultDir returns the recommended per-user directory for this application's
// encrypted token file, hiding platform differences. It is os.UserConfigDir
// joined with appID:
//
//   - Linux:   $XDG_CONFIG_HOME/<appID>  (or ~/.config/<appID>)
//   - macOS:   ~/Library/Application Support/<appID>
//   - Windows: %AppData%\<appID>
//
// It does not create the directory; New and NewDefault do. On mobile,
// os.UserConfigDir does not resolve to the application sandbox, so mobile
// consumers should pass their platform-provided sandbox path to New instead.
func DefaultDir(appID string) (string, error) {
	if strings.TrimSpace(appID) == "" {
		return "", fmt.Errorf("filestore: appID is required")
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("filestore: resolve user config dir: %w", err)
	}
	return filepath.Join(base, appID), nil
}

// NewDefault creates a Store in DefaultDir(appID), the common desktop case, so
// the consumer does not compute a platform-specific path. On mobile, use New
// with the platform-provided sandbox directory instead.
func NewDefault(appID string) (*Store, error) {
	dir, err := DefaultDir(appID)
	if err != nil {
		return nil, err
	}
	return New(appID, dir)
}
