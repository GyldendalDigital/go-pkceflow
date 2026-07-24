package filestore

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// machineID returns a stable machine identifier.
// Platform-specific implementations are in machineid_*.go files.
// Declared in platform files: func machineID() (string, error)

// fallbackKey reads or creates a persistent random key file.
// Used when the platform machine ID is unavailable.
func fallbackKey(path string) ([32]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is constructed internally from known machine-id locations
	if err == nil && len(data) == keySize {
		var key [32]byte
		copy(key[:], data)
		return key, nil
	}

	// Generate a new random key.
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return [32]byte{}, fmt.Errorf("generate fallback key: %w", err)
	}

	if err := os.WriteFile(path, key[:], filePerm); err != nil {
		return [32]byte{}, fmt.Errorf("write fallback key %q: %w", path, err)
	}

	return key, nil
}
