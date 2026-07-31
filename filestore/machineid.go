package filestore

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// machineID returns a stable machine identifier.
// Platform-specific implementations are in machineid_*.go files.
// Declared in platform files: func machineID() (string, error)

// fallbackKeyWithReader reads or creates the persistent random key used when
// the platform machine ID is unavailable.
func fallbackKeyWithReader(path string, random io.Reader) ([32]byte, error) {
	return fallbackKeyWithReaderAndSync(path, random, syncDirectory)
}

func fallbackKeyWithReaderAndSync(
	path string,
	random io.Reader,
	syncDir func(string) error,
) ([32]byte, error) {
	key, err := readFallbackKey(path)
	if err == nil {
		if err := syncDir(filepath.Dir(path)); err != nil {
			return [32]byte{}, fmt.Errorf("sync existing fallback key: %w", err)
		}
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return [32]byte{}, err
	}

	var candidate [32]byte
	if _, err := io.ReadFull(random, candidate[:]); err != nil {
		return [32]byte{}, fmt.Errorf("generate fallback key: %w", err)
	}

	err = publishFallbackKey(path, candidate)
	if err == nil {
		return candidate, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return [32]byte{}, err
	}

	// Another caller published a complete key first.
	key, err = readFallbackKey(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("read concurrently published fallback key: %w", err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return [32]byte{}, fmt.Errorf("sync concurrently published fallback key: %w", err)
	}
	return key, nil
}

func readFallbackKey(path string) ([32]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("inspect fallback key %q: %w", path, err)
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return [32]byte{}, fmt.Errorf("fallback key %q must not be a symlink", path)
	}
	if !before.Mode().IsRegular() {
		return [32]byte{}, fmt.Errorf("fallback key %q must be a regular file", path)
	}
	if before.Size() != keySize {
		return [32]byte{}, fmt.Errorf("fallback key %q must be exactly %d bytes", path, keySize)
	}

	file, err := os.Open(path) //nolint:gosec // path is the caller-selected private store directory
	if err != nil {
		return [32]byte{}, fmt.Errorf("open fallback key %q: %w", path, err)
	}
	defer file.Close() //nolint:errcheck

	after, err := file.Stat()
	if err != nil {
		return [32]byte{}, fmt.Errorf("stat fallback key %q: %w", path, err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != keySize {
		return [32]byte{}, fmt.Errorf("fallback key %q changed while opening", path)
	}
	if err := secureFile(file, filePerm); err != nil {
		return [32]byte{}, fmt.Errorf("secure fallback key %q: %w", path, err)
	}

	var key [32]byte
	if _, err := io.ReadFull(file, key[:]); err != nil {
		return [32]byte{}, fmt.Errorf("read fallback key %q: %w", path, err)
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return [32]byte{}, fmt.Errorf("fallback key %q changed while reading", path)
	}
	return key, nil
}

func publishFallbackKey(path string, key [32]byte) error {
	return publishFallbackKeyWithSync(path, key, syncDirectory)
}

func publishFallbackKeyWithSync(path string, key [32]byte, syncDir func(string) error) error {
	dir := filepath.Dir(path)
	tempPath, err := stagePrivateFile(dir, "."+filepath.Base(path)+"-*", key[:])
	if err != nil {
		return fmt.Errorf("stage fallback key %q: %w", path, err)
	}

	if err := os.Link(tempPath, path); err != nil {
		if cleanupErr := removeStagedFile(tempPath); cleanupErr != nil {
			return cleanupErr
		}
		return fmt.Errorf("publish fallback key %q: %w", path, err)
	}
	if err := removeStagedFile(tempPath); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync fallback key directory: %w", err)
	}
	return nil
}
