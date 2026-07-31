package filestore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// stagePrivateFile writes a complete private file in dir without publishing it
// under its final name. The caller owns the returned path and must remove it.
func stagePrivateFile(dir, pattern string, data []byte) (result string, resultErr error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("create temporary file: %w", err)
	}

	path := file.Name()
	closed := false
	keep := false
	defer func() {
		if keep {
			return
		}
		var cleanupErr error
		if !closed {
			if err := file.Close(); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("close failed temporary file: %w", err))
			}
		}
		cleanupErr = errors.Join(cleanupErr, removeStagedFile(path))
		resultErr = errors.Join(resultErr, cleanupErr)
	}()

	if err := secureFile(file, filePerm); err != nil {
		return "", fmt.Errorf("secure temporary file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return "", fmt.Errorf("write temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync temporary file: %w", err)
	}
	closeErr := file.Close()
	closed = true
	if closeErr != nil {
		return "", fmt.Errorf("close temporary file: %w", closeErr)
	}

	keep = true
	return path, nil
}

func writePrivateFileAtomic(path string, data []byte) error {
	return writePrivateFileAtomicWith(path, data, os.Rename, syncDirectory)
}

func writePrivateFileAtomicWith(
	path string,
	data []byte,
	rename func(oldPath, newPath string) error,
	syncDir func(string) error,
) error {
	dir := filepath.Dir(path)
	tempPath, err := stagePrivateFile(dir, "."+filepath.Base(path)+"-*", data)
	if err != nil {
		return err
	}

	if err := rename(tempPath, path); err != nil {
		return errors.Join(fmt.Errorf("replace file: %w", err), removeStagedFile(tempPath))
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync replacement directory: %w", err)
	}
	return nil
}

func removeStagedFile(path string) error {
	err := os.Remove(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("remove temporary file %q: %w", path, err)
}
