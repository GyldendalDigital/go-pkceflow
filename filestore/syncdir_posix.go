//go:build linux || darwin

package filestore

import (
	"fmt"
	"os"
)

func syncDirectory(path string) error {
	dir, err := os.Open(path) //nolint:gosec // path is the caller-selected private store directory
	if err != nil {
		return fmt.Errorf("open directory: %w", err)
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return fmt.Errorf("sync directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close directory: %w", err)
	}
	return nil
}
