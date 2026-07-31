package filestore

import (
	"fmt"
	"os"
	"runtime"
)

func securePath(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if got := info.Mode().Perm(); got != mode.Perm() {
		return fmt.Errorf("permissions are %o, want %o", got, mode.Perm())
	}
	return nil
}

func secureFile(file *os.File, mode os.FileMode) error {
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}

	info, err := file.Stat()
	if err != nil {
		return err
	}
	if got := info.Mode().Perm(); got != mode.Perm() {
		return fmt.Errorf("permissions are %o, want %o", got, mode.Perm())
	}
	return nil
}
