//go:build windows

package filestore

// Windows does not provide the same portable directory-fsync guarantee as
// Unix. Staged file contents are still flushed before namespace replacement.
func syncDirectory(string) error {
	return nil
}
