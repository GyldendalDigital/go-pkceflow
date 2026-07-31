//go:build linux || darwin

package filestore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
)

func TestNewTightensExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("Chmod setup: %v", err)
	}

	if _, err := New("test-app", dir); err != nil {
		t.Fatalf("New: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != dirPerm {
		t.Fatalf("directory permissions = %o, want %o", got, dirPerm)
	}
}

func TestFallbackKeyTightensExistingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), keyFileName)
	want := filledKey(0x29)
	if err := os.WriteFile(path, want[:], 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod setup: %v", err)
	}

	got, err := fallbackKeyWithReader(
		path,
		failingReader{err: errors.New("random reader should not be used")},
	)
	if err != nil {
		t.Fatalf("fallbackKeyWithReader: %v", err)
	}
	if got != want {
		t.Fatalf("fallback key = %x, want %x", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != filePerm {
		t.Fatalf("fallback key permissions = %o, want %o", got, filePerm)
	}
}

func TestFallbackKeyCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), keyFileName)
	want := filledKey(0x2f)
	if _, err := fallbackKeyWithReader(path, bytes.NewReader(want[:])); err != nil {
		t.Fatalf("fallbackKeyWithReader: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != filePerm {
		t.Fatalf("fallback key permissions = %o, want %o", got, filePerm)
	}
}

func TestSyncDirectoryRejectsMissingPath(t *testing.T) {
	if err := syncDirectory(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("syncDirectory accepted a missing path")
	}
}

func TestSaveReplacesPermissiveFileWithPrivateFile(t *testing.T) {
	dir := t.TempDir()
	store := &Store{dir: dir, key: filledKey(0x31), path: filepath.Join(dir, tokenFileName)}
	if err := store.Save(pkceflow.TokenState{AccessToken: "old"}); err != nil {
		t.Fatalf("initial Save: %v", err)
	}
	if err := os.Chmod(store.path, 0o644); err != nil {
		t.Fatalf("Chmod setup: %v", err)
	}

	if err := store.Save(pkceflow.TokenState{AccessToken: "new"}); err != nil {
		t.Fatalf("replacement Save: %v", err)
	}
	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != filePerm {
		t.Fatalf("token permissions = %o, want %o", got, filePerm)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.AccessToken != "new" {
		t.Fatalf("access token = %q, want new", got.AccessToken)
	}
}

func TestSaveFailurePreservesPreviousState(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permission failure is not reliable as root")
	}

	dir := t.TempDir()
	store := &Store{dir: dir, key: filledKey(0x47), path: filepath.Join(dir, tokenFileName)}
	if err := store.Save(pkceflow.TokenState{AccessToken: "old"}); err != nil {
		t.Fatalf("initial Save: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod read-only: %v", err)
	}
	defer os.Chmod(dir, dirPerm) //nolint:errcheck // restore t.TempDir cleanup access

	if err := store.Save(pkceflow.TokenState{AccessToken: "new"}); err == nil {
		t.Fatal("Save succeeded in a non-writable directory")
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		t.Fatalf("restore directory permissions: %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.AccessToken != "old" {
		t.Fatalf("access token after failed Save = %q, want old", got.AccessToken)
	}
}

func TestConcurrentSavesPublishCompleteStates(t *testing.T) {
	dir := t.TempDir()
	store := &Store{dir: dir, key: filledKey(0x55), path: filepath.Join(dir, tokenFileName)}
	if err := store.Save(completeState("seed")); err != nil {
		t.Fatalf("seed Save: %v", err)
	}

	const (
		writerCount = 4
		readerCount = 2
		rounds      = 10
	)
	start := make(chan struct{})
	done := make(chan struct{})
	errCh := make(chan error, 1)
	report := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	var readers sync.WaitGroup
	readers.Add(readerCount)
	for range readerCount {
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				state, err := store.Load()
				if err != nil {
					report(fmt.Errorf("Load: %w", err))
					continue
				}
				if state.AccessToken == "" ||
					state.AccessToken != state.RefreshToken ||
					state.AccessToken != state.IDToken {
					report(fmt.Errorf("observed incomplete state: %+v", state))
				}
			}
		}()
	}

	var writers sync.WaitGroup
	writers.Add(writerCount)
	for writer := range writerCount {
		go func(writer int) {
			defer writers.Done()
			<-start
			for round := range rounds {
				marker := fmt.Sprintf("writer-%d-round-%d", writer, round)
				if err := store.Save(completeState(marker)); err != nil {
					report(fmt.Errorf("Save(%q): %w", marker, err))
				}
			}
		}(writer)
	}

	close(start)
	writers.Wait()
	close(done)
	readers.Wait()
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

func completeState(marker string) pkceflow.TokenState {
	return pkceflow.TokenState{
		AccessToken:  marker,
		RefreshToken: marker,
		IDToken:      marker,
	}
}
