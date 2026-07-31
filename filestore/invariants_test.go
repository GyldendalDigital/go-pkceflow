package filestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
)

func TestNewRejectsBlankAppIDWithoutCreatingDirectory(t *testing.T) {
	for _, appID := range []string{"", " \t\n"} {
		t.Run(appID, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "store")
			if _, err := New(appID, dir); err == nil {
				t.Fatal("New accepted a blank app ID")
			}
			if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("store directory was created before validation: %v", err)
			}
		})
	}
}

func TestNewRejectsFileAsStoreDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store")
	if err := os.WriteFile(path, []byte("not a directory"), filePerm); err != nil {
		t.Fatalf("write store path: %v", err)
	}
	if _, err := New("test-app", path); err == nil {
		t.Fatal("New accepted a file as the store directory")
	}
}

func TestDeriveKeyWithSourcesUsesMachineID(t *testing.T) {
	want := sha256.Sum256([]byte("test-app:machine-123"))
	got, err := deriveKeyWithSources(
		"test-app",
		t.TempDir(),
		func() (string, error) { return "machine-123", nil },
		failingReader{err: errors.New("random reader should not be used")},
	)
	if err != nil {
		t.Fatalf("deriveKeyWithSources: %v", err)
	}
	if got != want {
		t.Fatalf("derived key = %x, want %x", got, want)
	}
}

func TestDeriveKeyWithSourcesUsesFallback(t *testing.T) {
	tests := []struct {
		name      string
		machineID func() (string, error)
	}{
		{
			name:      "machine ID error",
			machineID: func() (string, error) { return "", errors.New("unavailable") },
		},
		{
			name:      "empty machine ID",
			machineID: func() (string, error) { return "", nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			want := filledKey(0x42)
			got, err := deriveKeyWithSources(
				"test-app",
				dir,
				tt.machineID,
				bytes.NewReader(want[:]),
			)
			if err != nil {
				t.Fatalf("deriveKeyWithSources: %v", err)
			}
			if got != want {
				t.Fatalf("fallback key = %x, want %x", got, want)
			}
			assertFileBytes(t, filepath.Join(dir, keyFileName), want[:])
		})
	}
}

func TestFallbackKeyCreatesAndReusesKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), keyFileName)
	want := filledKey(0x2a)

	created, err := fallbackKeyWithReader(path, bytes.NewReader(want[:]))
	if err != nil {
		t.Fatalf("create fallback key: %v", err)
	}
	if created != want {
		t.Fatalf("created key = %x, want %x", created, want)
	}

	reused, err := fallbackKeyWithReader(
		path,
		failingReader{err: errors.New("random reader should not be used")},
	)
	if err != nil {
		t.Fatalf("reuse fallback key: %v", err)
	}
	if reused != want {
		t.Fatalf("reused key = %x, want %x", reused, want)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat fallback key: %v", err)
	}
	if !info.Mode().IsRegular() || info.Size() != keySize {
		t.Fatalf("fallback key info = mode %v size %d", info.Mode(), info.Size())
	}
	assertOnlyDirectoryEntry(t, filepath.Dir(path), keyFileName)
}

func TestFallbackKeyRandomFailureLeavesNoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), keyFileName)
	wantErr := errors.New("entropy unavailable")
	if _, err := fallbackKeyWithReader(path, failingReader{err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("fallbackKeyWithReader error = %v, want %v", err, wantErr)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fallback key exists after random failure: %v", err)
	}
}

func TestFallbackKeyReturnsPublicationFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", keyFileName)
	if _, err := fallbackKeyWithReader(path, bytes.NewReader(make([]byte, keySize))); err == nil {
		t.Fatal("fallbackKeyWithReader succeeded with a missing parent directory")
	}
}

func TestFallbackKeyMalformedFileReturnsErrorWithoutReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, keyFileName)
	want := []byte("too-short")
	if err := os.WriteFile(path, want, filePerm); err != nil {
		t.Fatalf("write malformed key: %v", err)
	}

	candidate := filledKey(0x33)
	if _, err := deriveKeyWithSources(
		"test-app",
		dir,
		func() (string, error) { return "", errors.New("unavailable") },
		bytes.NewReader(candidate[:]),
	); err == nil {
		t.Fatal("deriveKeyWithSources replaced a malformed fallback key")
	}
	assertFileBytes(t, path, want)
}

func TestFallbackKeyRejectsNonRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), keyFileName)
	if err := os.Mkdir(path, dirPerm); err != nil {
		t.Fatalf("create key directory: %v", err)
	}
	if _, err := fallbackKeyWithReader(path, bytes.NewReader(make([]byte, keySize))); err == nil {
		t.Fatal("fallbackKeyWithReader accepted a directory")
	}
}

func TestFallbackKeyRejectsSymlinkWithoutTouchingTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, keyFileName)
	want := bytes.Repeat([]byte{0x61}, keySize)
	if err := os.WriteFile(target, want, filePerm); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}

	if _, err := fallbackKeyWithReader(link, bytes.NewReader(make([]byte, keySize))); err == nil {
		t.Fatal("fallbackKeyWithReader accepted a symlink")
	}
	assertFileBytes(t, target, want)
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("Lstat link: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("fallback key symlink was replaced")
	}
}

func TestFallbackKeyConcurrentCreationPublishesSingleKey(t *testing.T) {
	for attempt := 0; attempt < 25; attempt++ {
		path := filepath.Join(t.TempDir(), keyFileName)
		var ready sync.WaitGroup
		ready.Add(2)
		release := make(chan struct{})
		results := make(chan fallbackResult, 2)

		for _, fill := range []byte{0x11, 0x77} {
			go func(fill byte) {
				key, err := fallbackKeyWithReader(path, &gatedFillReader{
					fill:    fill,
					ready:   &ready,
					release: release,
				})
				results <- fallbackResult{key: key, err: err}
			}(fill)
		}

		ready.Wait()
		close(release)
		first := <-results
		second := <-results
		if first.err != nil || second.err != nil {
			t.Fatalf("attempt %d errors = %v, %v", attempt, first.err, second.err)
		}
		if first.key != second.key {
			t.Fatalf("attempt %d returned different keys: %x != %x", attempt, first.key, second.key)
		}
		if first.key != filledKey(0x11) && first.key != filledKey(0x77) {
			t.Fatalf("attempt %d published unexpected key %x", attempt, first.key)
		}
		assertFileBytes(t, path, first.key[:])
		assertOnlyDirectoryEntry(t, filepath.Dir(path), keyFileName)
	}
}

func TestFallbackKeyLateReaderSyncsVisiblePublication(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, keyFileName)
	want := filledKey(0x5a)
	publisherAtSync := make(chan struct{})
	releasePublisher := make(chan struct{})
	publisherDone := make(chan error, 1)
	go func() {
		publisherDone <- publishFallbackKeyWithSync(path, want, func(gotDir string) error {
			if gotDir != dir {
				return fmt.Errorf("publisher sync directory = %q, want %q", gotDir, dir)
			}
			close(publisherAtSync)
			<-releasePublisher
			return nil
		})
	}()

	<-publisherAtSync
	readerAtSync := make(chan struct{})
	releaseReader := make(chan struct{})
	readerDone := make(chan fallbackResult, 1)
	go func() {
		key, err := fallbackKeyWithReaderAndSync(
			path,
			failingReader{err: errors.New("random reader should not be used")},
			func(gotDir string) error {
				if gotDir != dir {
					return fmt.Errorf("reader sync directory = %q, want %q", gotDir, dir)
				}
				close(readerAtSync)
				<-releaseReader
				return nil
			},
		)
		readerDone <- fallbackResult{key: key, err: err}
	}()

	<-readerAtSync
	select {
	case result := <-readerDone:
		t.Fatalf("late reader returned before directory sync: %+v", result)
	default:
	}
	close(releaseReader)
	result := <-readerDone
	if result.err != nil {
		t.Fatalf("late reader: %v", result.err)
	}
	if result.key != want {
		t.Fatalf("late reader key = %x, want %x", result.key, want)
	}

	close(releasePublisher)
	if err := <-publisherDone; err != nil {
		t.Fatalf("publisher: %v", err)
	}
}

func TestFallbackKeyExistingSyncFailureIsReturned(t *testing.T) {
	path := filepath.Join(t.TempDir(), keyFileName)
	want := filledKey(0x6b)
	if err := os.WriteFile(path, want[:], filePerm); err != nil {
		t.Fatalf("write fallback key: %v", err)
	}

	wantErr := errors.New("sync failed")
	_, err := fallbackKeyWithReaderAndSync(
		path,
		failingReader{err: errors.New("random reader should not be used")},
		func(string) error { return wantErr },
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("fallbackKeyWithReaderAndSync error = %v, want %v", err, wantErr)
	}
}

func TestPublishFallbackKeySyncFailureLeavesCompleteKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, keyFileName)
	want := filledKey(0x7c)
	wantErr := errors.New("sync failed")
	err := publishFallbackKeyWithSync(path, want, func(string) error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("publishFallbackKeyWithSync error = %v, want %v", err, wantErr)
	}
	assertFileBytes(t, path, want[:])
	assertOnlyDirectoryEntry(t, dir, keyFileName)
}

func TestLoadCorruptionThenSaveRecovers(t *testing.T) {
	want := pkceflow.TokenState{
		AccessToken:  "access-new",
		RefreshToken: "refresh-new",
		IDToken:      "id-new",
		ExpiresAt:    time.Unix(2_000_000_000, 0).UTC(),
		LastAuthAt:   time.Unix(1_999_999_000, 0).UTC(),
	}
	plaintext, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	key := filledKey(0x15)
	otherKey := filledKey(0x51)
	validCiphertext, err := encrypt(key[:], plaintext)
	if err != nil {
		t.Fatalf("encrypt fixture: %v", err)
	}
	damagedCiphertext := append([]byte(nil), validCiphertext...)
	damagedCiphertext[len(damagedCiphertext)-1] ^= 0xff
	wrongKeyCiphertext, err := encrypt(otherKey[:], plaintext)
	if err != nil {
		t.Fatalf("encrypt wrong-key fixture: %v", err)
	}
	invalidJSONCiphertext, err := encrypt(key[:], []byte("{"))
	if err != nil {
		t.Fatalf("encrypt invalid-JSON fixture: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{name: "too short", data: []byte{1}},
		{name: "damaged GCM", data: damagedCiphertext},
		{name: "different key", data: wrongKeyCiphertext},
		{name: "authenticated invalid JSON", data: invalidJSONCiphertext},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			store := &Store{
				dir:  dir,
				key:  key,
				path: filepath.Join(dir, tokenFileName),
			}
			if err := os.WriteFile(store.path, tt.data, filePerm); err != nil {
				t.Fatalf("write bad token file: %v", err)
			}

			got, err := store.Load()
			if err != nil {
				t.Fatalf("Load bad state: %v", err)
			}
			if !got.IsZero() {
				t.Fatalf("Load bad state = %+v, want zero", got)
			}

			if err := store.Save(want); err != nil {
				t.Fatalf("Save recovery state: %v", err)
			}
			got, err = store.Load()
			if err != nil {
				t.Fatalf("Load recovery state: %v", err)
			}
			assertTokenState(t, &got, &want)
		})
	}
}

func TestCryptoHelpersRejectInvalidInputs(t *testing.T) {
	if _, err := encrypt(make([]byte, keySize-1), nil); err == nil {
		t.Fatal("encrypt accepted a short key")
	}
	if _, err := decrypt(make([]byte, keySize-1), nil); err == nil {
		t.Fatal("decrypt accepted a short key")
	}
	if _, err := decrypt(make([]byte, keySize), make([]byte, 1)); err == nil {
		t.Fatal("decrypt accepted ciphertext shorter than the nonce")
	}
}

func TestLoadTreatsNonFilePathAsMissingState(t *testing.T) {
	dir := t.TempDir()
	store := &Store{dir: dir, key: filledKey(0x19), path: filepath.Join(dir, tokenFileName)}
	if err := os.Mkdir(store.path, dirPerm); err != nil {
		t.Fatalf("create token directory: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !got.IsZero() {
		t.Fatalf("Load non-file path = %+v, want zero state", got)
	}
}

func TestDeleteReturnsFilesystemError(t *testing.T) {
	dir := t.TempDir()
	store := &Store{dir: dir, key: filledKey(0x28), path: filepath.Join(dir, tokenFileName)}
	if err := os.Mkdir(store.path, dirPerm); err != nil {
		t.Fatalf("create token directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store.path, "child"), nil, filePerm); err != nil {
		t.Fatalf("write child: %v", err)
	}

	if err := store.Delete(); err == nil {
		t.Fatal("Delete removed a non-empty directory")
	}
}

func TestPrivateFileHelpersReturnFilesystemErrors(t *testing.T) {
	t.Run("secure missing path", func(t *testing.T) {
		if err := securePath(filepath.Join(t.TempDir(), "missing"), dirPerm); err == nil {
			t.Fatal("securePath accepted a missing path")
		}
	})

	t.Run("secure closed file", func(t *testing.T) {
		file, err := os.CreateTemp(t.TempDir(), "closed-*")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := secureFile(file, filePerm); err == nil {
			t.Fatal("secureFile accepted a closed file")
		}
	})

	t.Run("remove non-empty directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "staged")
		if err := os.Mkdir(dir, dirPerm); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "child"), nil, filePerm); err != nil {
			t.Fatalf("write child: %v", err)
		}
		if err := removeStagedFile(dir); err == nil {
			t.Fatal("removeStagedFile removed a non-empty directory")
		}
	})
}

func TestSaveRejectsDestinationDirectoryAndCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, tokenFileName)
	if err := os.Mkdir(path, dirPerm); err != nil {
		t.Fatalf("create destination directory: %v", err)
	}
	store := &Store{dir: dir, key: filledKey(0x23), path: path}
	if err := store.Save(pkceflow.TokenState{AccessToken: "access"}); err == nil {
		t.Fatal("Save replaced a destination directory")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != tokenFileName || !entries[0].IsDir() {
		t.Fatalf("unexpected files after failed Save: %+v", entries)
	}
}

func TestWritePrivateFileAtomicRenameFailurePreservesPreviousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, tokenFileName)
	want := []byte("previous-complete-file")
	if err := os.WriteFile(path, want, filePerm); err != nil {
		t.Fatalf("write previous file: %v", err)
	}
	wantErr := errors.New("rename failed")
	err := writePrivateFileAtomicWith(path, []byte("replacement"), func(string, string) error {
		return wantErr
	}, syncDirectory)
	if !errors.Is(err, wantErr) {
		t.Fatalf("writePrivateFileAtomicWith error = %v, want %v", err, wantErr)
	}
	assertFileBytes(t, path, want)
	assertOnlyDirectoryEntry(t, dir, tokenFileName)
}

func TestWritePrivateFileAtomicSyncFailureReturnsPublishedState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, tokenFileName)
	want := []byte("complete-replacement")
	wantErr := errors.New("sync failed")
	err := writePrivateFileAtomicWith(path, want, os.Rename, func(string) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("writePrivateFileAtomicWith error = %v, want %v", err, wantErr)
	}
	assertFileBytes(t, path, want)
	assertOnlyDirectoryEntry(t, dir, tokenFileName)
}

func TestSaveDoesNotFollowTokenSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, tokenFileName)
	wantTarget := []byte("do-not-touch")
	if err := os.WriteFile(target, wantTarget, filePerm); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}

	store := &Store{dir: dir, key: filledKey(0x39), path: path}
	if err := store.Save(pkceflow.TokenState{AccessToken: "access"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	assertFileBytes(t, target, wantTarget)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat token path: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("token path mode = %v, want regular file", info.Mode())
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.AccessToken != "access" {
		t.Fatalf("access token = %q, want access", got.AccessToken)
	}
}

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

type gatedFillReader struct {
	fill    byte
	ready   *sync.WaitGroup
	release <-chan struct{}
	once    sync.Once
}

func (r *gatedFillReader) Read(p []byte) (int, error) {
	r.once.Do(r.ready.Done)
	<-r.release
	for i := range p {
		p[i] = r.fill
	}
	return len(p), nil
}

type fallbackResult struct {
	key [32]byte
	err error
}

func filledKey(fill byte) [32]byte {
	var key [32]byte
	for i := range key {
		key[i] = fill
	}
	return key
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path) //nolint:gosec // test path is rooted in t.TempDir
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file %q = %x, want %x", path, got, want)
	}
}

func assertOnlyDirectoryEntry(t *testing.T, dir, want string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != want {
		t.Fatalf("directory %q entries = %v, want only %q", dir, entries, want)
	}
}

func assertTokenState(t *testing.T, got, want *pkceflow.TokenState) {
	t.Helper()
	if got.AccessToken != want.AccessToken ||
		got.RefreshToken != want.RefreshToken ||
		got.IDToken != want.IDToken ||
		!got.ExpiresAt.Equal(want.ExpiresAt) ||
		!got.LastAuthAt.Equal(want.LastAuthAt) {
		t.Fatalf("token state = %+v, want %+v", got, want)
	}
}

var _ io.Reader = (*gatedFillReader)(nil)
