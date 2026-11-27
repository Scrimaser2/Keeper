package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testPassword = "vault-test-password"

func createTestVault(t testing.TB, data []byte) (string, string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	container := filepath.Join(root, "container")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file.bin"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Service{}).Create(CreateOptions{Source: source, Destination: container, Key: testPassword}); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(container, archiveName), filepath.Join(root, "restore")
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	want := bytes.Repeat([]byte("photo-vault-round-trip\x00"), 8192)
	collection, destination := createTestVault(t, want)
	if err := (Service{}).Restore(RestoreOptions{Collection: collection, Destination: destination, Key: testPassword}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(destination, "file.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("restored bytes do not match source")
	}
}

func TestEncryptedBlockCorruptionIsRejected(t *testing.T) {
	collection, _ := createTestVault(t, bytes.Repeat([]byte("x"), streamChunkSize+3))
	session, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	entry := session.Items()[0]
	_ = session.Close()
	file, err := os.OpenFile(collection, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	position := entry.Offset + 4 + nonceSize + 1
	if _, err := file.ReadAt(b[:], position); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0x80
	if _, err := file.WriteAt(b[:], position); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := (Service{}).OpenSession(collection, testPassword); err == nil {
		t.Fatal("corrupted ciphertext was accepted as a valid commit")
	}
}

func TestTruncatedSnapshotReturnsUnexpectedEOF(t *testing.T) {
	collection, _ := createTestVault(t, bytes.Repeat([]byte("truncate"), 2048))
	session, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	entry := session.Items()[0]
	reader, err := session.Open(entry.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := os.Truncate(collection, entry.Offset+2); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, reader); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected unexpected EOF after truncation, got %v", err)
	}
}

func TestTruncatedSnapshotAtChunkBoundaryReturnsUnexpectedEOF(t *testing.T) {
	collection, _ := createTestVault(t, bytes.Repeat([]byte("b"), 2*streamChunkSize))
	session, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	entry := session.Items()[0]
	reader, err := session.Open(entry.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := os.Truncate(collection, entry.Offset+encodedRecordSize(streamChunkSize)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, reader); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected unexpected EOF at encrypted block boundary, got %v", err)
	}
}

func TestSessionKeepsSnapshotAcrossWrite(t *testing.T) {
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "container")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("second-file"), 1024)
	if err := os.WriteFile(filepath.Join(source, "a.bin"), []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "b.bin"), want, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Service{}).Create(CreateOptions{Source: source, Destination: destination, Key: testPassword}); err != nil {
		t.Fatal(err)
	}
	collection := filepath.Join(destination, archiveName)
	session, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := (Service{}).Delete(collection, testPassword, "a.bin"); err != nil {
		t.Fatal(err)
	}
	newSession, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer newSession.Close()
	var oldOffset, newOffset int64
	for _, item := range session.Items() {
		if item.Name == "b.bin" {
			oldOffset = item.Offset
		}
	}
	for _, item := range newSession.Items() {
		if item.Name == "b.bin" {
			newOffset = item.Offset
		}
	}
	if oldOffset != newOffset {
		t.Fatalf("append-only deletion unexpectedly moved live data: old=%d new=%d", oldOffset, newOffset)
	}
	reader, err := session.Open("b.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("session did not retain its original snapshot")
	}
}

func TestRestoreFailurePreservesExistingFile(t *testing.T) {
	collection, destination := createTestVault(t, bytes.Repeat([]byte("secret"), 1024))
	if err := os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(destination, "file.bin")
	if err := os.WriteFile(target, []byte("keep-existing"), 0600); err != nil {
		t.Fatal(err)
	}
	session, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	entry := session.Items()[0]
	_ = session.Close()
	file, err := os.OpenFile(collection, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	position := entry.Offset + 4 + nonceSize + 1
	if _, err := file.ReadAt(b[:], position); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 1
	if _, err := file.WriteAt(b[:], position); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if err := (Service{}).Restore(RestoreOptions{Collection: collection, Destination: destination, Key: testPassword}); err == nil {
		t.Fatal("restore unexpectedly succeeded")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep-existing" {
		t.Fatalf("existing file was changed: %q", got)
	}
}

func TestConcurrentWriterProcessHelper(t *testing.T) {
	path := os.Getenv("PHOTOVAULT_TEST_WRITER_PATH")
	if path == "" {
		return
	}
	if _, err := (Service{}).AddTag(path, testPassword, os.Getenv("PHOTOVAULT_TEST_WRITER_TAG"), []string{"file.bin"}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentWritesFromProcesses(t *testing.T) {
	collection, _ := createTestVault(t, []byte("content"))
	children := make([]*exec.Cmd, 2)
	for i, tag := range []string{"process-one", "process-two"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestConcurrentWriterProcessHelper$")
		cmd.Env = append(os.Environ(), "PHOTOVAULT_TEST_WRITER_PATH="+collection, "PHOTOVAULT_TEST_WRITER_TAG="+tag)
		children[i] = cmd
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, cmd := range children {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("writer process failed: %v", err)
		}
	}
	session, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var names []string
	for _, tag := range session.Tags() {
		names = append(names, tag.Name)
	}
	for _, want := range []string{"process-one", "process-two"} {
		found := false
		for _, name := range names {
			if name == want {
				found = true
			}
		}
		if !found {
			t.Errorf("tag %q was lost to concurrent write", want)
		}
	}
}

func TestMigrationV1ToV2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.vault")
	want := []byte("legacy photo")
	data, err := encode(map[string][]byte{"old.jpg": want}, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	session, err := (Service{}).OpenSession(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := session.Open("old.jpg")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	_ = reader.Close()
	_ = session.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("migrated item contents differ")
	}
	current, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var magic [8]byte
	_, _ = io.ReadFull(current, magic[:])
	_ = current.Close()
	if string(magic[:]) != streamMagic {
		t.Fatalf("expected v2 magic, got %q", magic)
	}
	if _, err := os.Stat(path + ".legacy"); err != nil {
		t.Fatalf("legacy backup missing: %v", err)
	}
}

func TestPVLT0003AppendRecoversCommittedSnapshot(t *testing.T) {
	collection, _ := createTestVault(t, []byte("keep-me"))
	file, err := os.OpenFile(collection, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, first, err := readStreamV3IndexFile(file, testPassword)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("incomplete-transaction-tail")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	_ = file.Close()
	session, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	_ = session.Close()
	if _, err := (Service{}).CreateTag(collection, testPassword, "recovered"); err != nil {
		t.Fatal(err)
	}
	file, err = os.Open(collection)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	_, _, _, tags, second, err := readStreamV3IndexFile(file, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence != first.Sequence+1 || second.PreviousOffset != first.FooterOffset {
		t.Fatalf("commit chain did not advance correctly: first=%+v second=%+v", first, second)
	}
	if _, ok := findTagByName(tags, "recovered"); !ok {
		t.Fatal("new committed metadata was not recovered")
	}
}

func TestPVLT0003CompactionDropsDeletedPayload(t *testing.T) {
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "container")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	keep := bytes.Repeat([]byte("live"), 1024)
	dead := bytes.Repeat([]byte("deleted"), 1024)
	if err := os.WriteFile(filepath.Join(source, "a-dead.bin"), dead, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "b-live.bin"), keep, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Service{}).Create(CreateOptions{Source: source, Destination: destination, Key: testPassword}); err != nil {
		t.Fatal(err)
	}
	collection := filepath.Join(destination, archiveName)
	if err := (Service{}).Delete(collection, testPassword, "a-dead.bin"); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(collection)
	if err != nil {
		t.Fatal(err)
	}
	if err := (Service{}).Compact(collection, testPassword); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(collection)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() >= before.Size() {
		t.Fatalf("compaction did not reclaim space: before=%d after=%d", before.Size(), after.Size())
	}
	session, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if got := len(session.Items()); got != 1 {
		t.Fatalf("expected one live file after compaction, got %d", got)
	}
	reader, err := session.Open("b-live.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, keep) {
		t.Fatal("compaction changed live file contents")
	}
}

func TestPVLT0002UpgradesOnFirstMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.vault")
	data := []byte("old data")
	header, aead, err := newStreamCipher(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{Name: "old.bin", Size: int64(len(data)), Hash: hashString(data)}
	if err := writeInitialStream(path, header, aead, []Entry{entry}, nil, map[string]io.Reader{"old.bin": bytes.NewReader(data)}); err != nil {
		t.Fatal(err)
	}
	if err := (Service{}).Delete(path, testPassword, "old.bin"); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var magic [8]byte
	_, _ = io.ReadFull(file, magic[:])
	_ = file.Close()
	if string(magic[:]) != streamV3Magic {
		t.Fatalf("expected first mutation to upgrade to PVLT0003, got %q", magic)
	}
}

func TestChangePasswordRewrapsDEKWithoutRewritingPayload(t *testing.T) {
	want := bytes.Repeat([]byte("password rotation keeps payload"), 1024)
	collection, _ := createTestVault(t, want)
	session, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	before, err := os.Stat(collection)
	if err != nil {
		t.Fatal(err)
	}
	newPassword := "rotated-password"
	if err := (Service{}).ChangePassword(collection, testPassword, newPassword); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(collection)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() {
		t.Fatalf("password change altered container size: before=%d after=%d", before.Size(), after.Size())
	}
	if _, err := (Service{}).OpenSession(collection, testPassword); err == nil {
		t.Fatal("old password still opens the collection")
	}
	updated, err := (Service{}).OpenSession(collection, newPassword)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := updated.Open("file.bin")
	if err != nil {
		_ = updated.Close()
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	_ = reader.Close()
	_ = updated.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("password change modified encrypted payload")
	}
	oldReader, err := session.Open("file.bin")
	if err != nil {
		t.Fatal(err)
	}
	oldData, err := io.ReadAll(oldReader)
	_ = oldReader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldData, want) {
		t.Fatal("existing snapshot stopped working after password change")
	}
}

func TestChangePasswordMigratesPVLT0002(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.vault")
	want := []byte("keep this v2 payload")
	header, aead, err := newStreamCipher(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{Name: "old.bin", Size: int64(len(want)), Hash: hashString(want)}
	if err := writeInitialStream(path, header, aead, []Entry{entry}, nil, map[string]io.Reader{"old.bin": bytes.NewReader(want)}); err != nil {
		t.Fatal(err)
	}
	newPassword := "v3-password"
	if err := (Service{}).ChangePassword(path, testPassword, newPassword); err != nil {
		t.Fatal(err)
	}
	session, err := (Service{}).OpenSession(path, newPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	reader, err := session.Open("old.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("PVLT0002 migration changed file content")
	}
}

func TestChangePasswordMigratesDirectKeyPVLT0003WithoutReencryptingPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct-v3.vault")
	data := bytes.Repeat([]byte("legacy PVLT0003 payload"), 64)
	salt := bytes.Repeat([]byte{0x5a}, saltSize)
	var rounds [8]byte
	binary.BigEndian.PutUint64(rounds[:], iterations)
	header := append([]byte(streamV3Magic), salt...)
	header = append(header, rounds[:]...)
	aead, err := streamAEAD(testPassword, salt, iterations)
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{Name: "legacy.bin", Size: int64(len(data)), Hash: hashString(data)}
	if err := createStreamV3Atomically(path, header, aead, []Entry{entry}, nil, map[string]io.Reader{"legacy.bin": bytes.NewReader(data)}); err != nil {
		t.Fatal(err)
	}
	legacy, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, legacyEntries, _, _, err := readStreamV3IndexFile(legacy, testPassword)
	if err != nil {
		_ = legacy.Close()
		t.Fatal(err)
	}
	oldRecord := make([]byte, encodedRecordSize(entry.Size))
	if _, err := legacy.ReadAt(oldRecord, legacyEntries[0].Offset); err != nil {
		_ = legacy.Close()
		t.Fatal(err)
	}
	_ = legacy.Close()

	newPassword := "wrapped-v3-password"
	if err := (Service{}).ChangePassword(path, testPassword, newPassword); err != nil {
		t.Fatal(err)
	}
	migrated, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, entries, _, _, err := readStreamV3IndexFile(migrated, newPassword)
	if err != nil {
		_ = migrated.Close()
		t.Fatal(err)
	}
	newRecord := make([]byte, encodedRecordSize(entries[0].Size))
	if _, err := migrated.ReadAt(newRecord, entries[0].Offset); err != nil {
		_ = migrated.Close()
		t.Fatal(err)
	}
	_ = migrated.Close()
	if !bytes.Equal(oldRecord, newRecord) {
		t.Fatal("PVLT0003 migration re-encrypted the existing payload")
	}
}

func TestPVLT0003AppendImportKeepsExistingPayloadOffset(t *testing.T) {
	collection, _ := createTestVault(t, []byte("already stored"))
	before, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	oldOffset := before.Items()[0].Offset
	_ = before.Close()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "new.bin"), []byte("append me"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Service{}).Create(CreateOptions{Source: source, Destination: filepath.Dir(collection), Key: testPassword}); err != nil {
		t.Fatal(err)
	}
	after, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	var gotOffset int64
	for _, item := range after.Items() {
		if item.Name == "file.bin" {
			gotOffset = item.Offset
		}
	}
	if gotOffset != oldOffset {
		t.Fatalf("existing payload moved during append: before=%d after=%d", oldOffset, gotOffset)
	}
	reader, err := after.Open("new.bin")
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
}

func TestPVLT0003RejectsCorruptCompleteTransaction(t *testing.T) {
	collection, _ := createTestVault(t, []byte("first committed object"))
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "new.bin"), []byte("second transaction payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Service{}).Create(CreateOptions{Source: source, Destination: filepath.Dir(collection), Key: testPassword}); err != nil {
		t.Fatal(err)
	}
	session, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	var entry Entry
	for _, item := range session.Items() {
		if item.Name == "new.bin" {
			entry = item
		}
	}
	_ = session.Close()
	file, err := os.OpenFile(collection, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	position := entry.Offset + 4 + nonceSize + 1
	if _, err := file.ReadAt(b[:], position); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	b[0] ^= 0x40
	if _, err := file.WriteAt(b[:], position); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	_ = file.Close()
	if _, err := (Service{}).OpenSession(collection, testPassword); err == nil || !strings.Contains(err.Error(), "corrupt PVLT0003 commit") {
		t.Fatalf("expected a hard error for a complete corrupt commit, got %v", err)
	}
}

func TestEntryCountLimitIsSymmetric(t *testing.T) {
	entries := make([]Entry, maxEntries+1)
	output, err := os.CreateTemp(t.TempDir(), "index-limit-*")
	if err != nil {
		t.Fatal(err)
	}
	err = writeStreamIndex(output, nil, nil, entries, nil)
	_ = output.Close()
	if err == nil || !strings.Contains(err.Error(), "too many items") {
		t.Fatalf("writer should reject %d entries, got %v", len(entries), err)
	}
	if err := appendStreamV3Contents(output, nil, nil, nil, entries, nil, nil, streamV3Commit{}); err == nil || !strings.Contains(err.Error(), "too many items") {
		t.Fatalf("PVLT0003 writer should reject %d entries, got %v", len(entries), err)
	}
	plain, err := json.Marshal(streamManifest{Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseStreamManifest(plain, 1<<30); err == nil || !strings.Contains(err.Error(), "too many items") {
		t.Fatalf("reader should reject %d entries, got %v", len(entries), err)
	}
}

func TestImport100000FilesLoad(t *testing.T) {
	if os.Getenv("PHOTOVAULT_LOAD_TEST") != "1" {
		t.Skip("set PHOTOVAULT_LOAD_TEST=1 to run the 100,000-file import")
	}
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "container")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100_000; i++ {
		name := filepath.Join(source, fmt.Sprintf("%06d.bin", i))
		if err := os.WriteFile(name, []byte(fmt.Sprintf("%06d", i)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (Service{}).Create(CreateOptions{Source: source, Destination: destination, Key: testPassword}); err != nil {
		t.Fatal(err)
	}
	session, err := (Service{}).OpenSession(filepath.Join(destination, archiveName), testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if got := len(session.Items()); got != 100_000 {
		t.Fatalf("expected 100000 items, got %d", got)
	}
}

func FuzzLegacyVaultDecoder(f *testing.F) {
	f.Add([]byte(""), "key")
	f.Add([]byte(magic), "key")
	f.Fuzz(func(t *testing.T, data []byte, key string) {
		if len(data) > 2<<20 || len(key) > 4096 {
			t.Skip()
		}
		_, _ = decode(data, key)
	})
}

func FuzzStreamIndexParser(f *testing.F) {
	header, aead, err := newStreamCipher("fuzz-key")
	if err != nil {
		f.Fatal(err)
	}
	seedPath := filepath.Join(f.TempDir(), "seed.vault")
	if err := writeInitialStream(seedPath, header, aead, nil, nil, nil); err != nil {
		f.Fatal(err)
	}
	seed, err := os.ReadFile(seedPath)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(streamMagic))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 20<<20 {
			t.Skip()
		}
		path := filepath.Join(t.TempDir(), "fuzz.vault")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, _, _ = readStreamIndexFile(file, "fuzz-key")
		_ = file.Close()
	})
}

func FuzzStreamV3CommitParser(f *testing.F) {
	header, aead, err := newStreamV3Cipher("fuzz-key")
	if err != nil {
		f.Fatal(err)
	}
	seedPath := filepath.Join(f.TempDir(), "seed-v3.vault")
	if err := createStreamV3Atomically(seedPath, header, aead, nil, nil, nil); err != nil {
		f.Fatal(err)
	}
	seed, err := os.ReadFile(seedPath)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(streamV3Magic))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 20<<20 {
			t.Skip()
		}
		path := filepath.Join(t.TempDir(), "fuzz-v3.vault")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, _, _, _ = readStreamV3IndexFile(file, "fuzz-key")
		_ = file.Close()
	})
}

func FuzzDecryptedStreamManifest(f *testing.F) {
	seed, err := json.Marshal(streamManifest{Entries: []Entry{{Name: "photo.jpg", Size: 0, Hash: strings.Repeat("0", 64), Offset: streamHeaderSize}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed, int64(streamHeaderSize+128))
	f.Add([]byte("{}"), int64(0))
	f.Fuzz(func(t *testing.T, plain []byte, indexOffset int64) {
		if len(plain) > maxIndexSize || indexOffset < 0 {
			t.Skip()
		}
		_, _, _ = parseStreamManifest(plain, indexOffset)
	})
}

// BenchmarkStreamReadSampledHeap samples Go HeapAlloc; it does not measure process RSS.
func BenchmarkStreamReadSampledHeap(b *testing.B) {
	root := b.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "container")
	if err := os.Mkdir(source, 0700); err != nil {
		b.Fatal(err)
	}
	content := bytes.Repeat([]byte("memory-benchmark"), (8<<20)/16)
	if err := os.WriteFile(filepath.Join(source, "payload.bin"), content, 0600); err != nil {
		b.Fatal(err)
	}
	if _, err := (Service{}).Create(CreateOptions{Source: source, Destination: destination, Key: testPassword}); err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(destination, archiveName)
	b.ReportAllocs()
	b.ReportMetric(0, "sampled-heap-delta-B")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before, sample runtime.MemStats
		runtime.ReadMemStats(&before)
		peak := before.HeapAlloc
		session, err := (Service{}).OpenSession(path, testPassword)
		if err != nil {
			b.Fatal(err)
		}
		reader, err := session.Open("payload.bin")
		if err != nil {
			b.Fatal(err)
		}
		buffer := make([]byte, streamChunkSize/4)
		for {
			_, readErr := reader.Read(buffer)
			runtime.ReadMemStats(&sample)
			if sample.HeapAlloc > peak {
				peak = sample.HeapAlloc
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				b.Fatal(readErr)
			}
		}
		b.ReportMetric(float64(peak-before.HeapAlloc), "sampled-heap-delta-B")
		_ = reader.Close()
		_ = session.Close()
	}
}

func TestRestoreRejectsSHA256Mismatch(t *testing.T) {
	collection, destination := createTestVault(t, []byte("hash-me"))
	if err := os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(destination, "file.bin")
	if err := os.WriteFile(target, []byte("keep-existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := rewriteV3ManifestHashForTest(collection, testPassword, "file.bin", strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if err := (Service{}).Restore(RestoreOptions{Collection: collection, Destination: destination, Key: testPassword}); err == nil {
		t.Fatal("restore accepted a validly encrypted index with a wrong item hash")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep-existing" {
		t.Fatalf("existing file changed: %q", got)
	}
}

func rewriteV3ManifestHashForTest(path, password, name, replacement string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	header, aead, entries, tags, commit, err := readStreamV3IndexFile(file, password)
	if err != nil {
		return err
	}
	for i := range entries {
		if entries[i].Name == name {
			entries[i].Hash = replacement
		}
	}
	start := int64(streamHeaderSize)
	previousHash := ""
	if commit.Sequence > 1 {
		start = commit.PreviousOffset + streamV3FooterSize
		previous := sha256.Sum256(commit.Footer[:])
		previousHash = hex.EncodeToString(previous[:])
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.NewSectionReader(file, start, commit.IndexOffset-start)); err != nil {
		return err
	}
	plain, err := json.Marshal(streamV3Manifest{Sequence: commit.Sequence, PreviousCommit: commit.PreviousOffset, PreviousCommitHash: previousHash, TransactionDigest: hex.EncodeToString(digest.Sum(nil)), Entries: entries, Tags: tags})
	if err != nil {
		return err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nil, nonce, plain, header)
	block := append(nonce, sealed...)
	if int64(len(block)) != commit.IndexLength {
		return errors.New("test mutation changed index length")
	}
	if _, err := file.WriteAt(block, commit.IndexOffset); err != nil {
		return err
	}
	return file.Sync()
}
