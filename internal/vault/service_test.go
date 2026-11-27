package vault

import (
	"bytes"
	"encoding/binary"
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
	session, err = (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	reader, err := session.Open("file.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := io.Copy(io.Discard, reader); err == nil {
		t.Fatal("corrupted ciphertext was accepted")
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
	oldItems := session.Items()
	newSession, err := (Service{}).OpenSession(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer newSession.Close()
	var oldOffset, newOffset int64
	for _, item := range oldItems {
		if item.Name == "b.bin" {
			oldOffset = item.Offset
		}
	}
	for _, item := range newSession.Items() {
		if item.Name == "b.bin" {
			newOffset = item.Offset
		}
	}
	if oldOffset == newOffset {
		t.Fatalf("test setup did not move the second file: old=%d new=%d", oldOffset, newOffset)
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

func BenchmarkStreamReadMemory(b *testing.B) {
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
	b.ReportMetric(0, "peak-heap-B")
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
		b.ReportMetric(float64(peak-before.HeapAlloc), "peak-heap-B")
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
	header, aead, entries, tags, err := readStreamIndex(collection, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	entries[0].Hash = strings.Repeat("0", 64)
	file, err := os.OpenFile(collection, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	var trailer [streamTrailerSize]byte
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.ReadAt(trailer[:], info.Size()-streamTrailerSize); err != nil {
		t.Fatal(err)
	}
	indexOffset := int64(binary.BigEndian.Uint64(trailer[8:16]))
	if err := file.Truncate(indexOffset); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(indexOffset, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := writeStreamIndex(file, header, aead, entries, tags); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
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
