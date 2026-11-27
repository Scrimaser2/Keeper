package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	streamMagic       = "PVLT0002"
	streamIndexMagic  = "PVLIDX02"
	streamChunkSize   = 1 << 20
	streamHeaderSize  = 8 + saltSize + 8
	streamTrailerSize = 8 + 8 + 8
	streamRecordOver  = 4 + nonceSize + 16
	maxIndexSize      = 16 << 20
	maxLegacySize     = 128 << 20
)

// Entry describes one item without loading its contents into memory.
type Entry struct {
	Name   string   `json:"name"`
	Size   int64    `json:"size"`
	Hash   string   `json:"sha256"`
	Offset int64    `json:"offset"`
	Tags   []string `json:"tags,omitempty"`
}

type streamManifest struct {
	Entries []Entry `json:"entries"`
	Tags    []Tag   `json:"tags,omitempty"`
}

// Session keeps only the encrypted container index and derived key in memory.
// Entry contents are authenticated and decrypted one 1 MiB block at a time.
type Session struct {
	path    string
	file    *os.File
	header  []byte
	aead    cipher.AEAD
	entries []Entry
	tags    []Tag
	byName  map[string]Entry
	mu      sync.RWMutex
	closed  bool
	readers int
}

func (service Service) OpenSession(path, password string) (*Session, error) {
	unlock, err := lockCollection(path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := ensureStreamFormatLocked(path, password); err != nil {
		return nil, err
	}
	file, err := openSnapshotFile(path)
	if err != nil {
		return nil, err
	}
	header, aead, entries, tags, err := readStreamIndexFile(file, password)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	session := &Session{path: path, file: file, header: header, aead: aead, entries: entries, tags: tags, byName: make(map[string]Entry, len(entries))}
	for _, entry := range entries {
		session.byName[entry.Name] = entry
	}
	return session, nil
}

func (session *Session) Path() string { return session.path }

func (session *Session) Items() []Entry {
	session.mu.RLock()
	defer session.mu.RUnlock()
	items := make([]Entry, len(session.entries))
	for i, entry := range session.entries {
		items[i] = entry
		items[i].Tags = append([]string(nil), entry.Tags...)
	}
	return items
}

func (session *Session) Tags() []Tag {
	session.mu.RLock()
	defer session.mu.RUnlock()
	tags := make([]Tag, len(session.tags))
	for i, tag := range session.tags {
		tags[i] = tag
		tags[i].Image = append([]byte(nil), tag.Image...)
	}
	return tags
}

func (session *Session) Open(name string) (io.ReadCloser, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil, errors.New("collection session is closed")
	}
	entry, exists := session.byName[name]
	if !exists {
		return nil, errors.New("item no longer exists in the collection")
	}
	section := io.NewSectionReader(session.file, entry.Offset, encodedRecordSize(entry.Size))
	session.readers++
	return &entryReader{source: section, aead: session.aead, entry: entry, remaining: entry.Size, release: session.releaseReader}, nil
}

func (session *Session) Close() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil
	}
	session.closed = true
	for i := range session.header {
		session.header[i] = 0
	}
	session.header = nil
	session.aead = nil
	session.entries = nil
	session.tags = nil
	session.byName = nil
	if session.file != nil && session.readers == 0 {
		err := session.file.Close()
		session.file = nil
		return err
	}
	return nil
}

func (session *Session) releaseReader() {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.readers--
	if session.closed && session.readers == 0 && session.file != nil {
		_ = session.file.Close()
		session.file = nil
	}
}

type entryReader struct {
	source    io.Reader
	aead      cipher.AEAD
	entry     Entry
	remaining int64
	chunk     uint64
	buffer    []byte
	offset    int64
	closed    bool
	release   func()
}

func (reader *entryReader) Read(output []byte) (int, error) {
	if reader.closed {
		return 0, os.ErrClosed
	}
	if len(output) == 0 {
		return 0, nil
	}
	if len(reader.buffer) == 0 {
		if reader.remaining == 0 {
			return 0, io.EOF
		}
		if err := reader.loadChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(output, reader.buffer)
	reader.buffer = reader.buffer[n:]
	return n, nil
}

func (reader *entryReader) loadChunk() error {
	var sizeBytes [4]byte
	if _, err := io.ReadFull(reader.source, sizeBytes[:]); err != nil {
		return asUnexpectedEOF(err)
	}
	chunkSize := int64(binary.BigEndian.Uint32(sizeBytes[:]))
	expected := int64(streamChunkSize)
	if reader.remaining < expected {
		expected = reader.remaining
	}
	if chunkSize <= 0 || chunkSize != expected {
		return errors.New("invalid encrypted item block size")
	}
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(reader.source, nonce[:]); err != nil {
		return asUnexpectedEOF(err)
	}
	ciphertext := make([]byte, int(chunkSize)+reader.aead.Overhead())
	if _, err := io.ReadFull(reader.source, ciphertext); err != nil {
		return asUnexpectedEOF(err)
	}
	plain, err := reader.aead.Open(nil, nonce[:], ciphertext, chunkAAD(reader.entry.Name, reader.chunk, reader.entry.Size))
	if err != nil {
		return errors.New("encrypted item block failed authentication")
	}
	reader.remaining -= chunkSize
	reader.chunk++
	reader.offset += chunkSize
	reader.buffer = plain
	return nil
}

func asUnexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

func (reader *entryReader) Close() error {
	if reader.closed {
		return nil
	}
	reader.closed = true
	for i := range reader.buffer {
		reader.buffer[i] = 0
	}
	reader.buffer = nil
	reader.aead = nil
	reader.source = nil
	if reader.release != nil {
		reader.release()
		reader.release = nil
	}
	return nil
}

func ensureStreamFormat(path, password string) error {
	unlock, err := lockCollection(path)
	if err != nil {
		return err
	}
	defer unlock()
	return ensureStreamFormatLocked(path, password)
}

func ensureStreamFormatLocked(path, password string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	var magicBytes [8]byte
	_, readErr := io.ReadFull(file, magicBytes[:])
	_ = file.Close()
	if readErr != nil {
		return readErr
	}
	if string(magicBytes[:]) == streamMagic {
		return nil
	}
	if string(magicBytes[:]) != magic {
		return errors.New("not a supported vault file")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() > maxLegacySize {
		return fmt.Errorf("legacy collection is too large for safe migration (%d MiB limit); original file was left unchanged", maxLegacySize>>20)
	}
	files, err := readRawCollection(path, password)
	if err != nil {
		return err
	}
	metadata, err := decodeMetadata(files)
	if err != nil {
		return err
	}
	delete(files, metadataPath)
	entries := make([]Entry, 0, len(files))
	for name, data := range files {
		entries = append(entries, Entry{Name: name, Size: int64(len(data)), Hash: hashString(data), Tags: append([]string(nil), metadata.Tags[name]...)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	header, aead, err := newStreamCipher(password)
	if err != nil {
		return err
	}
	sources := make(map[string]io.Reader, len(files))
	tagCatalog := makeTagCatalog(metadata.TagCatalog, tagsFromMap(metadata.Tags))
	for name, data := range files {
		sources[name] = bytes.NewReader(data)
	}
	candidate, err := os.CreateTemp(filepath.Dir(path), ".vault-upgrade-*")
	if err != nil {
		return err
	}
	converted := candidate.Name()
	if err := candidate.Close(); err != nil {
		_ = os.Remove(converted)
		return err
	}
	if err := writeInitialStream(converted, header, aead, entries, tagCatalog, sources); err != nil {
		_ = os.Remove(converted)
		return err
	}
	defer os.Remove(converted)
	backup, err := backupLegacyFile(path)
	if err != nil {
		return fmt.Errorf("converted collection is ready but original backup could not be created: %w", err)
	}
	if err := os.Rename(converted, path); err != nil {
		return fmt.Errorf("collection converted and original saved as %s, but upgrade could not be installed: %w", backup, err)
	}
	return nil
}

func backupLegacyFile(path string) (string, error) {
	source, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer source.Close()
	for suffix := 0; suffix < 1000; suffix++ {
		backup := path + ".legacy"
		if suffix > 0 {
			backup = fmt.Sprintf("%s.legacy-%d", path, suffix)
		}
		target, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(target, source)
		if copyErr == nil {
			copyErr = target.Sync()
		}
		closeErr := target.Close()
		if copyErr != nil {
			_ = os.Remove(backup)
			return "", copyErr
		}
		if closeErr != nil {
			_ = os.Remove(backup)
			return "", closeErr
		}
		return backup, nil
	}
	return "", errors.New("could not allocate a legacy backup filename")
}

func readStreamIndex(path, password string) ([]byte, cipher.AEAD, []Entry, []Tag, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer file.Close()
	return readStreamIndexFile(file, password)
}

func readStreamIndexFile(file *os.File, password string) ([]byte, cipher.AEAD, []Entry, []Tag, error) {
	reader := io.NewSectionReader(file, 0, 1<<63-1)
	info, err := file.Stat()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if info.Size() < streamHeaderSize+streamTrailerSize {
		return nil, nil, nil, nil, errors.New("not a supported streaming collection")
	}
	header := make([]byte, streamHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, nil, nil, nil, err
	}
	if string(header[:8]) != streamMagic {
		return nil, nil, nil, nil, errors.New("not a supported streaming collection")
	}
	iterations := binary.BigEndian.Uint64(header[8+saltSize:])
	if iterations < 10000 || iterations > 2000000 {
		return nil, nil, nil, nil, errors.New("invalid key derivation parameters")
	}
	aead, err := streamAEAD(password, header[8:8+saltSize], int(iterations))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if _, err := reader.Seek(info.Size()-streamTrailerSize, io.SeekStart); err != nil {
		return nil, nil, nil, nil, err
	}
	var trailer [streamTrailerSize]byte
	if _, err := io.ReadFull(reader, trailer[:]); err != nil {
		return nil, nil, nil, nil, err
	}
	if string(trailer[:8]) != streamIndexMagic {
		return nil, nil, nil, nil, errors.New("collection index is missing or damaged")
	}
	indexOffset := int64(binary.BigEndian.Uint64(trailer[8:16]))
	indexLength := int64(binary.BigEndian.Uint64(trailer[16:24]))
	maxEncryptedIndex := int64(maxIndexSize + nonceSize + aead.Overhead())
	if indexOffset < streamHeaderSize || indexLength < int64(nonceSize+aead.Overhead()) || indexLength > maxEncryptedIndex || indexOffset > info.Size()-streamTrailerSize || indexLength != info.Size()-streamTrailerSize-indexOffset {
		return nil, nil, nil, nil, errors.New("invalid collection index bounds")
	}
	if _, err := reader.Seek(indexOffset, io.SeekStart); err != nil {
		return nil, nil, nil, nil, err
	}
	indexBlock := make([]byte, indexLength)
	if _, err := io.ReadFull(reader, indexBlock); err != nil {
		return nil, nil, nil, nil, err
	}
	plain, err := aead.Open(nil, indexBlock[:nonceSize], indexBlock[nonceSize:], header)
	if err != nil {
		return nil, nil, nil, nil, errors.New("decryption failed (wrong key or damaged collection)")
	}
	var manifest streamManifest
	if err := json.Unmarshal(plain, &manifest); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid collection index: %w", err)
	}
	if len(manifest.Entries) > 100_000 {
		return nil, nil, nil, nil, errors.New("collection has too many items")
	}
	if err := validateStreamEntries(manifest.Entries, indexOffset); err != nil {
		return nil, nil, nil, nil, err
	}
	return header, aead, manifest.Entries, makeTagCatalog(manifest.Tags, tagsFromEntries(manifest.Entries)), nil
}

func validateStreamEntries(entries []Entry, indexOffset int64) error {
	seen := make(map[string]struct{}, len(entries))
	ordered := append([]Entry(nil), entries...)
	for _, entry := range ordered {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.Name)))
		if clean != entry.Name || clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
			return fmt.Errorf("unsafe path in collection: %q", entry.Name)
		}
		recordSize := encodedRecordSize(entry.Size)
		if entry.Size < 0 || recordSize < 0 || entry.Offset < streamHeaderSize || entry.Offset > indexOffset || recordSize > indexOffset-entry.Offset {
			return fmt.Errorf("invalid item bounds in collection: %q", entry.Name)
		}
		if _, exists := seen[entry.Name]; exists {
			return fmt.Errorf("duplicate item in collection index: %q", entry.Name)
		}
		seen[entry.Name] = struct{}{}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	for i := 1; i < len(ordered); i++ {
		previousEnd := ordered[i-1].Offset + encodedRecordSize(ordered[i-1].Size)
		if ordered[i].Offset < previousEnd {
			return errors.New("overlapping item data in collection index")
		}
	}
	return nil
}

func encodedRecordSize(size int64) int64 {
	if size <= 0 {
		return 0
	}
	chunks := (size-1)/streamChunkSize + 1
	if chunks > (int64(^uint64(0)>>1)-size)/streamRecordOver {
		return -1
	}
	return size + chunks*streamRecordOver
}

func newStreamCipher(password string) ([]byte, cipher.AEAD, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	header := make([]byte, 0, streamHeaderSize)
	header = append(header, streamMagic...)
	header = append(header, salt...)
	var rounds [8]byte
	binary.BigEndian.PutUint64(rounds[:], iterations)
	header = append(header, rounds[:]...)
	aead, err := streamAEAD(password, salt, iterations)
	return header, aead, err
}

func streamAEAD(password string, salt []byte, rounds int) (cipher.AEAD, error) {
	block, err := aes.NewCipher(deriveKey([]byte(password), salt, rounds))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func writeInitialStream(path string, header []byte, aead cipher.AEAD, entries []Entry, tags []Tag, sources map[string]io.Reader) error {
	return writeStreamAtomically(path, header, aead, nil, entries, tags, sources)
}

func rewriteStream(path string, password string, entries []Entry) error {
	_, _, _, tags, err := readStreamIndex(path, password)
	if err != nil {
		return err
	}
	return rewriteStreamWithTags(path, password, entries, tags)
}

func rewriteStreamWithTags(path string, password string, entries []Entry, tags []Tag) error {
	header, aead, oldEntries, _, err := readStreamIndex(path, password)
	if err != nil {
		return err
	}
	oldByName := make(map[string]Entry, len(oldEntries))
	for _, entry := range oldEntries {
		oldByName[entry.Name] = entry
	}
	for i := range entries {
		if old, ok := oldByName[entries[i].Name]; ok {
			entries[i].Offset = old.Offset
		}
	}
	return writeStreamAtomically(path, header, aead, oldEntries, entries, tags, nil)
}

func writeStreamAtomically(path string, header []byte, aead cipher.AEAD, oldEntries, entries []Entry, tags []Tag, sources map[string]io.Reader) error {
	var oldFile *os.File
	var err error
	if len(oldEntries) > 0 {
		oldFile, err = os.Open(path)
		if err != nil {
			return err
		}
		defer oldFile.Close()
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".vault-stream-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(header); err != nil {
		_ = temp.Close()
		return err
	}
	oldByName := make(map[string]Entry, len(oldEntries))
	for _, entry := range oldEntries {
		oldByName[entry.Name] = entry
	}
	for i := range entries {
		entry := &entries[i]
		position, err := temp.Seek(0, io.SeekCurrent)
		if err != nil {
			_ = temp.Close()
			return err
		}
		entry.Offset = position
		if source, ok := sources[entry.Name]; ok {
			updated, err := writeEncryptedEntry(temp, aead, *entry, source)
			if err != nil {
				_ = temp.Close()
				return fmt.Errorf("write item %q: %w", entry.Name, err)
			}
			*entry = updated
			continue
		}
		old, ok := oldByName[entry.Name]
		if !ok || oldFile == nil {
			_ = temp.Close()
			return fmt.Errorf("missing data source for item %q", entry.Name)
		}
		if _, err := oldFile.Seek(old.Offset, io.SeekStart); err != nil {
			_ = temp.Close()
			return err
		}
		if _, err := io.CopyN(temp, oldFile, encodedRecordSize(old.Size)); err != nil {
			_ = temp.Close()
			return fmt.Errorf("copy encrypted item %q: %w", entry.Name, err)
		}
		entry.Size = old.Size
		entry.Hash = old.Hash
	}
	if err := writeStreamIndex(temp, header, aead, entries, tags); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func writeEncryptedEntry(output *os.File, aead cipher.AEAD, entry Entry, source io.Reader) (Entry, error) {
	hasher := sha256.New()
	expectedHash := entry.Hash
	remaining := entry.Size
	var chunk uint64
	for remaining > 0 {
		size := int64(streamChunkSize)
		if remaining < size {
			size = remaining
		}
		plain := make([]byte, size)
		if _, err := io.ReadFull(source, plain); err != nil {
			return entry, err
		}
		_, _ = hasher.Write(plain)
		var sizeBytes [4]byte
		binary.BigEndian.PutUint32(sizeBytes[:], uint32(size))
		if _, err := output.Write(sizeBytes[:]); err != nil {
			return entry, err
		}
		nonce := make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return entry, err
		}
		if _, err := output.Write(nonce); err != nil {
			return entry, err
		}
		sealed := aead.Seal(nil, nonce, plain, chunkAAD(entry.Name, chunk, entry.Size))
		if _, err := output.Write(sealed); err != nil {
			return entry, err
		}
		for i := range plain {
			plain[i] = 0
		}
		remaining -= size
		chunk++
	}
	var extra [1]byte
	if n, err := source.Read(extra[:]); n != 0 || (err != nil && err != io.EOF) {
		return entry, errors.New("source changed while it was being added")
	}
	entry.Hash = hex.EncodeToString(hasher.Sum(nil))
	if expectedHash != "" && expectedHash != entry.Hash {
		return entry, errors.New("source changed while it was being added")
	}
	return entry, nil
}

func writeStreamIndex(output *os.File, header []byte, aead cipher.AEAD, entries []Entry, tags []Tag) error {
	indexOffset, err := output.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	data, err := json.Marshal(streamManifest{Entries: entries, Tags: makeTagCatalog(tags, tagsFromEntries(entries))})
	if err != nil {
		return err
	}
	if len(data) > maxIndexSize {
		return errors.New("collection index exceeds the 16 MiB limit")
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nil, nonce, data, header)
	if _, err := output.Write(nonce); err != nil {
		return err
	}
	if _, err := output.Write(sealed); err != nil {
		return err
	}
	indexLength := int64(len(nonce) + len(sealed))
	var trailer [streamTrailerSize]byte
	copy(trailer[:8], streamIndexMagic)
	binary.BigEndian.PutUint64(trailer[8:16], uint64(indexOffset))
	binary.BigEndian.PutUint64(trailer[16:24], uint64(indexLength))
	_, err = output.Write(trailer[:])
	return err
}

func chunkAAD(name string, index uint64, size int64) []byte {
	data := make([]byte, len(name)+1+8+8)
	copy(data, name)
	data[len(name)] = 0
	binary.BigEndian.PutUint64(data[len(name)+1:], index)
	binary.BigEndian.PutUint64(data[len(name)+9:], uint64(size))
	return data
}

func hashString(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}
