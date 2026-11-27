package vault

import (
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
	"reflect"
	"sort"
	"strings"
)

func validateTombstones(names []string) error {
	if len(names) > maxEntries {
		return errors.New("collection has too many tombstones")
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
		if clean != name || clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
			return fmt.Errorf("unsafe tombstone path: %q", name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate tombstone path: %q", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

const (
	streamV3Magic              = "PVLT0003"
	streamV3CommitMagic        = "PVLCMT03"
	streamV3FooterSize         = 40
	streamV3KeyMarker          = "KEYWRP01"
	streamV3CoreSize           = 8 + 8 + saltSize + 8
	streamV3KeySlotSize        = 8 + nonceSize + 32 + 16
	streamV3KeySlots           = 2
	streamV3WrappedSize        = streamV3CoreSize + streamV3KeySlots*streamV3KeySlotSize
	streamV3CheckpointInterval = 32
)

type streamV3Manifest struct {
	IndexMode          string   `json:"index_mode,omitempty"`
	Sequence           uint64   `json:"sequence"`
	PreviousCommit     int64    `json:"previous_commit,omitempty"`
	PreviousCommitHash string   `json:"previous_commit_hash,omitempty"`
	TransactionDigest  string   `json:"transaction_digest,omitempty"`
	Entries            []Entry  `json:"entries"`
	Upserts            []Entry  `json:"upserts,omitempty"`
	Deletes            []string `json:"deletes,omitempty"`
	Tombstones         []string `json:"tombstones,omitempty"`
	Tags               []Tag    `json:"tags,omitempty"`
}

type streamV3Commit struct {
	IndexOffset, IndexLength int64
	Sequence                 uint64
	PreviousOffset           int64
	FooterOffset             int64
	HeaderSize               int64
	Footer                   [streamV3FooterSize]byte
}

type streamV3KeySlot struct {
	Index      int
	Generation uint64
	DEK        []byte
}

func newStreamV3Cipher(password string) ([]byte, cipher.AEAD, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, err
	}
	return newStreamV3HeaderWithDEK(password, dek)
}

func newStreamV3HeaderWithDEK(password string, dek []byte) ([]byte, cipher.AEAD, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	core := append([]byte(streamV3Magic), streamV3KeyMarker...)
	core = append(core, salt...)
	var rounds [8]byte
	binary.BigEndian.PutUint64(rounds[:], iterations)
	core = append(core, rounds[:]...)
	kekAEAD, err := streamAEAD(password, salt, iterations)
	if err != nil {
		return nil, nil, err
	}
	header := make([]byte, streamV3WrappedSize)
	copy(header, core)
	if err := writeStreamV3KeySlot(header, 0, 1, dek, kekAEAD); err != nil {
		return nil, nil, err
	}
	aead, err := aeadFromKey(dek)
	return header, aead, err
}

func legacyStreamV3DEK(header []byte, password string) ([]byte, error) {
	salt, rounds, err := streamV3KDFParams(header)
	if err != nil {
		return nil, err
	}
	return deriveKey([]byte(password), salt, rounds), nil
}

func isWrappedStreamV3Header(header []byte) bool {
	return len(header) >= streamV3CoreSize && string(header[:8]) == streamV3Magic && string(header[8:16]) == streamV3KeyMarker
}

func streamV3HeaderSizeFor(header []byte) int64 {
	if isWrappedStreamV3Header(header) {
		return streamV3WrappedSize
	}
	return streamHeaderSize
}

func streamV3IndexAAD(header []byte) []byte {
	if isWrappedStreamV3Header(header) {
		return header[:streamV3CoreSize]
	}
	return header
}

func aeadFromKey(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func streamV3KDFParams(header []byte) (salt []byte, rounds int, err error) {
	if isWrappedStreamV3Header(header) {
		salt = header[16 : 16+saltSize]
		rounds = int(binary.BigEndian.Uint64(header[16+saltSize : streamV3CoreSize]))
	} else if len(header) >= streamHeaderSize && string(header[:8]) == streamV3Magic {
		salt = header[8 : 8+saltSize]
		rounds = int(binary.BigEndian.Uint64(header[8+saltSize : streamHeaderSize]))
	} else {
		return nil, 0, errors.New("invalid PVLT0003 header")
	}
	if rounds < 10000 || rounds > 2_000_000 {
		return nil, 0, errors.New("invalid key derivation parameters")
	}
	return salt, rounds, nil
}

func openStreamV3Header(header []byte, password string) (cipher.AEAD, streamV3KeySlot, error) {
	if !isWrappedStreamV3Header(header) {
		salt, rounds, err := streamV3KDFParams(header)
		if err != nil {
			return nil, streamV3KeySlot{}, err
		}
		aead, err := streamAEAD(password, salt, rounds)
		return aead, streamV3KeySlot{}, err
	}
	if len(header) < streamV3WrappedSize {
		return nil, streamV3KeySlot{}, errors.New("truncated PVLT0003 key envelope")
	}
	salt, rounds, err := streamV3KDFParams(header)
	if err != nil {
		return nil, streamV3KeySlot{}, err
	}
	kekAEAD, err := streamAEAD(password, salt, rounds)
	if err != nil {
		return nil, streamV3KeySlot{}, err
	}
	var selected streamV3KeySlot
	for slot := 0; slot < streamV3KeySlots; slot++ {
		offset := streamV3CoreSize + slot*streamV3KeySlotSize
		generation := binary.BigEndian.Uint64(header[offset : offset+8])
		if generation == 0 {
			continue
		}
		dek, err := kekAEAD.Open(nil, header[offset+8:offset+8+nonceSize], header[offset+8+nonceSize:offset+streamV3KeySlotSize], header[:streamV3CoreSize])
		if err != nil || len(dek) != 32 {
			continue
		}
		if generation > selected.Generation {
			selected = streamV3KeySlot{Index: slot, Generation: generation, DEK: dek}
		}
	}
	if selected.Generation == 0 {
		return nil, streamV3KeySlot{}, errors.New("decryption failed (wrong key or damaged collection)")
	}
	aead, err := aeadFromKey(selected.DEK)
	return aead, selected, err
}

func writeStreamV3KeySlot(header []byte, slot int, generation uint64, dek []byte, kekAEAD cipher.AEAD) error {
	if slot < 0 || slot >= streamV3KeySlots || len(header) < streamV3WrappedSize || len(dek) != 32 {
		return errors.New("invalid PVLT0003 key slot")
	}
	offset := streamV3CoreSize + slot*streamV3KeySlotSize
	var gen [8]byte
	binary.BigEndian.PutUint64(gen[:], generation)
	copy(header[offset:offset+8], gen[:])
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	copy(header[offset+8:offset+8+nonceSize], nonce)
	sealed := kekAEAD.Seal(nil, nonce, dek, header[:streamV3CoreSize])
	copy(header[offset+8+nonceSize:offset+streamV3KeySlotSize], sealed)
	return nil
}

func rewrapStreamV3Key(path, currentPassword, newPassword string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	header := make([]byte, streamV3WrappedSize)
	if _, err := file.ReadAt(header, 0); err != nil {
		return err
	}
	if !isWrappedStreamV3Header(header) {
		return errors.New("PVLT0003 collection must use a wrapped DEK before password changes")
	}
	aead, selected, err := openStreamV3Header(header, currentPassword)
	if err != nil {
		return err
	}
	_ = aead
	salt, rounds, err := streamV3KDFParams(header)
	if err != nil {
		return err
	}
	kekAEAD, err := streamAEAD(newPassword, salt, rounds)
	if err != nil {
		return err
	}
	maxGeneration := selected.Generation
	for slot := 0; slot < streamV3KeySlots; slot++ {
		offset := streamV3CoreSize + slot*streamV3KeySlotSize
		if generation := binary.BigEndian.Uint64(header[offset : offset+8]); generation > maxGeneration {
			maxGeneration = generation
		}
	}
	target := 1 - selected.Index
	if err := writeStreamV3KeySlot(header, target, maxGeneration+1, selected.DEK, kekAEAD); err != nil {
		return err
	}
	targetOffset := int64(streamV3CoreSize + target*streamV3KeySlotSize)
	if _, err := file.WriteAt(header[streamV3CoreSize+target*streamV3KeySlotSize:streamV3CoreSize+(target+1)*streamV3KeySlotSize], targetOffset); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	zeroSlot := make([]byte, streamV3KeySlotSize)
	for slot := 0; slot < streamV3KeySlots; slot++ {
		if slot == target {
			continue
		}
		offset := int64(streamV3CoreSize + slot*streamV3KeySlotSize)
		if _, err := file.WriteAt(zeroSlot, offset); err != nil {
			return err
		}
	}
	return file.Sync()
}

func readStreamV3IndexFile(file *os.File, password string) ([]byte, cipher.AEAD, []Entry, []Tag, streamV3Commit, error) {
	var zero streamV3Commit
	info, err := file.Stat()
	if err != nil {
		return nil, nil, nil, nil, zero, err
	}
	if info.Size() < streamHeaderSize+streamV3FooterSize {
		return nil, nil, nil, nil, zero, errors.New("not a supported PVLT0003 collection")
	}
	var first [streamV3CoreSize]byte
	if _, err := file.ReadAt(first[:8], 0); err != nil {
		return nil, nil, nil, nil, zero, err
	}
	if string(first[:8]) != streamV3Magic {
		return nil, nil, nil, nil, zero, errors.New("not a supported PVLT0003 collection")
	}
	headerSize := int64(streamHeaderSize)
	if info.Size() >= streamV3CoreSize {
		if _, err := file.ReadAt(first[8:], 8); err != nil && err != io.EOF {
			return nil, nil, nil, nil, zero, err
		}
		if string(first[8:16]) == streamV3KeyMarker {
			headerSize = streamV3WrappedSize
		}
	}
	if info.Size() < headerSize+streamV3FooterSize {
		return nil, nil, nil, nil, zero, errors.New("not a supported PVLT0003 collection")
	}
	header := make([]byte, headerSize)
	if _, err := file.ReadAt(header, 0); err != nil {
		return nil, nil, nil, nil, zero, err
	}
	aead, _, err := openStreamV3Header(header, password)
	if err != nil {
		return nil, nil, nil, nil, zero, err
	}
	commit, entries, tags, err := findLatestStreamV3Commit(file, info.Size(), header, aead, headerSize)
	if err != nil {
		return nil, nil, nil, nil, zero, err
	}
	return header, aead, entries, tags, commit, nil
}

func findLatestStreamV3Commit(file *os.File, fileSize int64, header []byte, aead cipher.AEAD, headerSize int64) (streamV3Commit, []Entry, []Tag, error) {
	var invalidCompleteCommit bool
	const scanChunk = 64 << 10
	for end := fileSize; end > headerSize; {
		start := end - scanChunk
		if start < headerSize {
			start = headerSize
		}
		buf := make([]byte, end-start)
		n, err := file.ReadAt(buf, start)
		if err != nil && err != io.EOF {
			return streamV3Commit{}, nil, nil, err
		}
		buf = buf[:n]
		for i := len(buf) - len(streamV3CommitMagic); i >= 0; i-- {
			if string(buf[i:i+8]) != streamV3CommitMagic {
				continue
			}
			candidateOffset := start + int64(i)
			commit, entries, tags, ok := readStreamV3CommitAt(file, fileSize, candidateOffset, header, aead, headerSize)
			if ok {
				if invalidCompleteCommit {
					return streamV3Commit{}, nil, nil, errors.New("corrupt PVLT0003 commit follows the last valid snapshot")
				}
				return commit, entries, tags, nil
			}
			if isCompleteStreamV3Footer(file, fileSize, candidateOffset, headerSize) {
				invalidCompleteCommit = true
			}
		}
		if start == headerSize {
			break
		}
		end = start + int64(len(streamV3CommitMagic)-1)
	}
	if invalidCompleteCommit {
		return streamV3Commit{}, nil, nil, errors.New("corrupt PVLT0003 commit found")
	}
	return streamV3Commit{}, nil, nil, errors.New("no valid PVLT0003 commit found")
}

func isCompleteStreamV3Footer(file *os.File, fileSize, offset, headerSize int64) bool {
	if offset < headerSize || offset > fileSize-streamV3FooterSize {
		return false
	}
	var footer [streamV3FooterSize]byte
	if _, err := file.ReadAt(footer[:], offset); err != nil || string(footer[:8]) != streamV3CommitMagic {
		return false
	}
	indexOffset := int64(binary.BigEndian.Uint64(footer[8:16]))
	indexLength := int64(binary.BigEndian.Uint64(footer[16:24]))
	sequence := binary.BigEndian.Uint64(footer[24:32])
	return sequence > 0 && indexOffset >= headerSize && indexOffset <= offset && indexLength >= nonceSize+16 && indexLength <= maxIndexSize+nonceSize+16 && indexLength == offset-indexOffset
}

func readStreamV3CommitAt(file *os.File, fileSize, footerOffset int64, header []byte, aead cipher.AEAD, headerSize int64) (streamV3Commit, []Entry, []Tag, bool) {
	return readStreamV3CommitAtDepth(file, fileSize, footerOffset, header, aead, headerSize, 0)
}

func readStreamV3CommitAtDepth(file *os.File, fileSize, footerOffset int64, header []byte, aead cipher.AEAD, headerSize int64, depth int) (streamV3Commit, []Entry, []Tag, bool) {
	var commit streamV3Commit
	if depth > streamV3CheckpointInterval {
		return commit, nil, nil, false
	}
	if footerOffset < headerSize || footerOffset+streamV3FooterSize > fileSize {
		return commit, nil, nil, false
	}
	if _, err := file.ReadAt(commit.Footer[:], footerOffset); err != nil {
		return commit, nil, nil, false
	}
	if string(commit.Footer[:8]) != streamV3CommitMagic {
		return commit, nil, nil, false
	}
	commit.IndexOffset = int64(binary.BigEndian.Uint64(commit.Footer[8:16]))
	commit.IndexLength = int64(binary.BigEndian.Uint64(commit.Footer[16:24]))
	commit.Sequence = binary.BigEndian.Uint64(commit.Footer[24:32])
	commit.PreviousOffset = int64(binary.BigEndian.Uint64(commit.Footer[32:40]))
	commit.FooterOffset = footerOffset
	commit.HeaderSize = headerSize
	maxIndex := int64(maxIndexSize + nonceSize + aead.Overhead())
	if commit.Sequence == 0 || commit.IndexOffset < headerSize || commit.IndexOffset > footerOffset || commit.IndexLength < int64(nonceSize+aead.Overhead()) || commit.IndexLength > maxIndex || commit.IndexLength != footerOffset-commit.IndexOffset {
		return streamV3Commit{}, nil, nil, false
	}
	index := make([]byte, commit.IndexLength)
	if _, err := file.ReadAt(index, commit.IndexOffset); err != nil {
		return streamV3Commit{}, nil, nil, false
	}
	plain, err := aead.Open(nil, index[:nonceSize], index[nonceSize:], streamV3IndexAAD(header))
	if err != nil {
		return streamV3Commit{}, nil, nil, false
	}
	var manifest streamV3Manifest
	if err := json.Unmarshal(plain, &manifest); err != nil {
		return streamV3Commit{}, nil, nil, false
	}
	if err := validateTombstones(manifest.Tombstones); err != nil {
		return streamV3Commit{}, nil, nil, false
	}
	if manifest.Sequence != commit.Sequence || manifest.PreviousCommit != commit.PreviousOffset {
		return streamV3Commit{}, nil, nil, false
	}
	if commit.Sequence == 1 {
		if commit.PreviousOffset != 0 || manifest.PreviousCommitHash != "" {
			return streamV3Commit{}, nil, nil, false
		}
	} else {
		if commit.PreviousOffset < headerSize || commit.PreviousOffset > footerOffset-streamV3FooterSize {
			return streamV3Commit{}, nil, nil, false
		}
		var previous [streamV3FooterSize]byte
		if _, err := file.ReadAt(previous[:], commit.PreviousOffset); err != nil || string(previous[:8]) != streamV3CommitMagic {
			return streamV3Commit{}, nil, nil, false
		}
		previousHash := sha256.Sum256(previous[:])
		if binary.BigEndian.Uint64(previous[24:32])+1 != commit.Sequence || manifest.PreviousCommitHash != hex.EncodeToString(previousHash[:]) {
			return streamV3Commit{}, nil, nil, false
		}
	}
	if manifest.TransactionDigest != "" {
		transactionStart := headerSize
		if commit.Sequence > 1 {
			transactionStart = commit.PreviousOffset + streamV3FooterSize
		}
		if transactionStart > commit.IndexOffset {
			return streamV3Commit{}, nil, nil, false
		}
		hasher := sha256.New()
		if _, err := io.Copy(hasher, io.NewSectionReader(file, transactionStart, commit.IndexOffset-transactionStart)); err != nil {
			return streamV3Commit{}, nil, nil, false
		}
		if manifest.TransactionDigest != hex.EncodeToString(hasher.Sum(nil)) {
			return streamV3Commit{}, nil, nil, false
		}
	}
	var entries []Entry
	var tags []Tag
	switch manifest.IndexMode {
	case "", "snapshot": // Empty mode is the original PVLT0003 full-index format.
		if len(manifest.Upserts) != 0 || len(manifest.Deletes) != 0 {
			return streamV3Commit{}, nil, nil, false
		}
		entries, tags, err = parseStreamManifestWithHeader(plain, commit.IndexOffset, headerSize)
		if err != nil {
			return streamV3Commit{}, nil, nil, false
		}
	case "delta":
		if commit.Sequence == 1 || len(manifest.Entries) != 0 || len(manifest.Upserts) > maxEntries || len(manifest.Deletes) > maxEntries {
			return streamV3Commit{}, nil, nil, false
		}
		if err := validateTombstones(manifest.Deletes); err != nil {
			return streamV3Commit{}, nil, nil, false
		}
		_, previousEntries, _, ok := readStreamV3CommitAtDepth(file, fileSize, commit.PreviousOffset, header, aead, headerSize, depth+1)
		if !ok {
			return streamV3Commit{}, nil, nil, false
		}
		byName := make(map[string]Entry, len(previousEntries)+len(manifest.Upserts))
		for _, entry := range previousEntries {
			byName[entry.Name] = entry
		}
		upsertNames := make(map[string]struct{}, len(manifest.Upserts))
		for _, entry := range manifest.Upserts {
			if _, exists := upsertNames[entry.Name]; exists {
				return streamV3Commit{}, nil, nil, false
			}
			upsertNames[entry.Name] = struct{}{}
		}
		for _, name := range manifest.Deletes {
			if _, exists := byName[name]; !exists {
				return streamV3Commit{}, nil, nil, false
			}
			delete(byName, name)
		}
		for _, entry := range manifest.Upserts {
			byName[entry.Name] = entry
		}
		if err := validateEntryCount(len(byName)); err != nil {
			return streamV3Commit{}, nil, nil, false
		}
		entries = make([]Entry, 0, len(byName))
		for _, entry := range byName {
			entries = append(entries, entry)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		snapshot, err := json.Marshal(streamManifest{Entries: entries, Tags: manifest.Tags})
		if err != nil {
			return streamV3Commit{}, nil, nil, false
		}
		entries, tags, err = parseStreamManifestWithHeader(snapshot, commit.IndexOffset, headerSize)
		if err != nil {
			return streamV3Commit{}, nil, nil, false
		}
	default:
		return streamV3Commit{}, nil, nil, false
	}
	return commit, entries, tags, true
}

func appendStreamV3Transaction(path, password string, entries []Entry, tags []Tag, sources map[string]io.Reader) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	header, aead, oldEntries, _, previous, err := readStreamV3IndexFile(file, password)
	if err != nil {
		return err
	}
	end := previous.FooterOffset + streamV3FooterSize
	if err := file.Truncate(end); err != nil {
		return err
	}
	if _, err := file.Seek(end, io.SeekStart); err != nil {
		return err
	}
	oldByName := make(map[string]Entry, len(oldEntries))
	for _, entry := range oldEntries {
		oldByName[entry.Name] = entry
	}
	return appendStreamV3Contents(file, header, aead, oldByName, entries, tags, sources, previous)
}

func upgradeStreamV2ToV3(path, password string) error {
	oldHeader, _, entries, tags, err := readStreamIndex(path, password)
	if err != nil {
		return err
	}
	if len(oldHeader) < 8 || string(oldHeader[:8]) != streamMagic {
		return errors.New("collection is not PVLT0002")
	}
	oldFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer oldFile.Close()
	temp, err := os.CreateTemp(filepath.Dir(path), ".vault-v2-upgrade-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	oldRounds := int(binary.BigEndian.Uint64(oldHeader[8+saltSize : streamHeaderSize]))
	dek := deriveKey([]byte(password), oldHeader[8:8+saltSize], oldRounds)
	newHeader, newAEAD, err := newStreamV3HeaderWithDEK(password, dek)
	if err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(newHeader); err != nil {
		_ = temp.Close()
		return err
	}
	ordered := append([]Entry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	newEntries := make(map[string]Entry, len(entries))
	for _, entry := range ordered {
		position, err := temp.Seek(0, io.SeekCurrent)
		if err != nil {
			_ = temp.Close()
			return err
		}
		if _, err := oldFile.Seek(entry.Offset, io.SeekStart); err != nil {
			_ = temp.Close()
			return err
		}
		if _, err := io.CopyN(temp, oldFile, encodedRecordSize(entry.Size)); err != nil {
			_ = temp.Close()
			return err
		}
		entry.Offset = position
		newEntries[entry.Name] = entry
	}
	for i := range entries {
		entries[i] = newEntries[entries[i].Name]
	}
	if err := appendStreamV3Contents(temp, newHeader, newAEAD, newEntries, entries, tags, nil, streamV3Commit{}); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := oldFile.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func upgradeStreamV3ToWrapped(path, password string) error {
	oldFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer oldFile.Close()
	oldHeader, _, entries, tags, _, err := readStreamV3IndexFile(oldFile, password)
	if err != nil {
		return err
	}
	if isWrappedStreamV3Header(oldHeader) {
		return nil
	}
	dek, err := legacyStreamV3DEK(oldHeader, password)
	if err != nil {
		return err
	}
	newHeader, newAEAD, err := newStreamV3HeaderWithDEK(password, dek)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".vault-v3-wrap-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(newHeader); err != nil {
		_ = temp.Close()
		return err
	}
	ordered := append([]Entry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	newEntries := make(map[string]Entry, len(entries))
	for _, entry := range ordered {
		position, err := temp.Seek(0, io.SeekCurrent)
		if err != nil {
			_ = temp.Close()
			return err
		}
		if _, err := oldFile.Seek(entry.Offset, io.SeekStart); err != nil {
			_ = temp.Close()
			return err
		}
		if _, err := io.CopyN(temp, oldFile, encodedRecordSize(entry.Size)); err != nil {
			_ = temp.Close()
			return err
		}
		entry.Offset = position
		newEntries[entry.Name] = entry
	}
	for i := range entries {
		entries[i] = newEntries[entries[i].Name]
	}
	if err := appendStreamV3Contents(temp, newHeader, newAEAD, newEntries, entries, tags, nil, streamV3Commit{}); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := oldFile.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func makeEntryReaders(file *os.File, aead cipher.AEAD, entries []Entry) map[string]io.Reader {
	sources := make(map[string]io.Reader, len(entries))
	for _, entry := range entries {
		sources[entry.Name] = &entryReader{source: io.NewSectionReader(file, entry.Offset, encodedRecordSize(entry.Size)), aead: aead, entry: entry, remaining: entry.Size}
	}
	return sources
}

func closeEntryReaders(sources map[string]io.Reader) {
	for _, source := range sources {
		if reader, ok := source.(io.Closer); ok {
			_ = reader.Close()
		}
	}
}

func appendStreamV3Contents(file *os.File, header []byte, aead cipher.AEAD, oldByName map[string]Entry, entries []Entry, tags []Tag, sources map[string]io.Reader, previous streamV3Commit) error {
	if err := validateEntryCount(len(entries)); err != nil {
		return err
	}
	transactionStart, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if previous.Sequence == 0 {
		transactionStart = int64(len(header))
	}
	for i := range entries {
		entry := &entries[i]
		if source, ok := sources[entry.Name]; ok {
			position, err := file.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}
			entry.Offset = position
			updated, err := writeEncryptedEntry(file, aead, *entry, source)
			if err != nil {
				return fmt.Errorf("write item %q: %w", entry.Name, err)
			}
			*entry = updated
			continue
		}
		old, ok := oldByName[entry.Name]
		if !ok {
			return fmt.Errorf("missing data source for item %q", entry.Name)
		}
		entry.Offset, entry.Size, entry.Hash = old.Offset, old.Size, old.Hash
	}
	sequence := previous.Sequence + 1
	live := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		live[entry.Name] = struct{}{}
	}
	previousHash := ""
	if previous.Sequence > 0 {
		sum := sha256.Sum256(previous.Footer[:])
		previousHash = hex.EncodeToString(sum[:])
	}
	indexOffset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.NewSectionReader(file, transactionStart, indexOffset-transactionStart)); err != nil {
		return err
	}
	transactionDigest := hex.EncodeToString(hasher.Sum(nil))
	manifest := streamV3Manifest{Sequence: sequence, PreviousCommit: previous.FooterOffset, PreviousCommitHash: previousHash, TransactionDigest: transactionDigest, Tags: makeTagCatalog(tags, tagsFromEntries(entries))}
	if previous.Sequence == 0 || sequence%streamV3CheckpointInterval == 0 {
		manifest.IndexMode = "snapshot"
		manifest.Entries = entries
	} else {
		manifest.IndexMode = "delta"
		for _, entry := range entries {
			old, exists := oldByName[entry.Name]
			if !exists || old.Size != entry.Size || old.Hash != entry.Hash || old.Offset != entry.Offset || !reflect.DeepEqual(old.Tags, entry.Tags) {
				manifest.Upserts = append(manifest.Upserts, entry)
			}
		}
		for name := range oldByName {
			if _, exists := live[name]; !exists {
				manifest.Deletes = append(manifest.Deletes, name)
			}
		}
		sort.Strings(manifest.Deletes)
	}
	plain, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if len(plain) > maxIndexSize {
		return errors.New("collection index exceeds the 16 MiB limit")
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nil, nonce, plain, streamV3IndexAAD(header))
	if _, err := file.Write(nonce); err != nil {
		return err
	}
	if _, err := file.Write(sealed); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	footerOffset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if footerOffset != indexOffset+int64(len(nonce)+len(sealed)) {
		return errors.New("invalid PVLT0003 index position")
	}
	var footer [streamV3FooterSize]byte
	copy(footer[:8], streamV3CommitMagic)
	binary.BigEndian.PutUint64(footer[8:16], uint64(indexOffset))
	binary.BigEndian.PutUint64(footer[16:24], uint64(len(nonce)+len(sealed)))
	binary.BigEndian.PutUint64(footer[24:32], sequence)
	binary.BigEndian.PutUint64(footer[32:40], uint64(previous.FooterOffset))
	if _, err := file.Write(footer[:]); err != nil {
		return err
	}
	return file.Sync()
}

func createStreamV3Atomically(path string, header []byte, aead cipher.AEAD, entries []Entry, tags []Tag, sources map[string]io.Reader) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".vault-v3-create-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(header); err != nil {
		_ = temp.Close()
		return err
	}
	if err := appendStreamV3Contents(temp, header, aead, nil, entries, tags, sources, streamV3Commit{}); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func compactStreamV3(path, password string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	header, aead, entries, tags, _, err := readStreamV3IndexFile(file, password)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".vault-v3-compact-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(header); err != nil {
		_ = temp.Close()
		return err
	}
	ordered := append([]Entry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	updated := make(map[string]Entry, len(entries))
	for _, entry := range ordered {
		position, err := temp.Seek(0, io.SeekCurrent)
		if err != nil {
			_ = temp.Close()
			return err
		}
		if _, err := file.Seek(entry.Offset, io.SeekStart); err != nil {
			_ = temp.Close()
			return err
		}
		if _, err := io.CopyN(temp, file, encodedRecordSize(entry.Size)); err != nil {
			_ = temp.Close()
			return err
		}
		entry.Offset = position
		updated[entry.Name] = entry
	}
	for i := range entries {
		entries[i] = updated[entries[i].Name]
	}
	if err := appendStreamV3Contents(temp, header, aead, updated, entries, tags, nil, streamV3Commit{}); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
