package vault

import (
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
	streamV3Magic       = "PVLT0003"
	streamV3CommitMagic = "PVLCMT03"
	streamV3FooterSize  = 40
)

type streamV3Manifest struct {
	Sequence           uint64   `json:"sequence"`
	PreviousCommit     int64    `json:"previous_commit,omitempty"`
	PreviousCommitHash string   `json:"previous_commit_hash,omitempty"`
	TransactionDigest  string   `json:"transaction_digest,omitempty"`
	Entries            []Entry  `json:"entries"`
	Tombstones         []string `json:"tombstones,omitempty"`
	Tags               []Tag    `json:"tags,omitempty"`
}

type streamV3Commit struct {
	IndexOffset, IndexLength int64
	Sequence                 uint64
	PreviousOffset           int64
	FooterOffset             int64
	Footer                   [streamV3FooterSize]byte
}

func newStreamV3Cipher(password string) ([]byte, cipher.AEAD, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	header := append([]byte(streamV3Magic), salt...)
	var rounds [8]byte
	binary.BigEndian.PutUint64(rounds[:], iterations)
	header = append(header, rounds[:]...)
	aead, err := streamAEAD(password, salt, iterations)
	return header, aead, err
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
	header := make([]byte, streamHeaderSize)
	if _, err := file.ReadAt(header, 0); err != nil {
		return nil, nil, nil, nil, zero, err
	}
	if string(header[:8]) != streamV3Magic {
		return nil, nil, nil, nil, zero, errors.New("not a supported PVLT0003 collection")
	}
	rounds := binary.BigEndian.Uint64(header[8+saltSize:])
	if rounds < 10000 || rounds > 2_000_000 {
		return nil, nil, nil, nil, zero, errors.New("invalid key derivation parameters")
	}
	aead, err := streamAEAD(password, header[8:8+saltSize], int(rounds))
	if err != nil {
		return nil, nil, nil, nil, zero, err
	}
	commit, entries, tags, err := findLatestStreamV3Commit(file, info.Size(), header, aead)
	if err != nil {
		return nil, nil, nil, nil, zero, err
	}
	return header, aead, entries, tags, commit, nil
}

func findLatestStreamV3Commit(file *os.File, fileSize int64, header []byte, aead cipher.AEAD) (streamV3Commit, []Entry, []Tag, error) {
	var invalidCompleteCommit bool
	const scanChunk = 64 << 10
	for end := fileSize; end > streamHeaderSize; {
		start := end - scanChunk
		if start < streamHeaderSize {
			start = streamHeaderSize
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
			commit, entries, tags, ok := readStreamV3CommitAt(file, fileSize, candidateOffset, header, aead)
			if ok {
				if invalidCompleteCommit {
					return streamV3Commit{}, nil, nil, errors.New("corrupt PVLT0003 commit follows the last valid snapshot")
				}
				return commit, entries, tags, nil
			}
			if isCompleteStreamV3Footer(file, fileSize, candidateOffset) {
				invalidCompleteCommit = true
			}
		}
		if start == streamHeaderSize {
			break
		}
		end = start + int64(len(streamV3CommitMagic)-1)
	}
	if invalidCompleteCommit {
		return streamV3Commit{}, nil, nil, errors.New("corrupt PVLT0003 commit found")
	}
	return streamV3Commit{}, nil, nil, errors.New("no valid PVLT0003 commit found")
}

func isCompleteStreamV3Footer(file *os.File, fileSize, offset int64) bool {
	if offset < streamHeaderSize || offset > fileSize-streamV3FooterSize {
		return false
	}
	var footer [streamV3FooterSize]byte
	if _, err := file.ReadAt(footer[:], offset); err != nil || string(footer[:8]) != streamV3CommitMagic {
		return false
	}
	indexOffset := int64(binary.BigEndian.Uint64(footer[8:16]))
	indexLength := int64(binary.BigEndian.Uint64(footer[16:24]))
	sequence := binary.BigEndian.Uint64(footer[24:32])
	return sequence > 0 && indexOffset >= streamHeaderSize && indexOffset <= offset && indexLength >= nonceSize+16 && indexLength <= maxIndexSize+nonceSize+16 && indexLength == offset-indexOffset
}

func readStreamV3CommitAt(file *os.File, fileSize, footerOffset int64, header []byte, aead cipher.AEAD) (streamV3Commit, []Entry, []Tag, bool) {
	var commit streamV3Commit
	if footerOffset < streamHeaderSize || footerOffset+streamV3FooterSize > fileSize {
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
	maxIndex := int64(maxIndexSize + nonceSize + aead.Overhead())
	if commit.Sequence == 0 || commit.IndexOffset < streamHeaderSize || commit.IndexOffset > footerOffset || commit.IndexLength < int64(nonceSize+aead.Overhead()) || commit.IndexLength > maxIndex || commit.IndexLength != footerOffset-commit.IndexOffset {
		return streamV3Commit{}, nil, nil, false
	}
	index := make([]byte, commit.IndexLength)
	if _, err := file.ReadAt(index, commit.IndexOffset); err != nil {
		return streamV3Commit{}, nil, nil, false
	}
	plain, err := aead.Open(nil, index[:nonceSize], index[nonceSize:], header)
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
		if commit.PreviousOffset < streamHeaderSize || commit.PreviousOffset > footerOffset-streamV3FooterSize {
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
		transactionStart := int64(streamHeaderSize)
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
	entries, tags, err := parseStreamManifestWithHeader(plain, commit.IndexOffset, streamHeaderSize)
	if err != nil {
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
	header, aead, entries, tags, err := readStreamIndex(path, password)
	if err != nil {
		return err
	}
	if len(header) < 8 || string(header[:8]) != streamMagic {
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
	newHeader := append([]byte(nil), header...)
	copy(newHeader[:8], streamV3Magic)
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
	if err := appendStreamV3Contents(temp, newHeader, aead, newEntries, entries, tags, nil, streamV3Commit{}); err != nil {
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

func appendStreamV3Contents(file *os.File, header []byte, aead cipher.AEAD, oldByName map[string]Entry, entries []Entry, tags []Tag, sources map[string]io.Reader, previous streamV3Commit) error {
	if err := validateEntryCount(len(entries)); err != nil {
		return err
	}
	transactionStart, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if previous.Sequence == 0 {
		transactionStart = streamHeaderSize
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
	tombstones := make([]string, 0)
	for name := range oldByName {
		if _, exists := live[name]; !exists {
			tombstones = append(tombstones, name)
		}
	}
	sort.Strings(tombstones)
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
	plain, err := json.Marshal(streamV3Manifest{Sequence: sequence, PreviousCommit: previous.FooterOffset, PreviousCommitHash: previousHash, TransactionDigest: transactionDigest, Entries: entries, Tombstones: tombstones, Tags: makeTagCatalog(tags, tagsFromEntries(entries))})
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
	sealed := aead.Seal(nil, nonce, plain, header)
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
