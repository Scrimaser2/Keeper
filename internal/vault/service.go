package vault

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"photovault/internal/catalog"
)

const archiveName = "photos.vault"

// Service coordinates encrypted collection storage and filesystem operations.
type Service struct{}

type CreateOptions struct {
	Source      string
	Destination string
	Key         string
	ClearSource bool
}

type CreateResult struct {
	DuplicateFiles     int
	SkippedSymlinks    int
	SkippedHiddenFiles int
	ClearedFiles       int
}

type RestoreOptions struct {
	Collection  string
	Destination string
	Key         string
}

type Collection struct {
	Files      map[string][]byte
	Tags       map[string][]string
	TagCatalog []Tag
}

func (Service) Create(options CreateOptions) (CreateResult, error) {
	var result CreateResult
	input, err := filepath.Abs(options.Source)
	if err != nil {
		return result, err
	}
	output, err := filepath.Abs(options.Destination)
	if err != nil {
		return result, err
	}
	if directoriesOverlap(input, output) {
		return result, errors.New("source and destination folders must not overlap")
	}
	info, err := os.Stat(input)
	if err != nil {
		return result, err
	}
	if !info.IsDir() {
		return result, errors.New("source must be a folder")
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return result, err
	}

	collectionPath := filepath.Join(output, archiveName)
	unlock, err := lockCollection(collectionPath)
	if err != nil {
		return result, err
	}
	defer unlock()
	var oldEntries []Entry
	var tagCatalog []Tag
	var header []byte
	var aead cipher.AEAD
	isV3 := false
	if _, err := os.Stat(collectionPath); err == nil {
		if err := ensureStreamFormatLocked(collectionPath, options.Key); err != nil {
			return result, err
		}
		header, aead, oldEntries, tagCatalog, err = readStreamIndex(collectionPath, options.Key)
		if err != nil {
			return result, err
		}
		isV3 = len(header) >= 8 && string(header[:8]) == streamV3Magic
	} else if !os.IsNotExist(err) {
		return result, err
	} else {
		header, aead, err = newStreamV3Cipher(options.Key)
		if err != nil {
			return result, err
		}
		isV3 = true
	}

	entriesByName := make(map[string]Entry, len(oldEntries))
	seenHashes := make(map[string]bool, len(oldEntries))
	for _, entry := range oldEntries {
		if catalog.IsHiddenPath(entry.Name) {
			continue
		}
		entriesByName[entry.Name] = entry
		if entry.Hash != "" {
			seenHashes[entry.Hash] = true
		}
	}
	sources := make(map[string]io.Reader)
	sourcePaths := make(map[string]string)
	if err := filepath.WalkDir(input, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(input, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if path == input && entry.IsDir() {
			return nil
		}
		if catalog.IsHiddenPath(name) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			result.SkippedHiddenFiles++
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			result.SkippedSymlinks++
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("only regular files are supported: %s", path)
		}
		if name == metadataPath {
			return fmt.Errorf("source contains a reserved metadata path: %s", path)
		}
		hashValue, size, err := hashFile(path)
		if err != nil {
			return err
		}
		if seenHashes[hashValue] {
			result.DuplicateFiles++
			return nil
		}
		seenHashes[hashValue] = true
		old := entriesByName[name]
		entriesByName[name] = Entry{Name: name, Size: size, Hash: hashValue, Tags: append([]string(nil), old.Tags...)}
		sourcePaths[name] = path
		return nil
	}); err != nil {
		return result, err
	}
	entries := make([]Entry, 0, len(entriesByName))
	for _, entry := range entriesByName {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for name, path := range sourcePaths {
		sources[name] = &lazyFileReader{path: path}
	}
	if !isV3 {
		if err := upgradeStreamV2ToV3(collectionPath, options.Key); err != nil {
			for _, source := range sources {
				if closer, ok := source.(io.Closer); ok {
					_ = closer.Close()
				}
			}
			return result, err
		}
		isV3 = true
	} else if !isWrappedStreamV3Header(header) {
		if err := upgradeStreamV3ToWrapped(collectionPath, options.Key); err != nil {
			for _, source := range sources {
				if closer, ok := source.(io.Closer); ok {
					_ = closer.Close()
				}
			}
			return result, err
		}
	}
	var writeErr error
	if isV3 {
		if _, statErr := os.Stat(collectionPath); os.IsNotExist(statErr) {
			writeErr = createStreamV3Atomically(collectionPath, header, aead, entries, tagCatalog, sources)
		} else {
			writeErr = appendStreamV3Transaction(collectionPath, options.Key, entries, tagCatalog, sources)
		}
	} else {
		writeErr = writeStreamAtomically(collectionPath, header, aead, oldEntries, entries, tagCatalog, sources)
	}
	if writeErr != nil {
		for _, source := range sources {
			if closer, ok := source.(io.Closer); ok {
				_ = closer.Close()
			}
		}
		return result, writeErr
	}
	for _, source := range sources {
		if closer, ok := source.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	if options.ClearSource {
		imported := make(map[string]string, len(sourcePaths))
		for name, path := range sourcePaths {
			entry := entriesByName[name]
			imported[path] = entry.Hash
		}
		result.ClearedFiles, err = clearImportedSourceFiles(imported)
		if err != nil {
			return result, fmt.Errorf("collection created, but source cleanup failed: %w", err)
		}
	}
	return result, nil
}

func (Service) Restore(options RestoreOptions) error {
	input, err := filepath.Abs(options.Collection)
	if err != nil {
		return err
	}
	output, err := filepath.Abs(options.Destination)
	if err != nil {
		return err
	}
	if directoriesOverlap(input, output) {
		return errors.New("collection and destination must not overlap")
	}
	session, err := (Service{}).OpenSession(input, options.Key)
	if err != nil {
		return err
	}
	defer session.Close()
	if err := os.MkdirAll(output, 0700); err != nil {
		return err
	}
	rootInfo, err := os.Lstat(output)
	if err != nil {
		return err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return errors.New("restore destination must be a real directory")
	}
	for _, item := range session.Items() {
		destination := filepath.Join(output, filepath.FromSlash(item.Name))
		if !isWithin(output, destination) {
			return fmt.Errorf("unsafe path in collection: %q", item.Name)
		}
		if err := makeSafeDirectories(output, filepath.Dir(destination)); err != nil {
			return err
		}
		if info, err := os.Lstat(destination); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to overwrite symbolic link: %s", destination)
		} else if err != nil && !os.IsNotExist(err) {
			return err
		}
		reader, err := session.Open(item.Name)
		if err != nil {
			return err
		}
		temp, err := os.CreateTemp(filepath.Dir(destination), ".vault-restore-*")
		if err != nil {
			_ = reader.Close()
			return err
		}
		tempPath := temp.Name()
		hasher := sha256.New()
		copied, copyErr := io.Copy(io.MultiWriter(temp, hasher), reader)
		readerErr := reader.Close()
		syncErr := temp.Sync()
		fileErr := temp.Close()
		if copyErr != nil {
			_ = os.Remove(tempPath)
			return copyErr
		}
		if copied != item.Size || hex.EncodeToString(hasher.Sum(nil)) != item.Hash {
			_ = os.Remove(tempPath)
			return fmt.Errorf("restored item %q failed size or SHA-256 verification", item.Name)
		}
		if readerErr != nil {
			_ = os.Remove(tempPath)
			return readerErr
		}
		if syncErr != nil {
			_ = os.Remove(tempPath)
			return syncErr
		}
		if fileErr != nil {
			_ = os.Remove(tempPath)
			return fileErr
		}
		if err := os.Rename(tempPath, destination); err != nil {
			_ = os.Remove(tempPath)
			return err
		}
	}
	return nil
}

func (Service) Open(path, key string) (Collection, error) {
	session, err := (Service{}).OpenSession(path, key)
	if err != nil {
		return Collection{}, err
	}
	defer session.Close()
	collection := Collection{Files: make(map[string][]byte), Tags: make(map[string][]string), TagCatalog: session.Tags()}
	for _, entry := range session.Items() {
		reader, err := session.Open(entry.Name)
		if err != nil {
			return Collection{}, err
		}
		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil {
			return Collection{}, readErr
		}
		if closeErr != nil {
			return Collection{}, closeErr
		}
		collection.Files[entry.Name] = data
		collection.Tags[entry.Name] = append([]string(nil), entry.Tags...)
	}
	return collection, nil
}

func (Service) Delete(path, key, name string) error {
	unlock, err := lockCollection(path)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ensureStreamFormatLocked(path, key); err != nil {
		return err
	}
	_, _, entries, _, err := readStreamIndex(path, key)
	if err != nil {
		return err
	}
	if _, exists := findEntry(entries, name); !exists {
		return errors.New("item no longer exists in the collection")
	}
	remaining := make([]Entry, 0, len(entries)-1)
	for _, entry := range entries {
		if entry.Name != name {
			remaining = append(remaining, entry)
		}
	}
	return rewriteStream(path, key, remaining)
}

// Compact rewrites a PVLT0003 collection with only live item records.
func (Service) Compact(path, key string) error {
	unlock, err := lockCollection(path)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ensureStreamFormatLocked(path, key); err != nil {
		return err
	}
	var magic [8]byte
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	_, readErr := io.ReadFull(file, magic[:])
	_ = file.Close()
	if readErr != nil {
		return readErr
	}
	if string(magic[:]) == streamMagic {
		if err := upgradeStreamV2ToV3(path, key); err != nil {
			return err
		}
	} else if string(magic[:]) != streamV3Magic {
		return errors.New("compaction requires a PVLT0002 or PVLT0003 collection")
	} else {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		header := make([]byte, streamV3WrappedSize)
		n, readErr := file.Read(header)
		_ = file.Close()
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if !isWrappedStreamV3Header(header[:n]) {
			if err := upgradeStreamV3ToWrapped(path, key); err != nil {
				return err
			}
		}
	}
	return compactStreamV3(path, key)
}

// ChangePassword rewraps the collection DEK without rewriting item payloads.
func (Service) ChangePassword(path, currentPassword, newPassword string) error {
	unlock, err := lockCollection(path)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ensureStreamFormatLocked(path, currentPassword); err != nil {
		return err
	}
	var magic [8]byte
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	_, readErr := io.ReadFull(file, magic[:])
	_ = file.Close()
	if readErr != nil {
		return readErr
	}
	if string(magic[:]) == streamMagic {
		if err := upgradeStreamV2ToV3(path, currentPassword); err != nil {
			return err
		}
	} else if string(magic[:]) == streamV3Magic {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		header := make([]byte, streamV3WrappedSize)
		n, readErr := file.Read(header)
		_ = file.Close()
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if !isWrappedStreamV3Header(header[:n]) {
			if err := upgradeStreamV3ToWrapped(path, currentPassword); err != nil {
				return err
			}
		}
	} else {
		return errors.New("password changes require a streaming collection")
	}
	return rewrapStreamV3Key(path, currentPassword, newPassword)
}

// RotateDataKey re-encrypts every live item with a fresh random DEK.
func (Service) RotateDataKey(path, password string) error {
	unlock, err := lockCollection(path)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ensureStreamFormatLocked(path, password); err != nil {
		return err
	}
	return rotateStreamV3DataKey(path, password)
}

// Verify reads and authenticates every live item in the collection.
func (Service) Verify(path, password string) error {
	session, err := (Service{}).OpenSession(path, password)
	if err != nil {
		return err
	}
	defer session.Close()
	for _, entry := range session.Items() {
		reader, err := session.Open(entry.Name)
		if err != nil {
			return fmt.Errorf("verify item %q: %w", entry.Name, err)
		}
		_, readErr := io.Copy(io.Discard, reader)
		closeErr := reader.Close()
		if readErr != nil {
			return fmt.Errorf("verify item %q: %w", entry.Name, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close item %q after verification: %w", entry.Name, closeErr)
		}
	}
	return nil
}

func (Service) AddTag(path, key, tag string, names []string) (int, error) {
	unlock, err := lockCollection(path)
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := ensureStreamFormatLocked(path, key); err != nil {
		return 0, err
	}
	_, _, entries, tags, err := readStreamIndex(path, key)
	if err != nil {
		return 0, err
	}
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return 0, errors.New("tag name cannot be empty")
	}
	definition, exists := findTagByName(tags, tag)
	if !exists {
		definition, err = newTag(tag)
		if err != nil {
			return 0, err
		}
		tags = append(tags, definition)
	}
	selected := make(map[string]bool, len(names))
	for _, name := range names {
		selected[name] = true
	}
	updated := 0
	for i := range entries {
		if !selected[entries[i].Name] {
			continue
		}
		if containsTag(entries[i].Tags, tag) {
			continue
		}
		entries[i].Tags = append(entries[i].Tags, definition.Name)
		updated++
	}
	if updated == 0 {
		return 0, nil
	}
	if err := rewriteStreamWithTags(path, key, entries, tags); err != nil {
		return 0, err
	}
	return updated, nil
}

func (Service) ListTags(path, key string) ([]Tag, error) {
	unlock, err := lockCollection(path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := ensureStreamFormatLocked(path, key); err != nil {
		return nil, err
	}
	_, _, _, tags, err := readStreamIndex(path, key)
	return tags, err
}

func (Service) CreateTag(path, key, name string) (Tag, error) {
	unlock, err := lockCollection(path)
	if err != nil {
		return Tag{}, err
	}
	defer unlock()
	if err := ensureStreamFormatLocked(path, key); err != nil {
		return Tag{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Tag{}, errors.New("tag name cannot be empty")
	}
	if len([]rune(name)) > 64 {
		return Tag{}, errors.New("tag name cannot exceed 64 characters")
	}
	_, _, entries, tags, err := readStreamIndex(path, key)
	if err != nil {
		return Tag{}, err
	}
	if existing, ok := findTagByName(tags, name); ok {
		return existing, nil
	}
	tag, err := newTag(name)
	if err != nil {
		return Tag{}, err
	}
	tags = append(tags, tag)
	if err := rewriteStreamWithTags(path, key, entries, tags); err != nil {
		return Tag{}, err
	}
	return tag, nil
}

func (Service) UpdateTag(path, key string, updated Tag) error {
	_, err := (Service{}).SaveTag(path, key, updated)
	return err
}

func (Service) SaveTag(path, key string, updated Tag) (Tag, error) {
	unlock, err := lockCollection(path)
	if err != nil {
		return Tag{}, err
	}
	defer unlock()
	if err := ensureStreamFormatLocked(path, key); err != nil {
		return Tag{}, err
	}
	updated.Name = strings.TrimSpace(updated.Name)
	if updated.Name == "" {
		return Tag{}, errors.New("tag name cannot be empty")
	}
	if len([]rune(updated.Name)) > 64 {
		return Tag{}, errors.New("tag name cannot exceed 64 characters")
	}
	if len(updated.Image) > 256<<10 {
		return Tag{}, errors.New("tag image cannot exceed 256 KiB")
	}
	if updated.Color != "" {
		if len(updated.Color) != 7 || updated.Color[0] != '#' {
			return Tag{}, errors.New("tag color must use #RRGGBB format")
		}
		if _, err := strconv.ParseUint(updated.Color[1:], 16, 24); err != nil {
			return Tag{}, errors.New("tag color must use #RRGGBB format")
		}
	}
	_, _, entries, tags, err := readStreamIndex(path, key)
	if err != nil {
		return Tag{}, err
	}
	var old Tag
	if updated.ID == "" {
		if _, exists := findTagByName(tags, updated.Name); exists {
			return Tag{}, errors.New("a tag with this name already exists")
		}
		created, createErr := newTag(updated.Name)
		if createErr != nil {
			return Tag{}, createErr
		}
		created.Color = updated.Color
		created.Image = append([]byte(nil), updated.Image...)
		updated = created
		tags = append(tags, updated)
	} else {
		var exists bool
		old, exists = findTagByID(tags, updated.ID)
		if !exists {
			return Tag{}, errors.New("tag does not exist")
		}
		if duplicate, exists := findTagByName(tags, updated.Name); exists && duplicate.ID != updated.ID {
			return Tag{}, errors.New("a tag with this name already exists")
		}
		for i := range tags {
			if tags[i].ID == updated.ID {
				tags[i] = updated
				break
			}
		}
	}
	if old.ID != "" && !strings.EqualFold(old.Name, updated.Name) {
		for i := range entries {
			for j, name := range entries[i].Tags {
				if strings.EqualFold(name, old.Name) {
					entries[i].Tags[j] = updated.Name
				}
			}
		}
	}
	if err := rewriteStreamWithTags(path, key, entries, tags); err != nil {
		return Tag{}, err
	}
	return updated, nil
}

func (Service) DeleteTag(path, key, tagID string) error {
	unlock, err := lockCollection(path)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ensureStreamFormatLocked(path, key); err != nil {
		return err
	}
	_, _, entries, tags, err := readStreamIndex(path, key)
	if err != nil {
		return err
	}
	tag, exists := findTagByID(tags, tagID)
	if !exists {
		return errors.New("tag does not exist")
	}
	remainingTags := make([]Tag, 0, len(tags)-1)
	for _, candidate := range tags {
		if candidate.ID != tag.ID {
			remainingTags = append(remainingTags, candidate)
		}
	}
	for i := range entries {
		entries[i].Tags = removeTagName(entries[i].Tags, tag.Name)
	}
	return rewriteStreamWithTags(path, key, entries, remainingTags)
}

func (Service) AssignTag(path, key, tagID string, names []string) (int, error) {
	return updateTagAssignments(path, key, tagID, names, true)
}

func (Service) RemoveTagFromItems(path, key, tagID string, names []string) (int, error) {
	return updateTagAssignments(path, key, tagID, names, false)
}

func updateTagAssignments(path, key, tagID string, names []string, assign bool) (int, error) {
	unlock, err := lockCollection(path)
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := ensureStreamFormatLocked(path, key); err != nil {
		return 0, err
	}
	_, _, entries, tags, err := readStreamIndex(path, key)
	if err != nil {
		return 0, err
	}
	tag, exists := findTagByID(tags, tagID)
	if !exists {
		return 0, errors.New("tag does not exist")
	}
	selected := make(map[string]bool, len(names))
	for _, name := range names {
		selected[name] = true
	}
	updated := 0
	for i := range entries {
		if !selected[entries[i].Name] {
			continue
		}
		if assign {
			if containsTag(entries[i].Tags, tag.Name) {
				continue
			}
			entries[i].Tags = append(entries[i].Tags, tag.Name)
		} else {
			updatedTags := removeTagName(entries[i].Tags, tag.Name)
			if len(updatedTags) == len(entries[i].Tags) {
				continue
			}
			entries[i].Tags = updatedTags
		}
		updated++
	}
	if updated == 0 {
		return 0, nil
	}
	if err := rewriteStreamWithTags(path, key, entries, tags); err != nil {
		return 0, err
	}
	return updated, nil
}

func findTagByID(tags []Tag, id string) (Tag, bool) {
	for _, tag := range tags {
		if tag.ID == id {
			return tag, true
		}
	}
	return Tag{}, false
}

func findTagByName(tags []Tag, name string) (Tag, bool) {
	for _, tag := range tags {
		if strings.EqualFold(tag.Name, strings.TrimSpace(name)) {
			return tag, true
		}
	}
	return Tag{}, false
}

func removeTagName(tags []string, target string) []string {
	remaining := make([]string, 0, len(tags))
	for _, tag := range tags {
		if !strings.EqualFold(tag, target) {
			remaining = append(remaining, tag)
		}
	}
	return remaining
}

func findEntry(entries []Entry, name string) (Entry, bool) {
	for _, entry := range entries {
		if entry.Name == name {
			return entry, true
		}
	}
	return Entry{}, false
}

func readExistingCollection(path, key string) (map[string][]byte, error) {
	if _, err := os.Stat(path); err == nil {
		return readRawCollection(path, key)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return make(map[string][]byte), nil
}

func hashCounts(files map[string][]byte) map[[32]byte]int {
	seen := make(map[[32]byte]int, len(files))
	for name, data := range files {
		if name != metadataPath {
			seen[sha256.Sum256(data)]++
		}
	}
	return seen
}

func addFolderContents(root string, files map[string][]byte, seen map[[32]byte]int, result *CreateResult) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			result.SkippedSymlinks++
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("only regular files are supported: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == metadataPath {
			return fmt.Errorf("source contains a reserved metadata path: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(data)
		if seen[hash] > 0 {
			result.DuplicateFiles++
			return nil
		}
		if old, exists := files[relative]; exists {
			oldHash := sha256.Sum256(old)
			seen[oldHash]--
			if seen[oldHash] == 0 {
				delete(seen, oldHash)
			}
		}
		files[relative] = data
		seen[hash]++
		return nil
	})
}

func clearImportedSourceFiles(imported map[string]string) (int, error) {
	cleared := 0
	for path, expectedHash := range imported {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return cleared, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		hashValue, _, err := hashFile(path)
		if err != nil {
			return cleared, err
		}
		if hashValue != expectedHash {
			continue
		}
		if err := os.Remove(path); err != nil {
			return cleared, err
		}
		cleared++
	}
	return cleared, nil
}

type lazyFileReader struct {
	path string
	file *os.File
}

func (r *lazyFileReader) Read(p []byte) (int, error) {
	if r.file == nil {
		f, err := os.Open(r.path)
		if err != nil {
			return 0, err
		}
		r.file = f
	}
	n, err := r.file.Read(p)
	if err == io.EOF {
		_ = r.file.Close()
		r.file = nil
	}
	return n, err
}
func (r *lazyFileReader) Close() error {
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

func makeSafeDirectories(root, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("unsafe destination path")
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0700); err != nil && !os.IsExist(err) {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("unsafe destination directory: %s", current)
		}
	}
	return nil
}

func directoriesOverlap(first, second string) bool {
	return first == second || isWithin(first, second) || isWithin(second, first)
}

func isWithin(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
