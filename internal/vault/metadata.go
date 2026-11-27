package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const metadataPath = "__LIBRARY_INTERNAL__/tags.json"

type metadata struct {
	Tags       map[string][]string `json:"tags"`
	TagCatalog []Tag               `json:"tag_catalog,omitempty"`
}

// Tag is a collection-level label that can be attached to any number of items.
type Tag struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color,omitempty"`
	Image []byte `json:"image,omitempty"`
}

func decodeMetadata(files map[string][]byte) (metadata, error) {
	result := metadata{Tags: make(map[string][]string)}
	data, exists := files[metadataPath]
	if !exists {
		return result, nil
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return result, fmt.Errorf("invalid collection metadata: %w", err)
	}
	if result.Tags == nil {
		result.Tags = make(map[string][]string)
	}
	return result, nil
}

func encodeMetadata(files map[string][]byte, value metadata) error {
	if len(value.Tags) == 0 {
		delete(files, metadataPath)
		return nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	files[metadataPath] = data
	return nil
}

func containsTag(tags []string, tag string) bool {
	for _, existing := range tags {
		if strings.EqualFold(existing, tag) {
			return true
		}
	}
	return false
}

func tagsFromMap(attached map[string][]string) []Tag {
	names := make([]string, 0)
	for _, tags := range attached {
		names = append(names, tags...)
	}
	return tagsFromNames(names)
}

func tagsFromEntries(entries []Entry) []Tag {
	names := make([]string, 0)
	for _, entry := range entries {
		names = append(names, entry.Tags...)
	}
	return tagsFromNames(names)
}

func tagsFromNames(names []string) []Tag {
	unique := make(map[string]string, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, exists := unique[key]; !exists {
			unique[key] = name
		}
	}
	tags := make([]Tag, 0, len(unique))
	for _, name := range unique {
		tags = append(tags, Tag{ID: legacyTagID(name), Name: name})
	}
	sort.Slice(tags, func(i, j int) bool { return strings.ToLower(tags[i].Name) < strings.ToLower(tags[j].Name) })
	return tags
}

func makeTagCatalog(definitions, attached []Tag) []Tag {
	byName := make(map[string]Tag, len(definitions)+len(attached))
	byID := make(map[string]bool, len(definitions)+len(attached))
	for _, candidate := range append(append([]Tag(nil), definitions...), attached...) {
		name := strings.TrimSpace(candidate.Name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, exists := byName[key]; exists {
			continue
		}
		id := strings.TrimSpace(candidate.ID)
		if id == "" || byID[id] {
			id = legacyTagID(name)
		}
		if byID[id] {
			continue
		}
		byID[id] = true
		candidate.ID = id
		candidate.Name = name
		candidate.Image = append([]byte(nil), candidate.Image...)
		byName[key] = candidate
	}
	tags := make([]Tag, 0, len(byName))
	for _, tag := range byName {
		tags = append(tags, tag)
	}
	sort.Slice(tags, func(i, j int) bool { return strings.ToLower(tags[i].Name) < strings.ToLower(tags[j].Name) })
	return tags
}

func newTag(name string) (Tag, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Tag{}, err
	}
	return Tag{ID: hex.EncodeToString(id[:]), Name: strings.TrimSpace(name)}, nil
}

func legacyTagID(name string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name))))
	return "legacy-" + hex.EncodeToString(sum[:8])
}
