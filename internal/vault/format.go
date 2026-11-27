package vault

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	magic      = "PVLT0001"
	saltSize   = 16
	nonceSize  = 12
	iterations = 250000
)

func readRawCollection(path, key string) (map[string][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decode(data, key)
}

func openCollection(path, key string) (Collection, error) {
	files, err := readRawCollection(path, key)
	if err != nil {
		return Collection{}, err
	}
	metadata, err := decodeMetadata(files)
	if err != nil {
		return Collection{}, err
	}
	delete(files, metadataPath)
	return Collection{Files: files, Tags: metadata.Tags}, nil
}

func writeCollection(path string, files map[string][]byte, key string) error {
	data, err := encode(files, key)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".vault-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func encode(files map[string][]byte, password string) ([]byte, error) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for name, data := range files {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
		if clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
			return nil, fmt.Errorf("unsafe file path %q", name)
		}
		entry, err := writer.Create(clean)
		if err != nil {
			return nil, err
		}
		if _, err := entry.Write(data); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	salt := make([]byte, saltSize)
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(deriveKey([]byte(password), salt, iterations))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	header := append([]byte(magic), salt...)
	header = append(header, nonce...)
	sealed := aead.Seal(nil, nonce, archive.Bytes(), header)
	var result bytes.Buffer
	result.Write(header)
	if err := binary.Write(&result, binary.BigEndian, uint64(iterations)); err != nil {
		return nil, err
	}
	result.Write(sealed)
	return result.Bytes(), nil
}

func decode(data []byte, password string) (map[string][]byte, error) {
	const headerLength = 8 + saltSize + nonceSize + 8
	if len(data) < headerLength || string(data[:8]) != magic {
		return nil, errors.New("not a supported vault file")
	}
	salt := data[8 : 8+saltSize]
	nonce := data[8+saltSize : 8+saltSize+nonceSize]
	iterations := binary.BigEndian.Uint64(data[8+saltSize+nonceSize : headerLength])
	if iterations < 10000 || iterations > 2000000 {
		return nil, errors.New("invalid key derivation parameters")
	}
	header := data[:8+saltSize+nonceSize]
	block, err := aes.NewCipher(deriveKey([]byte(password), salt, int(iterations)))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, data[headerLength:], header)
	if err != nil {
		return nil, errors.New("decryption failed (wrong key or damaged vault)")
	}
	reader, err := zip.NewReader(bytes.NewReader(plain), int64(len(plain)))
	if err != nil {
		return nil, err
	}
	if len(reader.File) > 100_000 {
		return nil, errors.New("legacy collection contains too many items for safe migration")
	}
	var totalUncompressed uint64
	for _, file := range reader.File {
		if file.UncompressedSize64 > uint64(maxLegacySize)-totalUncompressed {
			return nil, fmt.Errorf("legacy collection expands beyond the %d MiB safe migration limit", maxLegacySize>>20)
		}
		totalUncompressed += file.UncompressedSize64
	}
	files := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		name := filepath.ToSlash(filepath.Clean(filepath.FromSlash(file.Name)))
		if name == "." || strings.HasPrefix(name, "../") || filepath.IsAbs(name) {
			return nil, fmt.Errorf("unsafe path in vault: %q", file.Name)
		}
		entry, err := file.Open()
		if err != nil {
			return nil, err
		}
		content, readErr := io.ReadAll(entry)
		closeErr := entry.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		files[name] = content
	}
	return files, nil
}

// deriveKey implements PBKDF2-HMAC-SHA256 using only the standard library.
func deriveKey(password, salt []byte, rounds int) []byte {
	mac := hmac.New(sha256.New, password)
	input := make([]byte, len(salt)+4)
	copy(input, salt)
	binary.BigEndian.PutUint32(input[len(salt):], 1)
	_, _ = mac.Write(input)
	u := mac.Sum(nil)
	output := append([]byte(nil), u...)
	for round := 1; round < rounds; round++ {
		mac.Reset()
		_, _ = mac.Write(u)
		u = mac.Sum(nil)
		for i := range output {
			output[i] ^= u[i]
		}
	}
	return output
}
