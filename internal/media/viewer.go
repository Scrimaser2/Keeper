package media

import (
	"bytes"
	"fmt"
	"image"
	_ "image/png"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

type Viewer struct{}

// DecodeImage uses macOS ImageIO as a fallback for formats that Go's image
// decoders do not support, while keeping the encrypted source streamed to disk.
func DecodeImage(name string, source io.Reader, maxPixels int64, maxDimension int) (image.Image, error) {
	helper, err := helperPath()
	if err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp("", "library-image-decode-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, filepath.Base(name))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	_, copyErr := io.Copy(file, source)
	closeErr := file.Close()
	if copyErr != nil {
		return nil, copyErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	command := exec.Command(helper, "thumbnail", path, directory, strconv.FormatInt(maxPixels, 10), strconv.Itoa(maxDimension))
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("macOS image decoder failed: %w", err)
	}
	decoded, _, err := image.Decode(bytes.NewReader(output))
	return decoded, err
}

func (Viewer) Open(kind, name string, data io.ReadCloser) error {
	if data == nil {
		return fmt.Errorf("missing item data")
	}
	defer data.Close()
	helper, err := helperPath()
	if err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", "library-preview-")
	if err != nil {
		return err
	}
	path := filepath.Join(directory, filepath.Base(name))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		_ = os.RemoveAll(directory)
		return err
	}
	_, copyErr := io.Copy(file, data)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.RemoveAll(directory)
		return copyErr
	}
	if closeErr != nil {
		_ = os.RemoveAll(directory)
		return closeErr
	}
	command := exec.Command(helper, kind, path, directory)
	if err := command.Start(); err != nil {
		_ = os.RemoveAll(directory)
		return err
	}
	go func() {
		_ = command.Wait()
		_ = os.RemoveAll(directory)
	}()
	return nil
}

func helperPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	contents := filepath.Dir(filepath.Dir(executable))
	helper := filepath.Join(contents, "Helpers", "LibraryMediaViewer")
	if _, err := os.Stat(helper); err != nil {
		return "", fmt.Errorf("embedded media viewer is unavailable: %w", err)
	}
	return helper, nil
}
