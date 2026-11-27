package catalog

import (
	"path/filepath"
	"strings"
)

// IsHiddenPath reports whether a relative path contains a hidden component.
func IsHiddenPath(name string) bool {
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}
