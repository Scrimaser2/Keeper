//go:build !windows

package vault

import "os"

func openSnapshotFile(path string) (*os.File, error) { return os.Open(path) }
