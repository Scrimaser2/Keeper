//go:build windows

package vault

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func lockCollection(path string) (func(), error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Clean(abs)+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return func() { _ = windows.UnlockFileEx(windows.Handle(lock.Fd()), 0, 1, 0, &overlapped); _ = lock.Close() }, nil
}
