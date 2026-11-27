//go:build windows

package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// ErrLocked reports that a state directory is already held by another process.
var ErrLocked = errors.New("state directory already locked")

// AcquireShareLock takes a non-blocking exclusive LockFileEx lock on
// <dir>/share.lock so two share processes cannot run against the same state
// directory, while a crashed process releases the lock automatically when the
// kernel closes its handle.
func AcquireShareLock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "share.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, new(windows.Overlapped)); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s", ErrLocked, dir)
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
		_ = f.Close()
	}, nil
}
