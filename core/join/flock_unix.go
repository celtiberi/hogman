//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

// acquireShareLock takes a non-blocking advisory flock on <dir>/share.lock so
// two share processes cannot run against the same state directory, while an
// unclean container restart (including PID 1) never deadlocks on a stale PID file.
func acquireShareLock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "share.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errorf("share state directory %s is already locked by another running hogman process", dir)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
