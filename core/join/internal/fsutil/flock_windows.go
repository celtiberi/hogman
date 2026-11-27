//go:build windows

package fsutil

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrLocked reports that a state directory is already held by another process.
var ErrLocked = errors.New("state directory already locked")

// AcquireShareLock ensures dir exists on Windows, where sharePID + processAlive
// guards live share processes.
func AcquireShareLock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = filepath.Join(dir, "share.lock")
	return func() {}, nil
}
