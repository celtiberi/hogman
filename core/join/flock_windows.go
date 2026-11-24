//go:build windows

package main

import (
	"os"
	"path/filepath"
)

func acquireShareLock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// On Windows, sharePID + processAlive already guards live share processes.
	_ = filepath.Join(dir, "share.lock")
	return func() {}, nil
}
