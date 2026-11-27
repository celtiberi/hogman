//go:build !windows

package fsutil

import "os"

// ReplaceExecutable atomically replaces dstPath with tmpPath on Unix systems.
func ReplaceExecutable(tmpPath, dstPath string) error {
	return os.Rename(tmpPath, dstPath)
}
