//go:build windows

package fsutil

import "os"

// ReplaceExecutable swaps a running Windows executable by moving the current
// binary aside to dstPath.old before renaming tmpPath into place.
func ReplaceExecutable(tmpPath, dstPath string) error {
	oldPath := dstPath + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(tmpPath, dstPath); err == nil {
		return nil
	}
	if _, err := os.Stat(dstPath); err != nil {
		return os.Rename(tmpPath, dstPath)
	}
	if err := os.Rename(dstPath, oldPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Rename(oldPath, dstPath)
		return err
	}
	_ = os.Remove(oldPath)
	return nil
}
