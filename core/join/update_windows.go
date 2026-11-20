package main

import "os"

func serviceConfigured(string) bool { return false }

func replaceExecutable(tmpPath, dstPath string) error {
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
