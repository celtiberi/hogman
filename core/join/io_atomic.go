package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// writeFileAtomic writes data to a temporary file in path's parent directory,
// applies mode, fsyncs, and atomically renames it into place so concurrent
// readers never observe partial or truncated state/config/service files.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	dirMode := os.FileMode(0o755)
	if mode&0o077 == 0 {
		dirMode = 0o700
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".hogman-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	keep = true
	return nil
}

func daemonLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

func slogLogf(logger *slog.Logger, component string) func(string, ...any) {
	if logger == nil {
		logger = slog.Default()
	}
	return func(format string, args ...any) {
		logger.Debug(fmt.Sprintf(format, args...), "component", component)
	}
}
