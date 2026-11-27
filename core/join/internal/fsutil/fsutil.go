package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// WriteFileAtomic writes data to a temporary file in path's parent directory,
// applies mode, fsyncs, and atomically renames it into place so concurrent
// readers never observe partial or truncated state/config/service files.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
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

// CopyExecutableAtomic copies src to a temporary sibling file beside dst,
// chmods it 0755, and atomically replaces dst.
func CopyExecutableAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".hogman-bin-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := ReplaceExecutable(tmpPath, dst); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// FileSHA256 returns the lowercase hex SHA-256 digest of the file at path.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return strings.ToLower(hex.EncodeToString(h.Sum(nil))), nil
}

// ResolvedExePath returns the symlink-resolved path of the running executable.
func ResolvedExePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if realPath, err := filepath.EvalSymlinks(exe); err == nil {
		return filepath.Clean(realPath), nil
	}
	return filepath.Clean(exe), nil
}

// SameFilePath reports whether a and b refer to the same path or underlying file.
func SameFilePath(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}

// DaemonLogger returns a structured text slog.Logger writing to stderr.
func DaemonLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// SlogLogf adapts a *slog.Logger to printf-style callbacks (e.g. tsnet.Server.Logf).
func SlogLogf(logger *slog.Logger, component string) func(string, ...any) {
	if logger == nil {
		logger = slog.Default()
	}
	return func(format string, args ...any) {
		logger.Debug(fmt.Sprintf(format, args...), "component", component)
	}
}
