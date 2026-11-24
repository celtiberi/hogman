//go:build !windows

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// validateUnixSocketPath checks that sockPath is a clean absolute filesystem
// Unix socket path (never an abstract Linux @socket, relative path, or "..").
func validateUnixSocketPath(raw string) (string, error) {
	if raw == "" || strings.ContainsRune(raw, 0) {
		return "", errorf("invalid Unix socket path %q", raw)
	}
	if strings.HasPrefix(raw, "@") {
		return "", errorf("abstract Unix sockets (%q) are not allowed; use a filesystem path", raw)
	}
	if !strings.HasPrefix(raw, "/") {
		return "", errorf("Unix socket path %q must be absolute (unix:///path/to/app.sock)", raw)
	}
	for _, seg := range strings.Split(raw, "/") {
		if seg == ".." {
			return "", errorf("Unix socket path %q must not contain '..'", raw)
		}
	}
	clean := filepath.Clean(raw)
	if clean == "/" || strings.HasSuffix(raw, "/") {
		return "", errorf("Unix socket path %q must name a socket file, not a directory", raw)
	}
	return clean, nil
}

// verifyUnixSocketNoSymlink ensures neither sockPath nor its parent directory
// entry is a symlink and that sockPath is an actual Unix domain socket.
func verifyUnixSocketNoSymlink(sockPath string) error {
	parent := filepath.Dir(sockPath)
	pfi, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if pfi.Mode()&os.ModeSymlink != 0 || !pfi.IsDir() {
		return errorf("refusing Unix socket %q: parent %q must be a real directory (not a symlink)", sockPath, parent)
	}
	fi, err := os.Lstat(sockPath)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errorf("refusing Unix socket %q: symlinks are not allowed", sockPath)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return errorf("refusing %q: not a Unix domain socket", sockPath)
	}
	return nil
}

// unixSocketDialContext returns a DialContext that dials sockPath over AF_UNIX
// after verifying the path and parent directory are not symlinks.
func unixSocketDialContext(sockPath string) func(context.Context, string, string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		if err := verifyUnixSocketNoSymlink(sockPath); err != nil {
			return nil, err
		}
		return d.DialContext(ctx, "unix", sockPath)
	}
}
