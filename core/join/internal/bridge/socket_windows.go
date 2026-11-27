//go:build windows

package bridge

import (
	"context"
	"net"

	"hogman/join/internal/link"
)

func ValidateUnixSocketPath(raw string) (string, error) {
	return "", link.Errorf("unix:// share targets (%q) are only supported on Linux and macOS", raw)
}

func VerifyUnixSocketNoSymlink(sockPath string) error {
	return link.Errorf("unix:// share targets (%q) are only supported on Linux and macOS", sockPath)
}

func UnixSocketDialContext(sockPath string) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, link.Errorf("unix:// share targets (%q) are only supported on Linux and macOS", sockPath)
	}
}
