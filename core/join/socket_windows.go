//go:build windows

package main

import (
	"context"
	"net"
)

func validateUnixSocketPath(raw string) (string, error) {
	return "", errorf("unix:// share targets (%q) are only supported on Linux and macOS", raw)
}

func verifyUnixSocketNoSymlink(sockPath string) error {
	return errorf("unix:// share targets (%q) are only supported on Linux and macOS", sockPath)
}

func unixSocketDialContext(sockPath string) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, errorf("unix:// share targets (%q) are only supported on Linux and macOS", sockPath)
	}
}
