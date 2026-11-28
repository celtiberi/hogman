//go:build linux && !android

package mobile

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// newTunnelBoundDialer binds outbound pen-management TCP sockets to the active
// TUN interface (SO_BINDTODEVICE) and local mesh IPv4 address, failing closed
// if the interface is absent.
func newTunnelBoundDialer(selfIPv4 netip.Addr, tunName string, timeout time.Duration) (*net.Dialer, error) {
	if !selfIPv4.IsValid() || !selfIPv4.Is4() {
		return nil, errors.New("tunnel IPv4 address is not available")
	}
	if tunName == "" {
		return nil, errors.New("tunnel interface name is not available")
	}
	return &net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: selfIPv4.AsSlice()},
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, tunName)
			}); err != nil {
				return err
			}
			if sockErr != nil {
				return fmt.Errorf("bind socket to %s (SO_BINDTODEVICE): %w", tunName, sockErr)
			}
			return nil
		},
	}, nil
}
