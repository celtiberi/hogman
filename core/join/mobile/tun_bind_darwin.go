//go:build darwin || ios

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

// newTunnelBoundDialer returns a TCP dialer pinned strictly to the active utun
// interface (IP_BOUND_IF) and local mesh IPv4 address. On iOS NetworkExtension,
// an unbound dialer bypasses the extension's own utun and leaks 100.64/10
// packets onto the carrier network; this dialer fails closed if utun is absent.
func newTunnelBoundDialer(selfIPv4 netip.Addr, tunName string, timeout time.Duration) (*net.Dialer, error) {
	if !selfIPv4.IsValid() || !selfIPv4.Is4() {
		return nil, errors.New("tunnel IPv4 address is not available")
	}
	if tunName == "" {
		return nil, errors.New("tunnel interface name is not available")
	}
	iface, err := net.InterfaceByName(tunName)
	if err != nil {
		return nil, fmt.Errorf("lookup tunnel interface %q: %w", tunName, err)
	}
	ifindex := iface.Index
	return &net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: selfIPv4.AsSlice()},
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifindex)
			}); err != nil {
				return err
			}
			if sockErr != nil {
				return fmt.Errorf("bind socket to %s (IP_BOUND_IF): %w", tunName, sockErr)
			}
			return nil
		},
	}, nil
}
