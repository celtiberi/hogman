//go:build android || (!darwin && !ios && !linux)

package mobile

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// newTunnelBoundDialer verifies that selfIPv4 is actively assigned to a local
// interface by probing a local bind (avoiding net.Interfaces / NETLINK_ROUTE,
// which Android 11+ SELinux denies to app UIDs) and pins LocalAddr to selfIPv4.
// If the VPN TUN interface is absent or revoked, bind fails closed with
// EADDRNOTAVAIL before any packet leaves the host.
func newTunnelBoundDialer(selfIPv4 netip.Addr, _ string, timeout time.Duration) (*net.Dialer, error) {
	if !selfIPv4.IsValid() || !selfIPv4.Is4() {
		return nil, errors.New("tunnel IPv4 address is not available")
	}
	if !canBindLocalIPv4(selfIPv4) {
		return nil, fmt.Errorf("tunnel IPv4 %s is not active on any local interface", selfIPv4)
	}
	return &net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: selfIPv4.AsSlice()},
	}, nil
}

func canBindLocalIPv4(ip netip.Addr) bool {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip.AsSlice(), Port: 0})
	if err != nil {
		return false
	}
	_ = pc.Close()
	return true
}
