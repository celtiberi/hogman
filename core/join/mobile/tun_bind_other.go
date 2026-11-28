//go:build android || (!darwin && !ios && !linux)

package mobile

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// newTunnelBoundDialer verifies that selfIPv4 is actively assigned to an UP
// local interface (the Android VpnService TUN) and pins LocalAddr to selfIPv4.
// Unprivileged Android apps cannot call SO_BINDTODEVICE, so combining confirmed
// per-peer /32 VPN routes with LocalAddr=selfIPv4 fails closed with
// EADDRNOTAVAIL if the TUN interface is absent or revoked.
func newTunnelBoundDialer(selfIPv4 netip.Addr, _ string, timeout time.Duration) (*net.Dialer, error) {
	if !selfIPv4.IsValid() || !selfIPv4.Is4() {
		return nil, errors.New("tunnel IPv4 address is not available")
	}
	if !localInterfaceHasIPv4(selfIPv4) {
		return nil, fmt.Errorf("tunnel IPv4 %s is not active on any local interface", selfIPv4)
	}
	return &net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: selfIPv4.AsSlice()},
	}, nil
}

func localInterfaceHasIPv4(want netip.Addr) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipNet.IP)
			if ok && addr.Unmap() == want {
				return true
			}
		}
	}
	return false
}
