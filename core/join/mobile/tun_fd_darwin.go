//go:build darwin || ios

package mobile

import (
	"fmt"
	"os"

	"github.com/tailscale/wireguard-go/tun"
)

func openTUNFromFD(fd, mtu int) (tun.Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("invalid TUN fd %d", fd)
	}
	if mtu < MinTunnelMTU || mtu > MaxTunnelMTU {
		mtu = DefaultTunnelMTU
	}
	f := os.NewFile(uintptr(fd), "utun")
	if f == nil {
		return nil, fmt.Errorf("could not wrap utun fd %d", fd)
	}
	return tun.CreateTUNFromFile(f, mtu)
}
