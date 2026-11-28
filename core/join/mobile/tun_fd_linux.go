//go:build linux || android

package mobile

import (
	"fmt"

	"github.com/tailscale/wireguard-go/tun"
)

func openTUNFromFD(fd, _ int) (tun.Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("invalid TUN fd %d", fd)
	}
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return dev, err
}
