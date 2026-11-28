//go:build !linux && !android && !darwin && !ios

package mobile

import (
	"errors"

	"github.com/tailscale/wireguard-go/tun"
)

var errTUNFDUnsupported = errors.New("TUN file descriptors are unsupported on this platform")

func openTUNFromFD(_, _ int) (tun.Device, error) {
	return nil, errTUNFDUnsupported
}
