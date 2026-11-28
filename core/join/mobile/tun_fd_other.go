//go:build !linux && !android && !darwin && !ios

package mobile

import "github.com/tailscale/wireguard-go/tun"

func openTUNFromFD(_, _ int) (tun.Device, error) {
	return nil, errTUNFDUnsupported
}
