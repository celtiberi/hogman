//go:build !darwin && !linux

package main

import (
	"fmt"
	"net/netip"
	"runtime"

	"github.com/tailscale/wireguard-go/tun"
)

func setupSpikeTUN(_ netip.Prefix, _, _ netip.Addr, _ int, _ []string) (tun.Device, func(), error) {
	return nil, nil, fmt.Errorf("spike-tun is only implemented for macOS and Linux (not %s)", runtime.GOOS)
}
