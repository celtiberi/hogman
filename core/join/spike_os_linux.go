//go:build linux

package main

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/tailscale/wireguard-go/tun"
)

func setupSpikeTUN(subnet netip.Prefix, localIP, dnsIP netip.Addr, mtu int, zones []string) (tun.Device, func(), error) {
	dev, err := tun.CreateTUN("hogman0", mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("create tun hogman0: %w", err)
	}
	ifname, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, nil, fmt.Errorf("tun name: %w", err)
	}
	hasResolvectl := false
	cleanup := func() {
		if hasResolvectl {
			_ = runPrivileged("resolvectl", "revert", ifname)
		}
		_ = runPrivileged("ip", "link", "set", "dev", ifname, "down")
		_ = dev.Close()
	}

	addrCIDR := fmt.Sprintf("%s/%d", localIP.String(), subnet.Bits())
	if err := runPrivileged("ip", "addr", "replace", addrCIDR, "dev", ifname); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("ip addr replace %s: %w", addrCIDR, err)
	}
	if err := runPrivileged("ip", "link", "set", "dev", ifname, "mtu", fmt.Sprintf("%d", mtu), "up"); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("ip link up %s: %w", ifname, err)
	}

	if _, err := exec.LookPath("resolvectl"); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("resolvectl not found (systemd-resolved required for Linux spike)")
	}
	if err := runPrivileged("resolvectl", "dns", ifname, dnsIP.String()); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("resolvectl dns %s: %w", ifname, err)
	}
	hasResolvectl = true
	if len(zones) > 0 {
		domArgs := make([]string, 0, 2+len(zones))
		domArgs = append(domArgs, "domain", ifname)
		for _, z := range zones {
			domArgs = append(domArgs, "~"+z)
		}
		if err := runPrivileged("resolvectl", domArgs...); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("resolvectl domain %s: %w", ifname, err)
		}
	}
	if err := runPrivileged("resolvectl", "default-route", ifname, "false"); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("resolvectl default-route %s: %w", ifname, err)
	}
	_ = runPrivileged("resolvectl", "dnssec", ifname, "no")
	return dev, cleanup, nil
}

func runPrivileged(bin string, args ...string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}
