//go:build darwin

package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tailscale/wireguard-go/tun"
)

const spikeResolverMarker = "# Managed by hogman-join spike\n"

type spikeOSState struct {
	ifname        string
	subnet        netip.Prefix
	resolverFiles []string
}

func setupSpikeTUN(subnet netip.Prefix, localIP, dnsIP netip.Addr, mtu int, zones []string) (tun.Device, func(), error) {
	dev, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("create utun: %w", err)
	}
	ifname, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, nil, fmt.Errorf("utun name: %w", err)
	}
	st := &spikeOSState{ifname: ifname, subnet: subnet.Masked()}
	cleanup := func() {
		for _, p := range st.resolverFiles {
			if b, err := os.ReadFile(p); err == nil && strings.HasPrefix(string(b), spikeResolverMarker) {
				_ = os.Remove(p)
			}
		}
		_ = runPrivileged("route", "-n", "delete", "-net", st.subnet.String(), "-interface", st.ifname)
		_ = dev.Close()
	}

	mask := prefixNetmask4(subnet.Bits())
	if err := runPrivileged("ifconfig", ifname, "inet", localIP.String(), localIP.String(), "netmask", mask, "mtu", fmt.Sprintf("%d", mtu), "up"); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("ifconfig %s: %w", ifname, err)
	}
	if err := runPrivileged("route", "-n", "add", "-net", st.subnet.String(), "-interface", ifname); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("route add %s: %w", st.subnet, err)
	}

	if err := os.MkdirAll("/etc/resolver", 0o755); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("mkdir /etc/resolver: %w", err)
	}
	body := []byte(spikeResolverMarker + "nameserver " + dnsIP.String() + "\n")
	for _, z := range zones {
		p := filepath.Join("/etc/resolver", z)
		if existing, err := os.ReadFile(p); err == nil && !bytes.HasPrefix(existing, []byte(spikeResolverMarker)) {
			cleanup()
			return nil, nil, fmt.Errorf("refusing to overwrite existing %s (not managed by hogman spike)", p)
		}
		if err := os.WriteFile(p, body, 0o644); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("write %s: %w", p, err)
		}
		st.resolverFiles = append(st.resolverFiles, p)
	}
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

func prefixNetmask4(bits int) string {
	var m uint32
	if bits > 0 {
		m = ^uint32(0) << (32 - bits)
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(m>>24), byte(m>>16), byte(m>>8), byte(m))
}
