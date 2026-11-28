//go:build android

package mobile

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
)

var (
	androidProtectMu sync.RWMutex
	androidProtectFn func(fd int) error
)

func init() {
	// Android 11+ (API 30+) SELinux blocks NETLINK_ROUTE for untrusted apps,
	// causing net.Interfaces() (and therefore netmon.New) to fail with
	// "netlinkrib: permission denied". Register a route-probe interface getter
	// (no packets transmitted) matching tailscale.com/feature/androidbin.
	netmon.RegisterInterfaceGetter(androidInterfaces)
}

func registerPlatformProtectFunc(fn func(fd int) error) {
	androidProtectMu.Lock()
	androidProtectFn = fn
	androidProtectMu.Unlock()
	netns.SetAndroidProtectFunc(fn)
}

func androidInterfaces() ([]netmon.Interface, error) {
	androidProtectMu.RLock()
	protect := androidProtectFn
	androidProtectMu.RUnlock()

	var addrs []net.Addr
	if ip, ok := probeOutboundIP(protect, "udp4", "8.8.8.8:53"); ok {
		addrs = append(addrs, &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(32, 32)})
	}
	if ip, ok := probeOutboundIP(protect, "udp6", "[2001:4860:4860::8888]:53"); ok {
		addrs = append(addrs, &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(128, 128)})
	}
	return []netmon.Interface{{
		Interface: &net.Interface{
			Index: 1,
			MTU:   1500,
			Name:  "android",
			Flags: net.FlagUp | net.FlagRunning,
		},
		AltAddrs: addrs,
	}}, nil
}

// probeOutboundIP asks the kernel to pick a local source address for an
// unconnected UDP dial (performs no network I/O).
func probeOutboundIP(protect func(fd int) error, network, target string) (netip.Addr, bool) {
	d := newProtectedDialer(protect)
	d.Timeout = 2 * time.Second
	c, err := d.Dial(network, target)
	if err != nil {
		return netip.Addr{}, false
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() {
		return netip.Addr{}, false
	}
	return ip, true
}
