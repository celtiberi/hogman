package share

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hogman/join/internal/bridge"
	"hogman/join/internal/link"
	"hogman/join/internal/state"
)

const Usage = `hogman share: put something on your pen under its own name

usage:
  hogman share <name> <target>                         share from this computer (it must be on the pen)
  hogman share <name> <target> '<server link>'         share from a computer that isn't on the pen
  hogman share --private-name <target> [--note TEXT]   share under a random hostname (label stays inside the pen)
  hogman share list                                    what this computer shares
  hogman share stop <name>                             take a share down and give its name back

<target> is a port on this computer (3000), a local web address
(http://localhost:8080) or a folder (./site) to serve as a website.
<name> becomes https://<name>.<pen-zone>, open to everyone in the pen.
Note: <name> is publicly visible in certificate logs (contents stay private);
don't put anything sensitive in it.

options:
  --private-name      use a random hostname so the friendly name stays inside the pen (pair with --note "Label" for the portal directory). Does not hide the pen name, site count, or issuance/renewal timing in certificate logs, and does not change certificate caps.
  --note TEXT         short one-line description shown on the pen's home page (--note "" clears it)
  --foreground        stay attached to this terminal (Ctrl-C to stop) instead of running in the background
  --no-service        don't register a login item, just run in the background
  --pen ZONE          which pen, if this computer is on more than one
  --identity-headers  pass verified X-Hogman-* caller identity headers to a local upstream target
  --force             with stop, remove local files even if the pen cannot be reached
`

var (
	NameRE           = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){0,3}$`)
	reservedShareNS  = regexp.MustCompile(`^ns[0-9]*$`)
	reservedShareTop = map[string]bool{
		"home": true, "ns": true, "registrar": true,
		"search": true, "nodes": true, "www": true, "join": true, "admin": true,
	}
)

func IsReservedName(name string) bool {
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "_acme-challenge" || reservedShareNS.MatchString(l) {
			return true
		}
	}
	return reservedShareTop[labels[len(labels)-1]]
}

var blockedMetadataIPs = map[netip.Addr]bool{
	netip.MustParseAddr("169.254.169.254"): true, // AWS/GCP/Azure/DO/Oracle IMDS
	netip.MustParseAddr("169.254.170.2"):   true, // AWS ECS task metadata
	netip.MustParseAddr("169.254.169.253"): true, // AWS VPC DNS
	netip.MustParseAddr("169.254.169.123"): true, // AWS Time Sync
	netip.MustParseAddr("100.100.100.200"): true, // Alibaba Cloud IMDS
	netip.MustParseAddr("fd00:ec2::254"):   true, // AWS IPv6 IMDS
}

func IsBlockedMetadataHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	return h == "metadata.google.internal" || h == "metadata.goog" || h == "instance-data"
}

// IsAllowedIP reports whether addr is a local or private LAN address suitable
// as a share target: loopback (127.0.0.0/8, ::1), RFC 1918 (10/8, 172.16/12,
// 192.168/16), IPv6 ULA (fc00::/7), or link-local LAN (169.254/16, fe80::/10)
// — always denying cloud metadata endpoints, unspecified/multicast addresses,
// and public internet IPs.
func IsAllowedIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	ip := addr.Unmap()
	if addr.Zone() != "" && !ip.IsLinkLocalUnicast() {
		return false
	}
	if blockedMetadataIPs[ip] || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// IsLoopbackIP reports whether addr is strictly a loopback address (127.0.0.0/8
// or ::1). Used when --identity-headers is enabled so verified X-Hogman-*
// headers are never sent across a LAN hop.
func IsLoopbackIP(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	return addr.Unmap().IsLoopback()
}

// ValidateIdentityTarget enforces that --identity-headers is only used with a
// local upstream target (unix:// socket, localhost, or loopback IP), never a
// static folder or a non-local LAN host.
func ValidateIdentityTarget(target string, folder bool) error {
	if folder {
		return link.Errorf("--identity-headers cannot be used with a folder share")
	}
	if strings.HasPrefix(target, "unix://") {
		return nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return link.Errorf("--identity-headers: invalid share target %q: %v", target, err)
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "localhost" {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil && IsLoopbackIP(ip) {
		return nil
	}
	return link.Errorf("--identity-headers requires a local target (localhost, 127.0.0.1, ::1, or unix:// socket), got %q", target)
}

// LocalOrLANDialContext enforces at dial time (after resolving DNS) that share
// reverse-proxy requests only ever connect to loopback or private LAN IPs,
// denying cloud metadata endpoints and public internet addresses.
func LocalOrLANDialContext(lookup func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return shareDialContext(IsAllowedIP, "only local and private LAN targets are allowed", lookup, dial)
}

// LoopbackOnlyDialContext enforces at dial time that upstream connections only
// ever reach loopback addresses (127.0.0.0/8 or ::1).
func LoopbackOnlyDialContext(lookup func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return shareDialContext(IsLoopbackIP, "--identity-headers requires a loopback target", lookup, dial)
}

func shareDialContext(allowIP func(netip.Addr) bool, reason string, lookup func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	if dial == nil {
		d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		dial = d.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if IsBlockedMetadataHost(host) {
			return nil, link.Errorf("refusing to proxy to cloud metadata host %q", host)
		}
		var targets []string
		if ip, err := netip.ParseAddr(host); err == nil {
			if !allowIP(ip) {
				return nil, link.Errorf("refusing to proxy to disallowed address %q (%s)", host, reason)
			}
			if ip.Zone() != "" {
				targets = []string{ip.String()}
			} else {
				targets = []string{ip.Unmap().String()}
			}
		} else {
			resolved, err := lookup(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(resolved) == 0 {
				return nil, link.Errorf("host %q did not resolve to any address", host)
			}
			for _, r := range resolved {
				ip, ok := netip.AddrFromSlice(r.IP)
				if !ok {
					return nil, link.Errorf("refusing to proxy to invalid resolved address for %q", host)
				}
				ip = ip.Unmap()
				if r.Zone != "" {
					ip = ip.WithZone(r.Zone)
				}
				if !allowIP(ip) {
					return nil, link.Errorf("refusing to proxy to disallowed address %s resolved for %q (%s)", ip, host, reason)
				}
				targets = append(targets, ip.String())
			}
		}
		var lastErr error
		for _, ipStr := range targets {
			conn, err := dial(ctx, network, net.JoinHostPort(ipStr, port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// ParseTarget parses WHAT: a port, a local/LAN web address, a unix:// socket, or a folder.
func ParseTarget(what string) (target string, folder bool, err error) {
	if n, err := strconv.Atoi(what); err == nil {
		if n < 1 || n > 65535 {
			return "", false, link.Errorf("%d is not a port number", n)
		}
		return "http://127.0.0.1:" + what, false, nil
	}
	if strings.HasPrefix(what, "unix://") {
		rawPath := strings.TrimPrefix(what, "unix://")
		clean, err := bridge.ValidateUnixSocketPath(rawPath)
		if err != nil {
			return "", false, err
		}
		return "unix://" + clean, false, nil
	}
	if strings.HasPrefix(what, "http://") || strings.HasPrefix(what, "https://") {
		u, err := url.Parse(what)
		if err != nil || u.Host == "" || u.Hostname() == "" {
			return "", false, link.Errorf("%q is not a web address", what)
		}
		if u.User != nil {
			return "", false, link.Errorf("the share target must not contain credentials")
		}
		host := u.Hostname()
		if IsBlockedMetadataHost(host) {
			return "", false, link.Errorf("%q is a cloud metadata address and cannot be shared", what)
		}
		if ip, err := netip.ParseAddr(host); err == nil && !IsAllowedIP(ip) {
			return "", false, link.Errorf("%q is not a local or private LAN address (public internet and cloud metadata addresses cannot be shared)", what)
		}
		if p := u.Port(); p != "" {
			n, perr := strconv.Atoi(p)
			if perr != nil || n < 1 || n > 65535 {
				return "", false, link.Errorf("%q has an invalid port number %q", what, p)
			}
		}
		return strings.TrimSuffix(u.String(), "/"), false, nil
	}
	abs, err := filepath.Abs(what)
	if err != nil {
		return "", false, err
	}
	fi, err := os.Stat(abs)
	if err != nil || !fi.IsDir() {
		return "", false, link.Errorf("%q is not a port, a web address (http://localhost:8080) or a folder", what)
	}
	return abs, true, nil
}

func ResolveNote(old *state.ShareConfig, note string, noteSet bool) string {
	if noteSet {
		return strings.TrimSpace(note)
	}
	if old != nil {
		return old.Note
	}
	return ""
}

func FormatCertLogNotice(fqdn string) string {
	return fmt.Sprintf("• Note: %s will be publicly visible in certificate logs (contents stay private). Don't put anything sensitive in the name.", fqdn)
}

func FormatPrivateNameNotice(fqdn string) string {
	return fmt.Sprintf("• Private name: %s (only this random name appears in certificate logs; the pen name, site count, and certificate timing are still visible).", fqdn)
}

func FormatPrivateNoteTip() string {
	return `• Tip: pass --note "Label" so members see a readable name in the portal directory instead of the random hostname.`
}
