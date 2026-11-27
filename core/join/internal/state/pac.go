package state

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// PACMarker starts every rules file a Hogman agent serves, whatever its number
// of pens (RenderPAC's headers all begin this way).
const PACMarker = "// Hogman: "

var hostedPenZoneRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,28}[a-z0-9]\.pens\.hogman\.network$`)

func IsHostedPenZone(zone string) bool {
	return hostedPenZoneRE.MatchString(zone)
}

func ValidPACZone(zone string) bool {
	if zone == "" || strings.HasPrefix(zone, ".") || strings.HasSuffix(zone, ".") || strings.Contains(zone, "..") {
		return false
	}
	for i := 0; i < len(zone); i++ {
		c := zone[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func ValidPACProxyAddr(addr string) bool {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host != "localhost" {
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" || !ip.Unmap().IsLoopback() {
			return false
		}
	}
	port, err := strconv.Atoi(portStr)
	return err == nil && port >= 1 && port <= 65535
}

// ParseStrictHogmanPort enforces 127.0.0.1 and the Hogman local proxy port
// range (17000..26999) with canonical integer formatting (no leading zeros).
func ParseStrictHogmanPort(addr string) (int, bool) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return 0, false
	}
	if len(portStr) == 0 || portStr[0] == '0' {
		return 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < PortMin || port > PortMax {
		return 0, false
	}
	return port, true
}

func NormalizePenConfigs(pens []*AgentConfig, extra *AgentConfig) []*AgentConfig {
	byZone := map[string]*AgentConfig{}
	for _, p := range pens {
		if p == nil || !ValidPACZone(p.Zone) || !ValidPACProxyAddr(p.ProxyAddr) {
			continue
		}
		byZone[strings.ToLower(p.Zone)] = p
	}
	if extra != nil && ValidPACZone(extra.Zone) && ValidPACProxyAddr(extra.ProxyAddr) {
		byZone[strings.ToLower(extra.Zone)] = extra
	}
	out := make([]*AgentConfig, 0, len(byZone))
	for _, p := range byZone {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Zone) != len(out[j].Zone) {
			return len(out[i].Zone) > len(out[j].Zone)
		}
		return strings.ToLower(out[i].Zone) < strings.ToLower(out[j].Zone)
	})
	return out
}

func RenderPAC(pens []*AgentConfig) string {
	pens = NormalizePenConfigs(pens, nil)
	if len(pens) == 0 {
		return "// Hogman: no active pens.\nfunction FindProxyForURL(url, host) {\n  return \"DIRECT\";\n}\n"
	}
	if len(pens) == 1 {
		return fmt.Sprintf(`// Hogman: only names in %[1]s use the pen. Everything else is untouched.
function FindProxyForURL(url, host) {
  host = host.toLowerCase().replace(/\.+$/, "");
  if (host === "%[1]s" || dnsDomainIs(host, ".%[1]s")) return "PROXY %[2]s";
  return "DIRECT";
}
`, pens[0].Zone, pens[0].ProxyAddr)
	}
	var b strings.Builder
	b.WriteString("// Hogman: only pen names use their pen's proxy. Everything else is untouched.\n")
	b.WriteString("function FindProxyForURL(url, host) {\n")
	b.WriteString("  host = host.toLowerCase().replace(/\\.+$/, \"\");\n")
	for _, p := range pens {
		fmt.Fprintf(&b, "  if (host === %q || dnsDomainIs(host, %q)) return %q;\n", p.Zone, "."+p.Zone, "PROXY "+p.ProxyAddr)
	}
	b.WriteString("  return \"DIRECT\";\n")
	b.WriteString("}\n")
	return b.String()
}

func IsHogmanPACURL(rawURL string, known []*AgentConfig) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" || u.Path != "/proxy.pac" {
		return false
	}
	for _, p := range known {
		if p != nil && ValidPACProxyAddr(p.ProxyAddr) && strings.EqualFold(u.Host, p.ProxyAddr) {
			return true
		}
	}
	return false
}

func PenZoneNames(pens []*AgentConfig) []string {
	names := make([]string, 0, len(pens))
	for _, p := range pens {
		if p != nil && ValidPACZone(p.Zone) {
			names = append(names, p.Zone)
		}
	}
	sort.Strings(names)
	return names
}
