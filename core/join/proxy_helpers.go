package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// parseAutoProxyOutput parses the output of `networksetup -getautoproxyurl`.
func parseAutoProxyOutput(out string) (url string, enabled bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "URL:"):
			u := strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
			if u != "(null)" {
				url = u
			}
		case strings.HasPrefix(line, "Enabled:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "Enabled:"))
			enabled = strings.EqualFold(v, "Yes")
		}
	}
	return url, enabled
}

func validPACZone(zone string) bool {
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

func validPACProxyAddr(addr string) bool {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if net.ParseIP(host) == nil && host != "localhost" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	return err == nil && port >= 1 && port <= 65535
}

func normalizePenConfigs(pens []*agentConfig, extra *agentConfig) []*agentConfig {
	byZone := map[string]*agentConfig{}
	for _, p := range pens {
		if p == nil || !validPACZone(p.Zone) || !validPACProxyAddr(p.ProxyAddr) {
			continue
		}
		byZone[strings.ToLower(p.Zone)] = p
	}
	if extra != nil && validPACZone(extra.Zone) && validPACProxyAddr(extra.ProxyAddr) {
		byZone[strings.ToLower(extra.Zone)] = extra
	}
	out := make([]*agentConfig, 0, len(byZone))
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

func renderPAC(pens []*agentConfig) string {
	pens = normalizePenConfigs(pens, nil)
	if len(pens) == 0 {
		return "// Hogman: no active pens.\nfunction FindProxyForURL(url, host) {\n  return \"DIRECT\";\n}\n"
	}
	if len(pens) == 1 {
		return fmt.Sprintf(`// Hogman: only names in %[1]s use the pen. Everything else is untouched.
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (host === "%[1]s" || dnsDomainIs(host, ".%[1]s")) return "PROXY %[2]s";
  return "DIRECT";
}
`, pens[0].Zone, pens[0].ProxyAddr)
	}
	var b strings.Builder
	b.WriteString("// Hogman: only pen names use their pen's proxy. Everything else is untouched.\n")
	b.WriteString("function FindProxyForURL(url, host) {\n")
	b.WriteString("  host = host.toLowerCase();\n")
	for _, p := range pens {
		fmt.Fprintf(&b, "  if (host === %q || dnsDomainIs(host, %q)) return %q;\n", p.Zone, "."+p.Zone, "PROXY "+p.ProxyAddr)
	}
	b.WriteString("  return \"DIRECT\";\n")
	b.WriteString("}\n")
	return b.String()
}

func pacVersion(pens []*agentConfig) string {
	sum := sha256.Sum256([]byte(renderPAC(pens)))
	return hex.EncodeToString(sum[:])[:8]
}

func pacURLWithVersion(host *agentConfig, pens []*agentConfig) string {
	return host.pacURL() + "?v=" + pacVersion(pens)
}

func isHogmanPACURL(rawURL string, known []*agentConfig) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" || u.Path != "/proxy.pac" {
		return false
	}
	for _, p := range known {
		if p != nil && validPACProxyAddr(p.ProxyAddr) && strings.EqualFold(u.Host, p.ProxyAddr) {
			return true
		}
	}
	return false
}

// shouldLeaveAutoProxy reports whether an existing system PAC setting should be
// left untouched so corporate proxies or unknown local proxies are not overwritten.
func shouldLeaveAutoProxy(curURL string, enabled bool, known []*agentConfig) bool {
	return enabled && curURL != "" && !isHogmanPACURL(curURL, known)
}

func planAutoProxyAction(curURL string, enabled bool, known []*agentConfig, wantURL string) string {
	if wantURL == "" {
		if enabled && isHogmanPACURL(curURL, known) {
			return "off"
		}
		return "noop"
	}
	if shouldLeaveAutoProxy(curURL, enabled, known) {
		return "leave"
	}
	if enabled && curURL == wantURL {
		return "noop"
	}
	return "set"
}

func planClearAutoProxyAction(curURL string, enabled bool, known []*agentConfig, nextURL string) string {
	if !enabled || !isHogmanPACURL(curURL, known) {
		return "noop"
	}
	if nextURL == "" {
		return "off"
	}
	if curURL == nextURL {
		return "noop"
	}
	return "set"
}

func penZoneNames(pens []*agentConfig) []string {
	names := make([]string, 0, len(pens))
	for _, p := range pens {
		if p != nil && validPACZone(p.Zone) {
			names = append(names, p.Zone)
		}
	}
	sort.Strings(names)
	return names
}

func xmlEscape(s string) (string, error) {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return "", err
	}
	return b.String(), nil
}

// renderLaunchPlist builds a macOS LaunchAgent plist with XML-escaped strings.
func renderLaunchPlist(label, bin, dir, logPath string) (string, error) {
	el, err := xmlEscape(label)
	if err != nil {
		return "", err
	}
	eb, err := xmlEscape(bin)
	if err != nil {
		return "", err
	}
	ed, err := xmlEscape(dir)
	if err != nil {
		return "", err
	}
	ep, err := xmlEscape(logPath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array><string>%s</string><string>agent</string><string>%s</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, el, eb, ed, ep, ep), nil
}

func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// renderSystemdUnit builds a systemd user service unit with quoted ExecStart paths.
func renderSystemdUnit(zone, bin, dir string) string {
	return fmt.Sprintf(`[Unit]
Description=Hogman pen connection (%s)
After=network-online.target

[Service]
ExecStart=%s agent %s
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`, zone, systemdQuote(bin), systemdQuote(dir))
}
