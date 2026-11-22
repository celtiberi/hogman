package main

import (
	"fmt"
	"strings"
)

type systemProxyState struct {
	OSProxyConflict bool
	OSProxyKind     string // privacy-safe category list sent over Native Messaging ("pac", "http", "https", "socks")
	OSProxyDetail   string // detailed description for local CLI `status` output only (never sent to extensions)
	VPNOverride     bool
	VPNInterface    string
}

type scutilProxyInfo struct {
	PACOn   bool
	PACURL  string
	HTTPOn  bool
	HTTPSOn bool
	SOCKSOn bool
}

func parseScutilProxy(out string) scutilProxyInfo {
	var info scutilProxyInfo
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "ProxyAutoConfigEnable":
			info.PACOn = v == "1"
		case "ProxyAutoConfigURLString":
			info.PACURL = v
		case "HTTPEnable":
			info.HTTPOn = v == "1"
		case "HTTPSEnable":
			info.HTTPSOn = v == "1"
		case "SOCKSEnable":
			info.SOCKSOn = v == "1"
		}
	}
	return info
}

func parseScutilPrimaryInterface(out string) string {
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) == "PrimaryInterface" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func isTunnelInterface(iface string) bool {
	return strings.HasPrefix(iface, "utun") || strings.HasPrefix(iface, "ppp") || strings.HasPrefix(iface, "ipsec")
}

// evaluateDarwinProxyState computes VPN-override and non-Hogman OS proxy
// conflicts purely from parsed scutil outputs and whether any macOS service has
// a Hogman PAC configured.
func evaluateDarwinProxyState(proxy scutilProxyInfo, primaryIface string, serviceHasHogmanPAC bool, known []*agentConfig) systemProxyState {
	var st systemProxyState
	var conflicts []string
	var kinds []string
	if proxy.HTTPOn {
		conflicts = append(conflicts, "HTTP proxy")
		kinds = append(kinds, "http")
	}
	if proxy.HTTPSOn {
		conflicts = append(conflicts, "HTTPS proxy")
		kinds = append(kinds, "https")
	}
	if proxy.SOCKSOn {
		conflicts = append(conflicts, "SOCKS proxy")
		kinds = append(kinds, "socks")
	}
	if proxy.PACOn && proxy.PACURL != "" && !isHogmanPACURL(proxy.PACURL, known) {
		conflicts = append(conflicts, fmt.Sprintf("PAC (%s)", proxy.PACURL))
		kinds = append(kinds, "pac")
	}
	if len(conflicts) > 0 {
		st.OSProxyConflict = true
		st.OSProxyKind = strings.Join(kinds, ",")
		st.OSProxyDetail = strings.Join(conflicts, ", ")
	}
	hogmanPACActive := proxy.PACOn && isHogmanPACURL(proxy.PACURL, known)
	if !hogmanPACActive && serviceHasHogmanPAC && isTunnelInterface(primaryIface) {
		st.VPNOverride = true
		st.VPNInterface = primaryIface
	}
	return st
}
