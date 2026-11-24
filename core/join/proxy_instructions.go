package main

import (
	"fmt"
	"strings"
)

type networkServiceInfo struct {
	Name         string
	HardwarePort string
	Device       string
}

// parseNetworkServiceOrder parses `networksetup -listnetworkserviceorder` into
// enabled services (skipping disabled `(*)` entries).
func parseNetworkServiceOrder(out string) []networkServiceInfo {
	var services []networkServiceInfo
	cur := -1
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "(*)") {
			cur = -1
			continue
		}
		if strings.HasPrefix(line, "(") {
			if closeIdx := strings.Index(line, ")"); closeIdx > 1 {
				num := line[1:closeIdx]
				allDigits := true
				for i := 0; i < len(num); i++ {
					if num[i] < '0' || num[i] > '9' {
						allDigits = false
						break
					}
				}
				if allDigits {
					name := strings.TrimSpace(line[closeIdx+1:])
					if name != "" {
						services = append(services, networkServiceInfo{Name: name})
						cur = len(services) - 1
					} else {
						cur = -1
					}
					continue
				}
			}
		}
		if cur >= 0 && strings.HasPrefix(line, "(Hardware Port:") && strings.HasSuffix(line, ")") {
			inner := line[1 : len(line)-1]
			if hpPart, devPart, ok := strings.Cut(inner, ", Device:"); ok {
				services[cur].HardwarePort = strings.TrimSpace(strings.TrimPrefix(hpPart, "Hardware Port:"))
				services[cur].Device = strings.TrimSpace(devPart)
			}
			cur = -1
		}
	}
	return services
}

// isHardwareNetworkService reports whether a macOS network service is backed
// by a real hardware interface (Wi-Fi, Ethernet, USB LAN dock, etc.) rather
// than a VPN app (empty device), tunnel, or virtual bridge like Thunderbolt Bridge.
func isHardwareNetworkService(s networkServiceInfo) bool {
	dev := strings.ToLower(strings.TrimSpace(s.Device))
	if dev == "" || isTunnelInterface(dev) {
		return false
	}
	for _, prefix := range []string{"bridge", "lo", "awdl", "llw"} {
		if strings.HasPrefix(dev, prefix) {
			return false
		}
	}
	return true
}

func hardwareServiceNamesFromOrder(out string) []string {
	var names []string
	for _, s := range parseNetworkServiceOrder(out) {
		if isHardwareNetworkService(s) {
			names = append(names, s.Name)
		}
	}
	return names
}

func formatServiceList(services []string) string {
	switch len(services) {
	case 0:
		return "Wi-Fi (or Ethernet)"
	case 1:
		return services[0]
	case 2:
		return services[0] + " and " + services[1]
	default:
		return strings.Join(services[:len(services)-1], ", ") + ", and " + services[len(services)-1]
	}
}

// formatBrowserProxyInstructions returns plain, OS-specific one-time automatic
// proxy setup instructions using the stable, unversioned local PAC URL
// (http://127.0.0.1:<port>/proxy.pac). Hogman never asks for a Mac/system
// password to change proxy settings.
func formatBrowserProxyInstructions(goos, pacURL, zone string, zones, services []string) string {
	portal := "https://home." + zone
	multiNote := ""
	if len(zones) > 1 {
		multiNote = fmt.Sprintf("\n    (This same URL covers all %d pens: %s.)", len(zones), strings.Join(zones, ", "))
	}
	switch goos {
	case "darwin":
		svcList := formatServiceList(services)
		eachHint := ""
		if len(services) > 1 {
			eachHint = " (set it on each one)"
		}
		return fmt.Sprintf(
			"Hogman never asks for your Mac password — set the automatic proxy URL once in System Settings:\n"+
				"    1. Open System Settings → Network → %s → Details… → Proxies%s\n"+
				"    2. Turn on \"Automatic proxy configuration\" and paste:\n"+
				"         %s\n"+
				"    3. Click OK, then open %s%s\n"+
				"    (Using Firefox? Settings → Network Settings → Automatic proxy configuration URL works inside Firefox too.)\n"+
				"    We're working on a signed Mac app and Chrome/Firefox extensions so this will be automatic soon.",
			svcList, eachHint, pacURL, portal, multiNote,
		)
	case "windows":
		return fmt.Sprintf(
			"Hogman never asks for administrator access — set the automatic proxy URL once in Windows Settings:\n"+
				"    1. Open Settings → Network & Internet → Proxy → \"Use setup script\" → Set up\n"+
				"    2. Turn on \"Use setup script\" and paste:\n"+
				"         %s\n"+
				"    3. Click Save, then open %s%s\n"+
				"    We're working on Chrome/Firefox extensions so this will be automatic soon.",
			pacURL, portal, multiNote,
		)
	default: // linux and other unix desktops
		return fmt.Sprintf(
			"Hogman never asks for your password — set your browser's automatic proxy URL once:\n"+
				"    • Firefox: Settings → Network Settings → Automatic proxy configuration URL → %s\n"+
				"    • System / Chrome (GNOME): Settings → Network → Network Proxy → Automatic → %s\n"+
				"    Then open %s%s\n"+
				"    We're working on Chrome/Firefox extensions so this will be automatic soon.",
			pacURL, pacURL, portal, multiNote,
		)
	}
}

// formatDarwinProxySummary formats the macOS browser status line when at least
// one network service already points at Hogman, flagging any additional enabled
// hardware services (such as a newly connected dock or Ethernet adapter) that
// still need the automatic proxy URL set.
func formatDarwinProxySummary(configured, missing []string, configuredURL, stableURL, zone string, zones []string) string {
	var base string
	if len(zones) > 1 {
		base = fmt.Sprintf("already configured on %s (%s), which covers all %d pens (%s). If your browser doesn't see %s right away, toggle \"Automatic proxy configuration\" off and back on in System Settings (or restart your browser).",
			formatServiceList(configured), configuredURL, len(zones), strings.Join(zones, ", "), zone)
	} else {
		base = fmt.Sprintf("already configured on %s (%s) — Safari, Chrome and others find the pen automatically.",
			formatServiceList(configured), configuredURL)
	}
	if len(missing) == 0 {
		return base
	}
	svcList := formatServiceList(missing)
	return fmt.Sprintf("%s\n    ! Automatic proxy configuration is not set on %s yet.\n"+
		"      In System Settings → Network → %s → Details… → Proxies, turn on \"Automatic proxy configuration\" and paste:\n"+
		"        %s",
		base, svcList, svcList, stableURL)
}
