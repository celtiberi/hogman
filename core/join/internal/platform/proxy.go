package platform

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"hogman/join/internal/state"
)

// ChromeExtensionStoreURL is the published Chrome Web Store listing for the
// Hogman browser extension (Chrome, Brave, Edge, Arc, Vivaldi).
const ChromeExtensionStoreURL = "https://chromewebstore.google.com/detail/hogman/mgokdogedagoejnjmjpmbcmicbmhplkk"

// ParseAutoProxyOutput parses the output of `networksetup -getautoproxyurl`.
func ParseAutoProxyOutput(out string) (rawURL string, enabled bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "URL:"):
			u := strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
			if u != "(null)" {
				rawURL = u
			}
		case strings.HasPrefix(line, "Enabled:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "Enabled:"))
			enabled = strings.EqualFold(v, "Yes")
		}
	}
	return rawURL, enabled
}

// ShouldLeaveAutoProxy reports whether an existing system PAC setting should be
// left untouched so corporate proxies or unknown local proxies are not overwritten.
func ShouldLeaveAutoProxy(curURL string, enabled bool, known []*state.AgentConfig) bool {
	return enabled && curURL != "" && !IsOurPAC(curURL, known)
}

// IsOurPAC reports whether curURL is a running pen's PAC file or one a removed pen left behind.
func IsOurPAC(curURL string, known []*state.AgentConfig) bool {
	return state.IsHogmanPACURL(curURL, known) || StaleHogmanPAC(curURL)
}

// StaleHogmanPAC reports whether an automatic-proxy address is Hogman's own,
// left behind by a pen this computer no longer runs: http://127.0.0.1:<port>/proxy.pac
// where nothing answers any more, or a Hogman agent answers. A variable so tests
// can stub it.
var StaleHogmanPAC = func(raw string) bool {
	if !HogmanShapedPACURL(raw) {
		return false
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{
		Timeout:   1500 * time.Millisecond,
		Transport: tr,
		// Judge only what answers at that address: an unrelated local server
		// mustn't be able to point the check somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := c.Get(raw)
	if err != nil {
		return true // nothing listens there any more: a dead Hogman setting
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode == http.StatusOK && strings.HasPrefix(string(b), state.PACMarker)
}

// HogmanShapedPACURL matches the exact shape Hogman writes:
// http://127.0.0.1:<17000-26999>/proxy.pac with an optional ?v= version.
func HogmanShapedPACURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Path != "/proxy.pac" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Hostname() != "127.0.0.1" {
		return false
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < state.PortMin || p > state.PortMax {
		return false
	}
	for k := range u.Query() {
		if k != "v" {
			return false
		}
	}
	return true
}

// NetworkServiceInfo describes a single enabled macOS network service entry.
type NetworkServiceInfo struct {
	Name         string
	HardwarePort string
	Device       string
}

// ParseNetworkServiceOrder parses `networksetup -listnetworkserviceorder` into
// enabled services (skipping disabled `(*)` entries).
func ParseNetworkServiceOrder(out string) []NetworkServiceInfo {
	var services []NetworkServiceInfo
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
						services = append(services, NetworkServiceInfo{Name: name})
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

// IsHardwareNetworkService reports whether a macOS network service is backed
// by a real hardware interface rather than a VPN app, tunnel, or virtual bridge.
func IsHardwareNetworkService(s NetworkServiceInfo) bool {
	dev := strings.ToLower(strings.TrimSpace(s.Device))
	if dev == "" || IsTunnelInterface(dev) {
		return false
	}
	for _, prefix := range []string{"bridge", "lo", "awdl", "llw"} {
		if strings.HasPrefix(dev, prefix) {
			return false
		}
	}
	return true
}

func HardwareServiceNamesFromOrder(out string) []string {
	var names []string
	for _, s := range ParseNetworkServiceOrder(out) {
		if IsHardwareNetworkService(s) {
			names = append(names, s.Name)
		}
	}
	return names
}

func FormatServiceList(services []string) string {
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

// FormatBrowserProxyInstructions returns plain, OS-specific browser setup
// instructions leading with the Hogman browser extension and falling back to
// the stable, unversioned local PAC URL.
func FormatBrowserProxyInstructions(goos, pacURL, zone string, zones, services []string) string {
	portal := "https://home." + zone
	multiNote := ""
	if len(zones) > 1 {
		multiNote = fmt.Sprintf("\n    (This same setup covers all %d pens: %s.)", len(zones), strings.Join(zones, ", "))
	}
	extLead := fmt.Sprintf(
		"Using Chrome, Brave, Edge, Arc, or Vivaldi? Install the Hogman browser extension, then open its popup and turn on %s. No proxy settings needed.\n"+
			"    Chrome Web Store: %s\n"+
			"    (Firefox: coming soon.)\n"+
			"    Then open %s%s",
		zone, ChromeExtensionStoreURL, portal, multiNote,
	)
	switch goos {
	case "darwin":
		svcList := FormatServiceList(services)
		eachHint := ""
		if len(services) > 1 {
			eachHint = " (set it on each one)"
		}
		return fmt.Sprintf(
			"%s\n"+
				"    Other browsers (Safari, or no extension) — Hogman never asks for your Mac password; set the automatic proxy URL once in System Settings:\n"+
				"    1. Open System Settings → Network → %s → Details… → Proxies%s\n"+
				"    2. Turn on \"Automatic proxy configuration\" and paste:\n"+
				"         %s\n"+
				"    3. Click OK, then open %s\n"+
				"    (Using Firefox? Settings → Network Settings → Automatic proxy configuration URL works inside Firefox too.)",
			extLead, svcList, eachHint, pacURL, portal,
		)
	case "windows":
		return fmt.Sprintf(
			"%s\n"+
				"    Other browsers (or no extension) — Hogman never asks for administrator access; set the automatic proxy URL once in Windows Settings:\n"+
				"    1. Open Settings → Network & Internet → Proxy → \"Use setup script\" → Set up\n"+
				"    2. Turn on \"Use setup script\" and paste:\n"+
				"         %s\n"+
				"    3. Click Save, then open %s",
			extLead, pacURL, portal,
		)
	default:
		return fmt.Sprintf(
			"%s\n"+
				"    Other browsers (or no extension) — Hogman never asks for your password; set your browser's automatic proxy URL once:\n"+
				"    • Firefox: Settings → Network Settings → Automatic proxy configuration URL → %s\n"+
				"    • System / Chrome (GNOME): Settings → Network → Network Proxy → Automatic → %s\n"+
				"    Then open %s",
			extLead, pacURL, pacURL, portal,
		)
	}
}

// FormatDarwinProxySummary formats the macOS browser status line when at least
// one network service already points at Hogman.
func FormatDarwinProxySummary(configured, missing []string, configuredURL, stableURL, zone string, zones []string) string {
	var base string
	if len(zones) > 1 {
		base = fmt.Sprintf("already configured on %s (%s), which covers all %d pens (%s). If your browser doesn't see %s right away, toggle \"Automatic proxy configuration\" off and back on in System Settings (or restart your browser).",
			FormatServiceList(configured), configuredURL, len(zones), strings.Join(zones, ", "), zone)
	} else {
		base = fmt.Sprintf("already configured on %s (%s) — Safari, Chrome and others find the pen automatically.",
			FormatServiceList(configured), configuredURL)
	}
	if len(missing) == 0 {
		return base
	}
	svcList := FormatServiceList(missing)
	return fmt.Sprintf("%s\n    ! Automatic proxy configuration is not set on %s yet.\n"+
		"      In System Settings → Network → %s → Details… → Proxies, turn on \"Automatic proxy configuration\" and paste:\n"+
		"        %s",
		base, svcList, svcList, stableURL)
}
