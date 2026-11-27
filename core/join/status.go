package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"hogman/join/internal/agent"
	"hogman/join/internal/nativehost"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
)

type statusPenJSON struct {
	Zone     string `json:"zone"`
	Port     int    `json:"port"`
	Up       bool   `json:"up"`
	Hosted   bool   `json:"hosted"`
	Squatted bool   `json:"squatted,omitempty"`
	State    string `json:"state"`
}

type statusNativeHostJSON struct {
	Installed bool   `json:"installed"`
	Active    bool   `json:"active"`
	Path      string `json:"path"`
}

type statusSystemProxyJSON struct {
	VPNOverride          bool     `json:"vpn_override"`
	VPNInterface         string   `json:"vpn_interface,omitempty"`
	OSProxyConflict      bool     `json:"os_proxy_conflict"`
	OSProxyDetail        string   `json:"os_proxy_detail,omitempty"`
	StalePAC             string   `json:"stale_pac,omitempty"`
	MissingProxyServices []string `json:"missing_proxy_services,omitempty"`
}

type statusOutputJSON struct {
	Version           string                `json:"version"`
	Platform          string                `json:"platform"`
	Pens              []statusPenJSON       `json:"pens"`
	Shares            []shareListItemJSON   `json:"shares"`
	NativeHost        statusNativeHostJSON  `json:"native_host"`
	SystemProxy       statusSystemProxyJSON `json:"system_proxy"`
	CorruptPenConfigs []string              `json:"corrupt_pen_configs"`
}

func penStateLabel(p nativehost.PenEntry) string {
	switch {
	case p.Squatted:
		return "port squatted by another process"
	case p.Up:
		return "up"
	case p.StatusReason() != "":
		return "down (" + p.StatusReason() + ")"
	default:
		return "down"
	}
}

func buildStatusOutput(base, sharesDir string) statusOutputJSON {
	pens, configs := nativehost.CollectPens(base)
	outPens := make([]statusPenJSON, 0, len(pens))
	for _, p := range pens {
		outPens = append(outPens, statusPenJSON{
			Zone:     p.Zone,
			Port:     p.Port,
			Up:       p.Up,
			Hosted:   p.Hosted,
			Squatted: p.Squatted,
			State:    penStateLabel(p),
		})
	}
	sys := platform.DetectSystemProxyState(configs)
	hostPath := nativehost.BinaryPath(base)
	_, hostErr := os.Stat(hostPath)
	bad := state.CorruptPenConfigs(base)
	if bad == nil {
		bad = []string{}
	}
	return statusOutputJSON{
		Version:  version,
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Pens:     outPens,
		Shares:   collectShareListItems(state.AllSharesIn(sharesDir, "")),
		NativeHost: statusNativeHostJSON{
			Installed: hostErr == nil,
			Active:    hostErr == nil && nativehost.ExtensionRecentlySeen(base, 7*24*time.Hour),
			Path:      hostPath,
		},
		SystemProxy: statusSystemProxyJSON{
			VPNOverride:          sys.VPNOverride,
			VPNInterface:         sys.VPNInterface,
			OSProxyConflict:      sys.OSProxyConflict,
			OSProxyDetail:        sys.OSProxyDetail,
			StalePAC:             sys.StalePAC,
			MissingProxyServices: sys.MissingProxyServices,
		},
		CorruptPenConfigs: bad,
	}
}

func statusCmd(o options) error {
	base := state.ConfigBase()
	if o.jsonOut {
		return writeJSON(os.Stdout, buildStatusOutput(base, state.SharesBase()))
	}
	pens, configs := nativehost.CollectPens(base)
	if len(pens) == 0 {
		say("No pens installed on this computer.")
		if shares := state.AllShares(""); len(shares) > 0 {
			say("  (%d local share(s) configured; run 'hogman share list' to see them)", len(shares))
		}
	} else {
		say("Pens:")
		for _, p := range pens {
			addr := "-"
			if p.Port > 0 {
				addr = fmt.Sprintf("127.0.0.1:%d", p.Port)
			}
			say("  %-42s  %-16s  %s", p.Zone, addr, penStateLabel(p))
		}
	}
	if bad := state.CorruptPenConfigs(base); len(bad) > 0 {
		say("\n! Unreadable or invalid pen settings in %s: %s", base, strings.Join(bad, ", "))
	}

	sys := platform.DetectSystemProxyState(configs)
	_, hostErr := os.Stat(nativehost.BinaryPath(base))
	if line := extensionHostLine(hostErr == nil, nativehost.ExtensionRecentlySeen(base, 7*24*time.Hour), sys.VPNOverride); line != "" {
		say("\n%s", line)
	}
	if sys.StalePAC != "" {
		say("\n! A proxy setting left by a pen this computer no longer runs is still on: %s", sys.StalePAC)
		if host := agent.PickPACHost(configs); host != nil {
			say("  Update \"Automatic proxy configuration\" in System Settings → Network → Wi-Fi (or Ethernet) → Details… → Proxies to: %s", host.PACURL())
		} else {
			say("  Turn off \"Automatic proxy configuration\" in System Settings → Network → Wi-Fi (or Ethernet) → Details… → Proxies.")
		}
	}
	if sys.VPNOverride {
		say("\n! VPN override detected (%s): macOS system PAC is hidden while this VPN is connected.", sys.VPNInterface)
		if !nativehost.ExtensionRecentlySeen(base, 7*24*time.Hour) {
			say("  To browse pen sites with your VPN on, use the Hogman browser extension (Chrome, Brave, Edge, or Firefox) or pause the VPN (Safari requires pausing the VPN).")
		}
	}
	if sys.OSProxyConflict {
		say("\n! Non-Hogman system proxy active: %s", sys.OSProxyDetail)
	}
	if len(sys.MissingProxyServices) > 0 {
		if host := agent.PickPACHost(configs); host != nil {
			svcList := platform.FormatServiceList(sys.MissingProxyServices)
			say("\n! Automatic proxy configuration is not set on: %s", svcList)
			say("  In System Settings → Network → %s → Details… → Proxies, turn on \"Automatic proxy configuration\" and paste:", svcList)
			say("    %s", host.PACURL())
		}
	}
	return nil
}

func browserSetupCmd(args []string, o options) error {
	var extraChrome, extraFirefox []string
	if o.chromeID != "" {
		id := strings.ToLower(strings.TrimSpace(o.chromeID))
		if !nativehost.ValidChromeExtID(id) {
			return errorf("invalid --chrome-id %q (expected 32 lowercase letters a-p)", o.chromeID)
		}
		extraChrome = append(extraChrome, id)
	}
	if o.firefoxID != "" {
		id := strings.TrimSpace(o.firefoxID)
		if !nativehost.ValidFirefoxExtID(id) {
			return errorf("invalid --firefox-id %q (expected Gecko add-on ID like name@domain or {uuid})", o.firefoxID)
		}
		extraFirefox = append(extraFirefox, id)
	}
	if len(args) > 0 {
		return errorf("usage: hogman browser-setup [--chrome-id <32-char-id>] [--firefox-id <gecko-id>]")
	}
	base := state.ConfigBase()
	hostPath, n, err := nativehost.Install(base, ensureCanonicalBinary, extraChrome, extraFirefox, note)
	if err != nil {
		return errorf("could not set up browser extension host: %v", err)
	}
	say("✓ Installed Hogman browser native host at %s (%d browser manifest(s) written).", hostPath, n)
	saved := nativehost.LoadSavedBrowserIDs(base)
	if len(nativehost.DefaultChromeExtIDs) == 0 && len(saved.ChromeIDs) == 0 && len(nativehost.DefaultFirefoxExtIDs) == 0 && len(saved.FirefoxIDs) == 0 {
		note("No published extension IDs are built in yet. For developer testing, pass --chrome-id <32-char-id> and/or --firefox-id <gecko-id>.")
	} else if n == 0 {
		note("No supported browser profile directories were found yet; re-run hogman browser-setup after launching your browser.")
	}
	return nil
}

// extensionHostLine is status's line about the browser extension's native
// host. The extension is optional (it's for browsing pens with a VPN on), so
// it's only mentioned when it's installed or a VPN override makes it useful.
func extensionHostLine(installed, recentlySeen, vpnOverride bool) string {
	switch {
	case installed && recentlySeen:
		return "Browser extension host: active (browser extension connected)"
	case installed:
		return "Browser extension host: installed (not yet contacted by browser extension)"
	case vpnOverride:
		return "Browser extension host: not installed (run: hogman browser-setup)"
	}
	return ""
}
