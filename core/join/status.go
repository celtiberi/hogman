package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

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

func penStateLabel(p nativePenEntry) string {
	switch {
	case p.Squatted:
		return "port squatted by another process"
	case p.Up:
		return "up"
	case p.statusReason != "":
		return "down (" + p.statusReason + ")"
	default:
		return "down"
	}
}

func buildStatusOutput(base, sharesDir string) statusOutputJSON {
	pens, configs := collectNativePens(base)
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
	sys := detectSystemProxyState(configs)
	hostPath := nativeHostBinaryPath(base)
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
			Active:    hostErr == nil && extensionRecentlySeen(base, 7*24*time.Hour),
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
	pens, configs := collectNativePens(base)
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

	sys := detectSystemProxyState(configs)
	_, hostErr := os.Stat(nativeHostBinaryPath(base))
	if line := extensionHostLine(hostErr == nil, extensionRecentlySeen(base, 7*24*time.Hour), sys.VPNOverride); line != "" {
		say("\n%s", line)
	}
	if sys.StalePAC != "" {
		say("\n! A proxy setting left by a pen this computer no longer runs is still on: %s", sys.StalePAC)
		if host := pickPACHost(configs); host != nil {
			say("  Update \"Automatic proxy configuration\" in System Settings → Network → Wi-Fi (or Ethernet) → Details… → Proxies to: %s", host.PACURL())
		} else {
			say("  Turn off \"Automatic proxy configuration\" in System Settings → Network → Wi-Fi (or Ethernet) → Details… → Proxies.")
		}
	}
	if sys.VPNOverride {
		say("\n! VPN override detected (%s): macOS system PAC is hidden while this VPN is connected.", sys.VPNInterface)
		if !extensionRecentlySeen(base, 7*24*time.Hour) {
			say("  To browse pen sites with your VPN on, use the Hogman browser extension (Chrome, Brave, Edge, or Firefox) or pause the VPN (Safari requires pausing the VPN).")
		}
	}
	if sys.OSProxyConflict {
		say("\n! Non-Hogman system proxy active: %s", sys.OSProxyDetail)
	}
	if len(sys.MissingProxyServices) > 0 {
		if host := pickPACHost(configs); host != nil {
			svcList := formatServiceList(sys.MissingProxyServices)
			say("\n! Automatic proxy configuration is not set on: %s", svcList)
			say("  In System Settings → Network → %s → Details… → Proxies, turn on \"Automatic proxy configuration\" and paste:", svcList)
			say("    %s", host.PACURL())
		}
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
