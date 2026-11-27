package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"hogman/join/internal/agent"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/nativehost"
	"hogman/join/internal/platform"
	"hogman/join/internal/share"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
	"hogman/join/internal/updater"
)

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "ok", "warn", "fail"
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

type doctorReport struct {
	Version  string        `json:"version"`
	Platform string        `json:"platform"`
	OK       bool          `json:"ok"`
	Checks   []doctorCheck `json:"checks"`
}

func runDoctor(configBase, sharesDir, exePath string) doctorReport {
	rep := doctorReport{
		Version:  version,
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		OK:       true,
		Checks:   []doctorCheck{},
	}
	add := func(c doctorCheck) {
		if c.Status == "fail" {
			rep.OK = false
		}
		rep.Checks = append(rep.Checks, c)
	}

	// 1. Binary & installation mode
	if mgr, upgradeCmd, managed := updater.DetectPackageManager(exePath, runtime.GOOS); managed {
		add(doctorCheck{
			Name:   "binary",
			Status: "ok",
			Detail: fmt.Sprintf("%s %s (%s, managed by %s)", cliBinaryName(), version, rep.Platform, mgr),
			Fix:    upgradeCmd,
		})
	} else {
		add(doctorCheck{
			Name:   "binary",
			Status: "ok",
			Detail: fmt.Sprintf("%s %s (%s at %s)", cliBinaryName(), version, rep.Platform, exePath),
		})
	}

	// 2. Legacy duplicate per-pen / per-share binaries (including old hogman-join copies)
	instName := state.InstalledBinaryName(runtime.GOOS)
	oldInstName := state.LegacyBinaryName(runtime.GOOS)
	canon := state.CanonicalBinaryPath(configBase)
	var dupes []string
	checkLegacy := func(dir, label string) {
		for _, name := range []string{instName, oldInstName} {
			legacy := filepath.Join(dir, name)
			if _, err := os.Stat(legacy); err == nil && !fsutil.SameFilePath(legacy, exePath) && !fsutil.SameFilePath(legacy, canon) {
				dupes = append(dupes, label)
				return
			}
		}
	}
	for _, p := range updater.LoadPenTargets(configBase) {
		checkLegacy(p.Dir, p.Zone)
	}
	for _, d := range state.AllSharesIn(sharesDir, "") {
		checkLegacy(d, filepath.Base(d))
	}
	oldCanon := filepath.Join(configBase, "bin", oldInstName)
	if _, err := os.Stat(oldCanon); err == nil && !fsutil.SameFilePath(oldCanon, exePath) && !fsutil.SameFilePath(oldCanon, canon) {
		dupes = append(dupes, oldInstName)
	}
	if len(dupes) > 0 {
		add(doctorCheck{
			Name:   "binary-layout",
			Status: "warn",
			Detail: fmt.Sprintf("%d legacy per-pen/share binary copy(ies) found (%s)", len(dupes), strings.Join(dupes, ", ")),
			Fix:    cliBinaryName() + " update",
		})
	} else {
		add(doctorCheck{
			Name:   "binary-layout",
			Status: "ok",
			Detail: "single canonical binary layout",
		})
	}

	// 3. Corrupt pen configs
	if bad := state.CorruptPenConfigs(configBase); len(bad) > 0 {
		add(doctorCheck{
			Name:   "pen-configs",
			Status: "fail",
			Detail: fmt.Sprintf("unreadable or invalid pen config(s) in %s: %s", configBase, strings.Join(bad, ", ")),
			Fix:    "inspect or remove the broken directory under " + configBase,
		})
	}

	// 4. Installed pens
	pens, configs := nativehost.CollectPens(configBase)
	if len(pens) == 0 {
		add(doctorCheck{
			Name:   "pens",
			Status: "ok",
			Detail: "no pens installed on this computer",
		})
	} else {
		for _, p := range pens {
			switch {
			case p.Squatted:
				port := p.ConfiguredPort()
				if port == 0 {
					port = p.Port
				}
				add(doctorCheck{
					Name:   "pen:" + p.Zone,
					Status: "fail",
					Detail: fmt.Sprintf("local port 127.0.0.1:%d is squatted by another process (or pre-token agent)", port),
					Fix:    cliBinaryName() + " update",
				})
			case p.Up:
				add(doctorCheck{
					Name:   "pen:" + p.Zone,
					Status: "ok",
					Detail: fmt.Sprintf("up on 127.0.0.1:%d", p.Port),
				})
			default:
				reason := p.StatusReason()
				penDir := filepath.Join(configBase, p.Zone)
				if interrupted, _ := state.ReadUpdatingMarker(penDir); interrupted {
					reason = "interrupted update left agent stopped"
				} else if reason == "" {
					if !platform.ServiceConfigured(p.Zone) {
						reason = "agent not running and no login item registered"
					} else {
						reason = "agent not running"
					}
				}
				fix := cliBinaryName() + " update"
				if strings.Contains(strings.ToLower(reason), "removed") {
					fix = cliBinaryName() + " leave " + p.Zone + " (or re-join with a fresh link)"
				}
				add(doctorCheck{
					Name:   "pen:" + p.Zone,
					Status: "fail",
					Detail: "down (" + reason + ")",
					Fix:    fix,
				})
			}
		}
	}

	// 5. Local shares
	for _, d := range state.AllSharesIn(sharesDir, "") {
		c, err := state.LoadShare(d)
		if err != nil {
			add(doctorCheck{
				Name:   "share:" + filepath.Base(d),
				Status: "fail",
				Detail: "unreadable share.json: " + err.Error(),
			})
			continue
		}
		running := share.PID(d) != 0
		st := state.ReadShareStatus(d)
		if !running && st.State == "error" && st.Error != "" {
			add(doctorCheck{
				Name:   "share:" + c.FQDN(),
				Status: "fail",
				Detail: link.SingleLine(st.Error),
				Fix:    "check log: " + filepath.Join(d, "share.log"),
			})
		} else if running {
			add(doctorCheck{
				Name:   "share:" + c.FQDN(),
				Status: "ok",
				Detail: "running -> " + c.Showing(),
			})
		}
	}

	// 6. System proxy & VPN state
	sys := platform.DetectSystemProxyState(configs)
	if sys.StalePAC != "" {
		fix := "turn off \"Automatic proxy configuration\" in System Settings → Network → Wi-Fi (or Ethernet) → Details… → Proxies"
		if host := agent.PickPACHost(configs); host != nil {
			fix = "update \"Automatic proxy configuration\" in System Settings → Network → Wi-Fi (or Ethernet) → Details… → Proxies to " + host.PACURL()
		}
		add(doctorCheck{
			Name:   "system-proxy",
			Status: "warn",
			Detail: "stale Hogman automatic proxy still active: " + sys.StalePAC,
			Fix:    fix,
		})
	} else if sys.OSProxyConflict {
		add(doctorCheck{
			Name:   "system-proxy",
			Status: "warn",
			Detail: "non-Hogman system proxy active: " + sys.OSProxyDetail,
		})
	} else if len(sys.MissingProxyServices) > 0 {
		svcList := platform.FormatServiceList(sys.MissingProxyServices)
		fix := "turn on \"Automatic proxy configuration\" in System Settings → Network → " + svcList + " → Details… → Proxies"
		if host := agent.PickPACHost(configs); host != nil {
			fix += " and paste " + host.PACURL()
		}
		add(doctorCheck{
			Name:   "system-proxy",
			Status: "warn",
			Detail: "automatic proxy configuration not set on: " + svcList,
			Fix:    fix,
		})
	} else {
		add(doctorCheck{
			Name:   "system-proxy",
			Status: "ok",
			Detail: "no conflicting system proxy detected",
		})
	}

	_, hostErr := os.Stat(nativehost.BinaryPath(configBase))
	extInstalled := hostErr == nil
	extSeen := nativehost.ExtensionRecentlySeen(configBase, 7*24*time.Hour)
	if sys.VPNOverride {
		if extInstalled && extSeen {
			add(doctorCheck{
				Name:   "vpn",
				Status: "ok",
				Detail: fmt.Sprintf("VPN active (%s); Hogman browser extension connected", sys.VPNInterface),
			})
		} else {
			add(doctorCheck{
				Name:   "vpn",
				Status: "warn",
				Detail: fmt.Sprintf("VPN override detected (%s): macOS hides system PAC while VPN is on", sys.VPNInterface),
				Fix:    "install the Hogman browser extension (" + platform.ChromeExtensionStoreURL + "; Firefox: coming soon), open its popup to turn on your pen, and run: " + cliBinaryName() + " browser-setup",
			})
		}
	} else if extInstalled {
		detail := "installed (not yet contacted by browser extension)"
		if extSeen {
			detail = "active (browser extension connected)"
		}
		add(doctorCheck{
			Name:   "browser-extension",
			Status: "ok",
			Detail: detail,
		})
	}

	return rep
}

func doctorCmd(o options, u *ui.UI) error {
	exePath, _ := fsutil.ResolvedExePath()
	rep := runDoctor(state.ConfigBase(), state.SharesBase(), exePath)
	if o.jsonOut {
		return u.WriteJSON(rep)
	}
	for _, c := range rep.Checks {
		icon := "✓"
		switch c.Status {
		case "warn":
			icon = "!"
		case "fail":
			icon = "✗"
		}
		u.Say("%s %-24s %s", icon, c.Name, c.Detail)
		if c.Fix != "" && c.Status != "ok" {
			u.Say("    fix: %s", c.Fix)
		}
	}
	if !rep.OK {
		return errorf("one or more checks failed")
	}
	return nil
}
