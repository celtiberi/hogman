package main

import (
	"os/exec"
	"strings"
)

// isRoot reports whether we are elevated ("Run as administrator").
func isRoot() bool {
	return exec.Command("net", "session").Run() == nil
}

func trustInstalled(r *RootInfo) bool {
	out, err := run(false, "certutil", "-store", "Root", r.SHA1)
	return err == nil && strings.Contains(strings.ToUpper(strings.ReplaceAll(out, " ", "")), r.SHA1)
}

// installTrust adds the root to the machine's Trusted Root store, used by
// Edge, Chrome, curl, git (schannel) and most apps. Firefox uses it when
// "security.enterprise_roots.enabled" is on, the default on Windows.
func installTrust(r *RootInfo, file string) error {
	if trustInstalled(r) {
		note("already trusted")
		return nil
	}
	if !isRoot() {
		return errorf("adding the certificate needs administrator rights: open a terminal with \"Run as administrator\" and run this again")
	}
	out, err := run(false, "certutil", "-addstore", "-f", "Root", file)
	if err != nil {
		return errorf("could not add the certificate: %v\n%s", err, out)
	}
	return nil
}

func removeTrust(r *RootInfo, _ string) error {
	if !trustInstalled(r) {
		return nil
	}
	out, err := run(false, "certutil", "-delstore", "Root", r.SHA1)
	if err != nil {
		return errorf("could not remove the certificate (run as administrator?): %v\n%s", err, out)
	}
	return nil
}

func removeLegacyHogmanRoot(zone, rootFP string) (bool, error) {
	var sha1s []string
	if psOut, err := run(false, "powershell", "-NoProfile", "-Command",
		"Get-ChildItem Cert:\\LocalMachine\\Root | ForEach-Object { [Convert]::ToBase64String($_.RawData) }"); err == nil {
		for _, m := range parseWindowsBase64CertsLegacyRoots(psOut, zone, rootFP) {
			sha1s = append(sha1s, m.SHA1)
		}
	} else if out, err := run(false, "certutil", "-store", "Root"); err == nil {
		sha1s = parseWindowsLegacyRootSHA1s(out, zone)
	}
	if len(sha1s) == 0 {
		return false, nil
	}
	if !isRoot() {
		return false, errorf("removing old network certificate(s) needs administrator rights: open a terminal with \"Run as administrator\" and run this again")
	}
	removed := false
	for _, h := range sha1s {
		if out, err := run(false, "certutil", "-delstore", "Root", h); err != nil {
			return removed, errorf("could not remove old certificate (%s): %v\n%s", h, err, out)
		}
		removed = true
	}
	return removed, nil
}

func tailscaleCandidates() []string {
	return []string{"tailscale", `C:\Program Files\Tailscale\tailscale.exe`}
}

func tailscaleInstallHelp() string {
	return "Install Tailscale from https://tailscale.com/download/windows, then run this again."
}

func openURL(u string) { _, _ = run(false, "rundll32", "url.dll,FileProtocolHandler", u) }
