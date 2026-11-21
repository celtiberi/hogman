package main

import (
	"os"
)

const systemKeychain = "/Library/Keychains/System.keychain"

func isRoot() bool { return os.Geteuid() == 0 }

func removeLegacyHogmanRoot(zone, rootFP string) (bool, error) {
	out, err := run(false, "security", "find-certificate", "-a", "-p", systemKeychain)
	if err != nil {
		return false, nil
	}
	matches := matchingLegacyRootsFromPEM([]byte(out), zone, rootFP)
	if len(matches) == 0 {
		return false, nil
	}
	removed := false
	for _, m := range matches {
		if path, cleanup, err := writeTempCert(m.PEM); err == nil {
			_, _ = run(true, "security", "remove-trusted-cert", "-d", path)
			cleanup()
		}
		delOut, err := run(true, "security", "delete-certificate", "-Z", m.SHA1, systemKeychain)
		if err != nil {
			return removed, errorf("could not remove old certificate (%s): %v\n%s", m.CommonName, err, delOut)
		}
		removed = true
	}
	return removed, nil
}

func tailscaleCandidates() []string {
	return []string{"tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
		"/opt/homebrew/bin/tailscale", "/usr/local/bin/tailscale"}
}

func tailscaleInstallHelp() string {
	return "Install Tailscale from the Mac App Store or https://tailscale.com/download/mac, open it once, then run this again."
}

func openURL(u string) { _, _ = run(false, "open", u) }
