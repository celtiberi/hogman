package main

import (
	"os"
	"strings"
)

const systemKeychain = "/Library/Keychains/System.keychain"

func isRoot() bool { return os.Geteuid() == 0 }

// trustInstalled needs both: the certificate in the System keychain, and an
// admin trust setting for it verified by macOS's own trust engine.
func trustInstalled(r *RootInfo) bool {
	out, err := run(false, "security", "find-certificate", "-a", "-Z", systemKeychain)
	if err != nil || !strings.Contains(out, r.SHA1) {
		return false
	}
	certFile, cleanup, err := writeTempCert(r.PEM)
	if err != nil {
		return false
	}
	defer cleanup()
	_, err = run(false, "security", "verify-cert", "-L", "-l", "-p", "ssl", "-c", certFile)
	return err == nil
}

// dropUntrusted removes a copy that was added but never trusted.
func dropUntrusted(r *RootInfo) {
	out, _ := run(false, "security", "find-certificate", "-a", "-Z", systemKeychain)
	if strings.Contains(out, r.SHA1) {
		_, _ = run(true, "security", "delete-certificate", "-Z", r.SHA1, systemKeychain)
	}
}

// installTrust adds the root to the System keychain as trusted for TLS.
// Safari, Chrome, curl, git and most apps use this store. Firefox uses it too
// when "security.enterprise_roots.enabled" is on, the default on macOS.
func installTrust(r *RootInfo, file string) error {
	if trustInstalled(r) {
		note("already trusted")
		return nil
	}
	note("macOS will ask for your password to add it to the System keychain")
	out, err := run(true, "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-p", "ssl", "-k", systemKeychain, file)
	if err != nil {
		dropUntrusted(r) // macOS adds the certificate before asking; don't leave it behind
		if strings.Contains(out, "no user interaction was possible") {
			// macOS only lets a person approve new trusted certificates on screen,
			// even for root. Over SSH or in a background job there is no screen.
			return errorf("macOS needs you to approve the certificate on screen, and it can't ask here.\n" +
				"  Run this in Terminal on the Mac itself (not over SSH), or have your\n" +
				"  device management install the certificate, then run with --no-trust.")
		}
		return errorf("could not add the certificate: %v\n%s", err, out)
	}
	return nil
}

func removeTrust(r *RootInfo, file string) error {
	if !trustInstalled(r) {
		return nil
	}
	_, _ = run(true, "security", "remove-trusted-cert", "-d", file)
	out, err := run(true, "security", "delete-certificate", "-Z", r.SHA1, systemKeychain)
	if err != nil {
		return errorf("could not remove the certificate: %v\n%s", err, out)
	}
	return nil
}

func tailscaleCandidates() []string {
	return []string{"tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
		"/opt/homebrew/bin/tailscale", "/usr/local/bin/tailscale"}
}

func tailscaleInstallHelp() string {
	return "Install Tailscale from the Mac App Store or https://tailscale.com/download/mac, open it once, then run this again."
}

func openURL(u string) { _, _ = run(false, "open", u) }
