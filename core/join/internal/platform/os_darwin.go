package platform

import "os"

func IsRoot() bool { return os.Geteuid() == 0 }

func tailscaleCandidates() []string {
	// Only check the signed app bundle path.
	return []string{"/Applications/Tailscale.app/Contents/MacOS/Tailscale"}
}

func tailscaleInstallHelp() string {
	return "Install Tailscale from the Mac App Store or https://tailscale.com/download/mac, open it once, then run this again."
}

func OpenURL(u string) { _, _ = Run("/usr/bin/open", u) }
