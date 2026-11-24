package main

import (
	"os"
	"path/filepath"
)

func isRoot() bool { return os.Geteuid() == 0 }

// linuxSystemTool resolves a standard Linux userland utility from fixed system
// directories (including NixOS's system profile) without trusting $PATH.
func linuxSystemTool(name string) string {
	for _, dir := range []string{"/usr/bin", "/bin", "/run/current-system/sw/bin"} {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

func tailscaleCandidates() []string {
	return []string{"/usr/bin/tailscale", "/usr/local/bin/tailscale"}
}

func tailscaleInstallHelp() string {
	return "Install Tailscale (https://tailscale.com/download/linux, or: curl -fsSL https://tailscale.com/install.sh | sh), then run this again."
}

func openURL(u string) {
	if p := linuxSystemTool("xdg-open"); p != "" {
		_, _ = run(p, u)
	}
}
