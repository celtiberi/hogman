package main

import (
	"os"
	"path/filepath"
)

func isRoot() bool { return os.Geteuid() == 0 }

// Distributions keep extra trust anchors in different places.
type anchorStore struct {
	dir    string
	update []string
}

func linuxStore() (*anchorStore, error) {
	stores := []anchorStore{
		{"/usr/local/share/ca-certificates", []string{"update-ca-certificates"}},              // Debian, Ubuntu, Alpine
		{"/etc/pki/ca-trust/source/anchors", []string{"update-ca-trust", "extract"}},          // Fedora, RHEL
		{"/etc/ca-certificates/trust-source/anchors", []string{"update-ca-trust", "extract"}}, // Arch
	}
	for _, s := range stores {
		tool := sbinTool(s.update[0])
		if tool == "" {
			continue
		}
		if fi, err := os.Stat(s.dir); err == nil && fi.IsDir() {
			s.update = append([]string{tool}, s.update[1:]...)
			return &s, nil
		}
	}
	return nil, errorf("could not find this system's certificate store (looked for update-ca-certificates and update-ca-trust)")
}

// sbinTool finds an admin tool strictly from trusted system directories
// (never $PATH) because it is executed under sudo as root.
func sbinTool(name string) string {
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin"} {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

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

func removeLegacyHogmanRoot(zone, rootFP string) (bool, error) {
	s, err := linuxStore()
	if err != nil {
		return false, nil
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return false, nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	paths := filterLinuxLegacyAnchorFiles(s.dir, names, zone, rootFP, os.ReadFile)
	if len(paths) == 0 {
		return false, nil
	}
	for _, p := range paths {
		if out, err := run(true, "/bin/rm", "-f", p); err != nil {
			return false, errorf("could not remove old certificate (%s): %v\n%s", p, err, out)
		}
	}
	args := s.update[1:]
	if filepath.Base(s.update[0]) == "update-ca-certificates" {
		args = append([]string{"--fresh"}, args...)
	}
	if out, err := run(true, s.update[0], args...); err != nil {
		return false, errorf("could not refresh the certificate store: %v\n%s", err, out)
	}
	return true, nil
}

func tailscaleCandidates() []string {
	return []string{"/usr/bin/tailscale", "/usr/local/bin/tailscale"}
}

func tailscaleInstallHelp() string {
	return "Install Tailscale (https://tailscale.com/download/linux, or: curl -fsSL https://tailscale.com/install.sh | sh), then run this again."
}

func openURL(u string) {
	if p := linuxSystemTool("xdg-open"); p != "" {
		_, _ = run(false, p, u)
	}
}
