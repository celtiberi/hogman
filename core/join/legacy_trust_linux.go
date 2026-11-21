package main

import (
	"os"
	"os/exec"
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

// sbinTool finds an admin tool. Debian keeps update-ca-certificates in
// /usr/sbin, which isn't on an ordinary user's PATH, and we run it with sudo
// anyway, so look there too and use the full path.
func sbinTool(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/local/sbin"} {
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
		if out, err := run(true, "rm", "-f", p); err != nil {
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
	return []string{"tailscale", "/usr/bin/tailscale", "/usr/local/bin/tailscale"}
}

func tailscaleInstallHelp() string {
	return "Install Tailscale (https://tailscale.com/download/linux, or: curl -fsSL https://tailscale.com/install.sh | sh), then run this again."
}

func openURL(u string) {
	if _, err := exec.LookPath("xdg-open"); err == nil {
		_, _ = run(false, "xdg-open", u)
	}
}
