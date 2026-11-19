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
		if _, err := exec.LookPath(s.update[0]); err != nil {
			continue
		}
		if fi, err := os.Stat(s.dir); err == nil && fi.IsDir() {
			return &s, nil
		}
	}
	return nil, errorf("could not find this system's certificate store (looked for update-ca-certificates and update-ca-trust)")
}

func anchorPath(s *anchorStore, r *RootInfo) string {
	return filepath.Join(s.dir, "hogman-"+r.Zone+".crt")
}

func trustInstalled(r *RootInfo) bool {
	s, err := linuxStore()
	if err != nil {
		return false
	}
	b, err := os.ReadFile(anchorPath(s, r))
	return err == nil && string(b) == r.PEM
}

// installTrust adds the root to the system store used by curl, git, Go,
// Python's requests (via certifi only if configured) and most tools.
// Chrome and Firefox on Linux keep their own stores (NSS); see the hint printed.
func installTrust(r *RootInfo, file string) error {
	s, err := linuxStore()
	if err != nil {
		return err
	}
	if trustInstalled(r) {
		note("already trusted")
		return nil
	}
	if out, err := run(true, "install", "-m", "0644", file, anchorPath(s, r)); err != nil {
		return errorf("could not copy the certificate: %v\n%s", err, out)
	}
	if out, err := run(true, s.update[0], s.update[1:]...); err != nil {
		return errorf("could not refresh the certificate store: %v\n%s", err, out)
	}
	note("browsers on Linux keep their own list; if Chrome or Firefox warn, import %s there", file)
	return nil
}

func removeTrust(r *RootInfo, _ string) error {
	s, err := linuxStore()
	if err != nil {
		return err
	}
	if _, err := os.Stat(anchorPath(s, r)); err != nil {
		return nil
	}
	if out, err := run(true, "rm", "-f", anchorPath(s, r)); err != nil {
		return errorf("could not remove the certificate: %v\n%s", err, out)
	}
	_, err = run(true, s.update[0], s.update[1:]...)
	return err
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
