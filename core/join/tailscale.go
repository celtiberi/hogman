package main

import (
	"encoding/json"
	"os/exec"
	"strings"
)

// Tailscale drives the stock Tailscale client already on this machine.
type Tailscale struct{ bin string }

func findTailscale() (*Tailscale, error) {
	for _, c := range tailscaleCandidates() {
		if p, err := exec.LookPath(c); err == nil {
			return &Tailscale{bin: p}, nil
		}
	}
	return nil, errorf("Tailscale is not installed. %s", tailscaleInstallHelp())
}

type TSStatus struct {
	BackendState string
	Self         *struct {
		HostName     string
		DNSName      string
		TailscaleIPs []string
		Online       bool
	}
	CurrentTailnet *struct {
		Name           string
		MagicDNSSuffix string
	}
}

func (t *Tailscale) Status() (*TSStatus, error) {
	out, err := run(t.bin, "status", "--json")
	idx := strings.Index(out, "{")
	if err != nil && idx < 0 {
		return nil, errorf("tailscale is installed but not running (%v). Start it and run this again.\n%s", err, out)
	}
	if idx < 0 {
		return nil, errorf("could not read tailscale status: unexpected output")
	}
	var s TSStatus
	if err := json.Unmarshal([]byte(out[idx:]), &s); err != nil {
		return nil, errorf("could not read tailscale status: %v", err)
	}
	return &s, nil
}

// OnNetwork reports whether the active Tailscale profile is this network.
func (s *TSStatus) OnNetwork(zone string) bool {
	return s.CurrentTailnet != nil && s.CurrentTailnet.MagicDNSSuffix == "nodes."+zone
}

func (t *Tailscale) Logout() error {
	out, err := run(t.bin, "logout")
	if err != nil {
		if needsPrivilege(out) && !isRoot() {
			return errorf("Tailscale needs operator permission to log out (Hogman never runs sudo). Run this yourself:\n  sudo %s logout\n%s", t.bin, out)
		}
		return errorf("tailscale logout: %v\n%s", err, out)
	}
	return nil
}

// RemoveProfiles deletes this device's saved Tailscale profiles for the
// network (named after its control host), except the one in use.
func (t *Tailscale) RemoveProfiles(controlHost string) int {
	out, err := run(t.bin, "switch", "--list", "--json")
	if err != nil {
		return 0
	}
	var profiles []struct {
		ID       string `json:"id"`
		Tailnet  string `json:"tailnet"`
		Selected bool   `json:"selected"`
	}
	if json.Unmarshal([]byte(out), &profiles) != nil {
		return 0
	}
	n := 0
	for _, p := range profiles {
		if p.Tailnet != controlHost || p.Selected {
			continue
		}
		out, err := run(t.bin, "switch", "remove", p.ID)
		if err != nil {
			if needsPrivilege(out) && !isRoot() {
				note("could not remove old Tailscale profile %s without operator permission; remove it yourself with: sudo %s switch remove %s", p.ID, t.bin, p.ID)
			}
			continue
		}
		n++
	}
	return n
}

func (t *Tailscale) Down() error {
	out, err := run(t.bin, "down")
	if err != nil && needsPrivilege(out) && !isRoot() {
		return errorf("Tailscale needs operator permission to disconnect (Hogman never runs sudo). Run this yourself:\n  sudo %s down\n%s", t.bin, out)
	}
	return err
}

func needsPrivilege(out string) bool {
	o := strings.ToLower(out)
	return strings.Contains(o, "access denied") || strings.Contains(o, "permission denied") ||
		strings.Contains(o, "operator") || strings.Contains(o, "must be root")
}
