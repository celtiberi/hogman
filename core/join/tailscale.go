package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"time"
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
	out, err := run(false, t.bin, "status", "--json")
	if err != nil && !strings.HasPrefix(strings.TrimSpace(out), "{") {
		return nil, errorf("tailscale is installed but not running (%v). Start it and run this again.\n%s", err, out)
	}
	var s TSStatus
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &s); err != nil {
		return nil, errorf("could not read tailscale status: %v", err)
	}
	return &s, nil
}

// OnNetwork reports whether the active Tailscale profile is this network.
func (s *TSStatus) OnNetwork(zone string) bool {
	return s.CurrentTailnet != nil && s.CurrentTailnet.MagicDNSSuffix == "nodes."+zone
}

// OnOtherNetwork names another tailnet this device is currently using, if any.
func (s *TSStatus) OnOtherNetwork(zone string) string {
	if s.BackendState == "Running" && s.CurrentTailnet != nil && !s.OnNetwork(zone) {
		return s.CurrentTailnet.Name
	}
	return ""
}

// Login joins as a new Tailscale profile, so any other network this device
// was on is kept and can be switched back to with `tailscale switch`.
func (t *Tailscale) Login(loginServer, key, hostname string) error {
	args := []string{"login", "--login-server=" + loginServer, "--authkey=" + key,
		"--accept-dns=true", "--accept-routes=false", "--timeout=60s"}
	if hostname != "" {
		args = append(args, "--hostname="+hostname)
	}
	out, err := run(false, t.bin, args...)
	if err != nil && needsPrivilege(out) && !isRoot() {
		note("Tailscale needs administrator rights here")
		out, err = run(true, t.bin, args...)
	}
	if err != nil {
		return errorf("tailscale could not join: %v\n%s", err, redact(out, key))
	}
	return nil
}

func (t *Tailscale) Logout() error {
	out, err := run(false, t.bin, "logout")
	if err != nil && needsPrivilege(out) && !isRoot() {
		out, err = run(true, t.bin, "logout")
	}
	if err != nil {
		return errorf("tailscale logout: %v\n%s", err, out)
	}
	return nil
}

// RemoveProfiles deletes this device's saved Tailscale profiles for the
// network (named after its control host), except the one in use.
func (t *Tailscale) RemoveProfiles(controlHost string) int {
	out, err := run(false, t.bin, "switch", "--list", "--json")
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
		out, err := run(false, t.bin, "switch", "remove", p.ID)
		if err != nil && needsPrivilege(out) && !isRoot() {
			_, err = run(true, t.bin, "switch", "remove", p.ID)
		}
		if err == nil {
			n++
		}
	}
	return n
}

func (t *Tailscale) Down() error {
	out, err := run(false, t.bin, "down")
	if err != nil && needsPrivilege(out) && !isRoot() {
		_, err = run(true, t.bin, "down")
	}
	return err
}

func needsPrivilege(out string) bool {
	o := strings.ToLower(out)
	return strings.Contains(o, "access denied") || strings.Contains(o, "permission denied") ||
		strings.Contains(o, "operator") || strings.Contains(o, "must be root")
}

func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[key]")
}

// WaitRunning waits until this device is up on the network and has an address.
func (t *Tailscale) WaitRunning(zone string, d time.Duration) (*TSStatus, error) {
	deadline := time.Now().Add(d)
	for {
		s, err := t.Status()
		if err == nil && s.BackendState == "Running" && s.OnNetwork(zone) && s.Self != nil && len(s.Self.TailscaleIPs) > 0 {
			return s, nil
		}
		if time.Now().After(deadline) {
			state := "unknown"
			if s != nil {
				state = s.BackendState
			}
			return nil, errorf("joined, but the device did not come online within %s (state: %s)", d, state)
		}
		time.Sleep(time.Second)
	}
}
