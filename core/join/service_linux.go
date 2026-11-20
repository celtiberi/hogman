package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func unitName(zone string) string { return "hogman-" + zone + ".service" }

func unitPath(zone string) string {
	base, _ := os.UserConfigDir()
	return filepath.Join(base, "systemd", "user", unitName(zone))
}

func haveUserSystemd() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	_, err := run(false, "systemctl", "--user", "show-environment")
	return err == nil
}

// startAgent runs the agent as a systemd user service where there is one,
// otherwise as a plain background process.
func startAgent(dir string, c *agentConfig, o options) error {
	bin, err := installedBinary(dir)
	if err != nil {
		return err
	}
	if o.noService || !haveUserSystemd() {
		if !o.noService {
			note("no user service manager here; running in the background until restart")
		}
		return startDetached(bin, dir)
	}
	unit := renderSystemdUnit(c.Zone, bin, dir)
	path := unitPath(c.Zone)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return err
	}
	_, _ = run(false, "systemctl", "--user", "daemon-reload")
	if out, err := run(false, "systemctl", "--user", "enable", "--now", unitName(c.Zone)); err != nil {
		return errorf("could not start the background service: %v\n%s", err, out)
	}
	note("it will start by itself when you log in")
	return nil
}

func stopAgent(dir string, c *agentConfig) {
	if haveUserSystemd() {
		_, _ = run(false, "systemctl", "--user", "disable", "--now", unitName(c.Zone))
		_ = os.Remove(unitPath(c.Zone))
		_, _ = run(false, "systemctl", "--user", "daemon-reload")
	}
	stopDetached(dir)
}

func startDetached(bin, dir string) error {
	logf, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "agent", dir)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Env = os.Environ()
	return cmd.Start()
}

// Linux desktops each keep proxy settings in their own place, so the member
// sets it in the browser. The message says how.
func setSystemProxy(c *agentConfig) (string, error) {
	return "set your browser's (or desktop's) automatic proxy configuration URL to " + c.pacURL(), nil
}

func clearSystemProxy(c *agentConfig) string { return "" }
