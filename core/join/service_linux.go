package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func unitPath(zone string) string {
	base, _ := os.UserConfigDir()
	return filepath.Join(base, "systemd", "user", unitName(zone))
}

func systemctlBin() string {
	if p := linuxSystemTool("systemctl"); p != "" {
		return p
	}
	return "/usr/bin/systemctl"
}

func haveUserSystemd() bool {
	sc := linuxSystemTool("systemctl")
	if sc == "" {
		return false
	}
	_, err := run(false, sc, "--user", "show-environment")
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
	sc := systemctlBin()
	_, _ = run(false, sc, "--user", "daemon-reload")
	if out, err := run(false, sc, "--user", "enable", "--now", unitName(c.Zone)); err != nil {
		return errorf("could not start the background service: %v\n%s", err, out)
	}
	note("it will start by itself when you log in")
	return nil
}

func stopAgent(dir string, c *agentConfig) {
	if haveUserSystemd() {
		sc := systemctlBin()
		_, _ = run(false, sc, "--user", "disable", "--now", unitName(c.Zone))
		_ = os.Remove(unitPath(c.Zone))
		_, _ = run(false, sc, "--user", "daemon-reload")
	}
	stopDetached(dir)
}

func shareUnitPath(c *shareConfig) string {
	base, _ := os.UserConfigDir()
	return filepath.Join(base, "systemd", "user", shareUnitName(c))
}

func shareServiceConfigured(c *shareConfig) bool {
	_, err := os.Stat(shareUnitPath(c))
	return err == nil
}

func currentUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

func linuxLingerEnabled() bool {
	name := currentUsername()
	if name == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join("/var/lib/systemd/linger", name)); err == nil {
		return true
	}
	lc := linuxSystemTool("loginctl")
	if lc == "" {
		return false
	}
	out, err := run(false, lc, "show-user", name, "-p", "Linger", "--value")
	return err == nil && strings.EqualFold(strings.TrimSpace(out), "yes")
}

func startShareBackground(dir string, c *shareConfig, o options) (bool, int, error) {
	bin, err := installedBinary(dir)
	if err != nil {
		return false, 0, err
	}
	return startShareServiceWithBinary(bin, dir, c, o.noService)
}

func startShareServiceWithBinary(bin, dir string, c *shareConfig, noService bool) (bool, int, error) {
	logPath := filepath.Join(dir, "share.log")
	if noService || !haveUserSystemd() {
		if !noService {
			note("no user service manager here; running in the background until restart")
		}
		pid, err := spawnDetached(logPath, bin, "__share-run", dir)
		return false, pid, err
	}
	unit := renderShareSystemdUnit(c, bin, dir)
	path := shareUnitPath(c)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, 0, err
	}
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return false, 0, err
	}
	sc := systemctlBin()
	_, _ = run(false, sc, "--user", "daemon-reload")
	if out, err := run(false, sc, "--user", "enable", "--now", shareUnitName(c)); err != nil {
		_ = os.Remove(path)
		_, _ = run(false, sc, "--user", "daemon-reload")
		return false, 0, errorf("could not start the background service: %v\n%s", err, out)
	}
	note("it will start by itself when you log in")
	if !linuxLingerEnabled() {
		if name := currentUsername(); name != "" {
			note("to keep running after you log out (e.g. on a server): sudo loginctl enable-linger %s", name)
		} else {
			note("to keep running after you log out (e.g. on a server): sudo loginctl enable-linger $USER")
		}
	}
	return true, 0, nil
}

func stopShareService(c *shareConfig) {
	path := shareUnitPath(c)
	if haveUserSystemd() {
		sc := systemctlBin()
		_, _ = run(false, sc, "--user", "disable", "--now", shareUnitName(c))
		_ = os.Remove(path)
		_, _ = run(false, sc, "--user", "daemon-reload")
		return
	}
	_ = os.Remove(path)
}

func startDetached(bin, dir string) error {
	_, err := spawnDetached(filepath.Join(dir, "agent.log"), bin, "agent", dir)
	return err
}

// Linux desktops each keep proxy settings in their own place, so the member
// sets it in the browser. The message says how.
func setSystemProxy(c *agentConfig, pens []*agentConfig) (string, error) {
	pens = normalizePenConfigs(pens, c)
	if len(pens) <= 1 {
		return "set your browser's (or desktop's) automatic proxy configuration URL to " + c.pacURL(), nil
	}
	return "set your browser's (or desktop's) automatic proxy configuration URL to " + c.pacURL() +
		" (covers all " + strconv.Itoa(len(pens)) + " pens: " + strings.Join(penZoneNames(pens), ", ") +
		"; if your browser already uses another pen's proxy.pac, reload proxy settings)", nil
}

func clearSystemProxy(leaving *agentConfig, remaining []*agentConfig) string {
	remaining = normalizePenConfigs(remaining, nil)
	host := pickPACHost(remaining)
	if host == nil {
		return ""
	}
	return "if your browser's automatic proxy configuration was pointing at " + leaving.pacURL() +
		", update it to " + host.pacURL() + " for your remaining pen(s): " + strings.Join(penZoneNames(remaining), ", ")
}
