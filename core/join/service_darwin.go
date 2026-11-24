package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func launchPlist(zone string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchLabel(zone)+".plist")
}

// startAgent runs the agent as a per-user LaunchAgent, so it starts at login
// and restarts if it stops. No administrator rights needed.
func startAgent(dir string, c *agentConfig, o options) error {
	bin, err := installedBinary(dir)
	if err != nil {
		return err
	}
	if o.noService {
		return startDetached(bin, dir)
	}
	plist, err := renderLaunchPlist(launchLabel(c.Zone), bin, dir, filepath.Join(dir, "agent.log"))
	if err != nil {
		return err
	}
	path := launchPlist(c.Zone)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = run(false, "/bin/launchctl", "bootout", domain+"/"+launchLabel(c.Zone))
	if out, err := run(false, "/bin/launchctl", "bootstrap", domain, path); err != nil {
		// No desktop session (for example over SSH): fall back to a plain background process.
		_ = os.Remove(path)
		note("could not register a login item (%s); running in the background until restart", firstLine(out))
		return startDetached(bin, dir)
	}
	note("it will start by itself when you log in")
	return nil
}

func stopAgent(dir string, c *agentConfig) {
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = run(false, "/bin/launchctl", "bootout", domain+"/"+launchLabel(c.Zone))
	_ = os.Remove(launchPlist(c.Zone))
	stopDetached(dir)
}

func sharePlist(c *shareConfig) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", shareLaunchLabel(c)+".plist")
}

func shareServiceConfigured(c *shareConfig) bool {
	_, err := os.Stat(sharePlist(c))
	return err == nil
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
	if noService {
		pid, err := spawnDetached(logPath, bin, "__share-run", dir)
		return false, pid, err
	}
	plist, err := renderShareLaunchPlist(c, bin, dir)
	if err != nil {
		return false, 0, err
	}
	path := sharePlist(c)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, 0, err
	}
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		return false, 0, err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = run(false, "/bin/launchctl", "bootout", domain+"/"+shareLaunchLabel(c))
	if out, err := run(false, "/bin/launchctl", "bootstrap", domain, path); err != nil {
		_ = os.Remove(path)
		note("could not register a login item (%s); running in the background until restart", firstLine(out))
		pid, serr := spawnDetached(logPath, bin, "__share-run", dir)
		return false, pid, serr
	}
	note("it will start by itself when you log in")
	return true, 0, nil
}

func stopShareService(c *shareConfig) {
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = run(false, "/bin/launchctl", "bootout", domain+"/"+shareLaunchLabel(c))
	_ = os.Remove(sharePlist(c))
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

// networkServices lists the Mac's enabled network services (Wi-Fi, Ethernet...).
func networkServices() []string {
	out, err := run(false, "/usr/sbin/networksetup", "-listallnetworkservices")
	if err != nil {
		return nil
	}
	var svcs []string
	for _, l := range strings.Split(out, "\n")[1:] {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "*") {
			svcs = append(svcs, l)
		}
	}
	return svcs
}

func autoProxyState(svc string) (string, bool) {
	out, _ := run(false, "/usr/sbin/networksetup", "-getautoproxyurl", svc)
	return parseAutoProxyOutput(out)
}

// setSystemProxy points the Mac's automatic proxy setting at the agent's
// rules file, which sends only pen names through their pens. It never replaces
// an enabled non-Hogman setting someone else put there.
func setSystemProxy(c *agentConfig, pens []*agentConfig) (string, error) {
	known := normalizePenConfigs(pens, c)
	want := pacURLWithVersion(c, known)
	manual := "set System Settings → Network → (your network) → Proxies → Automatic proxy configuration to " + c.pacURL()
	var done, left []string
	for _, svc := range networkServices() {
		cur, enabled := autoProxyState(svc)
		switch planAutoProxyAction(cur, enabled, known, want) {
		case "leave":
			// Someone else's setting (a company PAC, another tool): leave this
			// connection alone, but still set the others.
			left = append(left, svc+" ("+cur+")")
		case "noop":
			done = append(done, svc)
		case "set":
			explainSudo("to point this Mac's automatic proxy at the pen")
			if out, err := run(true, "/usr/sbin/networksetup", "-setautoproxyurl", svc, want); err != nil {
				return "", fmt.Errorf("%s (%s). To do it by hand, %s", firstLine(out), svc, manual)
			}
			done = append(done, svc)
		}
	}
	if len(done) == 0 {
		if len(left) > 0 {
			return "this Mac already uses another automatic proxy (" + strings.Join(left, ", ") + "), so it was left alone. To use the pen in browsers, " + manual, nil
		}
		return manual, nil
	}
	if len(left) > 0 {
		note("left alone (another automatic proxy is set): %s", strings.Join(left, ", "))
	}
	if len(known) > 1 {
		return fmt.Sprintf("Safari, Chrome and others now find all %d pens (%s) by themselves (set on: %s)",
			len(known), strings.Join(penZoneNames(known), ", "), strings.Join(done, ", ")), nil
	}
	return "Safari, Chrome and others now find the pen by themselves (set on: " + strings.Join(done, ", ") + ")", nil
}

func clearSystemProxy(leaving *agentConfig, remaining []*agentConfig) string {
	known := normalizePenConfigs(remaining, leaving)
	nextURL := ""
	if host := pickPACHost(remaining); host != nil {
		nextURL = pacURLWithVersion(host, remaining)
	}
	turnedOff, updated := false, false
	for _, svc := range networkServices() {
		cur, enabled := autoProxyState(svc)
		switch planClearAutoProxyAction(cur, enabled, known, nextURL) {
		case "off":
			explainSudo("to remove the pen from this Mac's automatic proxy setting")
			if _, err := run(true, "/usr/sbin/networksetup", "-setautoproxystate", svc, "off"); err == nil {
				turnedOff = true
			}
		case "set":
			explainSudo("to update this Mac's automatic proxy setting")
			if _, err := run(true, "/usr/sbin/networksetup", "-setautoproxyurl", svc, nextURL); err == nil {
				updated = true
			}
		}
	}
	if updated {
		return "updated the automatic proxy setting for your remaining pen(s): " + strings.Join(penZoneNames(remaining), ", ")
	}
	if turnedOff {
		return "removed the pen's automatic proxy setting"
	}
	return ""
}
