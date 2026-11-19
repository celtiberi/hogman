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

func launchLabel(zone string) string { return "network.hogman." + zone }

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
	_, _ = run(false, "launchctl", "bootout", domain+"/"+launchLabel(c.Zone))
	if out, err := run(false, "launchctl", "bootstrap", domain, path); err != nil {
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
	_, _ = run(false, "launchctl", "bootout", domain+"/"+launchLabel(c.Zone))
	_ = os.Remove(launchPlist(c.Zone))
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

// networkServices lists the Mac's enabled network services (Wi-Fi, Ethernet...).
func networkServices() []string {
	out, err := run(false, "networksetup", "-listallnetworkservices")
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
	out, _ := run(false, "networksetup", "-getautoproxyurl", svc)
	return parseAutoProxyOutput(out)
}

// setSystemProxy points the Mac's automatic proxy setting at the agent's
// rules file, which sends only pen names through the pen. It never replaces
// an enabled setting someone else put there.
func setSystemProxy(c *agentConfig) (string, error) {
	manual := "set System Settings → Network → (your network) → Proxies → Automatic proxy configuration to " + c.pacURL()
	var done []string
	for _, svc := range networkServices() {
		cur, enabled := autoProxyState(svc)
		if shouldLeaveAutoProxy(cur, enabled, c.pacURL()) {
			return "this Mac already uses an automatic proxy (" + cur + "), so it was left alone. To use the pen in browsers, " + manual, nil
		}
		if enabled && cur == c.pacURL() {
			done = append(done, svc)
			continue
		}
		if out, err := run(true, "networksetup", "-setautoproxyurl", svc, c.pacURL()); err != nil {
			return "", fmt.Errorf("%s (%s). To do it by hand, %s", firstLine(out), svc, manual)
		}
		done = append(done, svc)
	}
	if len(done) == 0 {
		return manual, nil
	}
	return "Safari, Chrome and others now find the pen by themselves (set on: " + strings.Join(done, ", ") + ")", nil
}

func clearSystemProxy(c *agentConfig) string {
	cleared := false
	for _, svc := range networkServices() {
		cur, enabled := autoProxyState(svc)
		if enabled && cur == c.pacURL() {
			if _, err := run(true, "networksetup", "-setautoproxystate", svc, "off"); err == nil {
				cleared = true
			}
		}
	}
	if cleared {
		return "removed the pen's automatic proxy setting"
	}
	return ""
}
