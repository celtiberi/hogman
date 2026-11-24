package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func launchPlist(zone string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchLabel(zone)+".plist")
}

// startAgent runs the agent as a per-user LaunchAgent, so it starts at login
// and restarts if it stops. No administrator rights needed. Always stops any
// previous agent (including a legacy hogman-join process holding the proxy
// port) first.
func startAgent(dir string, c *agentConfig, o options) error {
	bin, err := installedBinary(dir)
	if err != nil {
		return err
	}
	if currentAgentHealthy(dir, c) {
		return nil
	}
	stopAgent(dir, c)
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

// stopOrphanAgentForDir finds and stops any hogman or legacy hogman-join agent
// process owned by our UID running `agent <dir>` even if agent.pid is missing
// or stale (I-10).
func stopOrphanAgentForDir(dir string) {
	cleanDir := filepath.Clean(dir)
	if cleanDir == "" || cleanDir == "." || cleanDir == "/" {
		return
	}
	out, err := run(false, "/bin/ps", "-u", strconv.Itoa(os.Getuid()), "-o", "pid=,args=")
	if err != nil {
		return
	}
	myPID := os.Getpid()
	needle := " agent " + cleanDir
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sp := strings.IndexAny(line, " \t")
		if sp <= 0 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(line[:sp]))
		if err != nil || pid <= 1 || pid == myPID {
			continue
		}
		args := strings.TrimSpace(line[sp:])
		idx := strings.Index(args, needle)
		if idx <= 0 {
			continue
		}
		// Match exact trailing argument (or followed by whitespace) and a hogman* executable.
		tail := args[idx+len(needle):]
		if tail != "" && tail[0] != ' ' && tail[0] != '\t' {
			continue
		}
		exeBase := filepath.Base(strings.TrimSpace(args[:idx]))
		if !strings.HasPrefix(exeBase, "hogman") {
			continue
		}
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Signal(syscall.SIGTERM)
			for i := 0; i < 20; i++ {
				if !processAlive(pid) {
					break
				}
				time.Sleep(150 * time.Millisecond)
			}
			if processAlive(pid) {
				_ = p.Kill()
				for i := 0; i < 10; i++ {
					if !processAlive(pid) {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
	}
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
	_, err := spawnDetached(filepath.Join(dir, "agent.log"), bin, "agent", dir)
	return err
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

// setSystemProxy checks (read-only, no password) whether macOS already points
// at a Hogman automatic proxy URL. If not, it returns step-by-step macOS
// System Settings instructions using the stable local PAC URL so Hogman never
// asks for the user's Mac password or administrator privileges (D-41).
func setSystemProxy(c *agentConfig, pens []*agentConfig) (string, bool, error) {
	known := normalizePenConfigs(pens, c)
	stableURL := c.pacURL()
	if host := pickPACHost(known); host != nil {
		stableURL = host.pacURL()
	}

	var configured, left []string
	configuredURL := ""
	for _, svc := range networkServices() {
		cur, enabled := autoProxyState(svc)
		if !enabled || cur == "" {
			continue
		}
		if isHogmanPACURL(cur, known) {
			configured = append(configured, svc)
			if configuredURL == "" {
				configuredURL = cur
			}
		} else {
			left = append(left, svc+" ("+cur+")")
		}
	}

	if len(configured) > 0 {
		if len(known) > 1 {
			return fmt.Sprintf("already configured on %s (%s), which covers all %d pens (%s). If your browser doesn't see %s right away, toggle Auto proxy configuration off and back on in System Settings (or restart your browser).",
				strings.Join(configured, ", "), configuredURL, len(known), strings.Join(penZoneNames(known), ", "), c.Zone), true, nil
		}
		return fmt.Sprintf("already configured on %s (%s) — Safari, Chrome and others find the pen automatically.",
			strings.Join(configured, ", "), configuredURL), true, nil
	}
	if len(left) > 0 {
		note("another automatic proxy is already set on %s (left untouched)", strings.Join(left, ", "))
	}
	return formatBrowserProxyInstructions("darwin", stableURL, c.Zone, penZoneNames(known)), false, nil
}

// clearSystemProxy checks (read-only, no password) whether macOS still points
// at a leaving or orphaned Hogman automatic proxy URL and returns clear steps
// to update or turn it off in System Settings (D-41).
func clearSystemProxy(leaving *agentConfig, remaining []*agentConfig) string {
	known := normalizePenConfigs(remaining, leaving)
	nextURL := ""
	if host := pickPACHost(remaining); host != nil {
		nextURL = host.pacURL()
	}
	var matching []string
	for _, svc := range networkServices() {
		cur, enabled := autoProxyState(svc)
		if !enabled || cur == "" {
			continue
		}
		if leaving != nil {
			if isHogmanPACURL(cur, []*agentConfig{leaving}) {
				matching = append(matching, svc)
			}
		} else if isOurPAC(cur, known) {
			if nextURL == "" || !isHogmanPACURL(cur, remaining) {
				matching = append(matching, svc)
			}
		}
	}
	if len(matching) == 0 {
		return ""
	}
	if nextURL != "" {
		return fmt.Sprintf("in System Settings → Network → %s → Details… → Proxies, update \"Auto proxy configuration\" to %s for your remaining pen(s): %s",
			strings.Join(matching, " / "), nextURL, strings.Join(penZoneNames(remaining), ", "))
	}
	return fmt.Sprintf("turn off \"Auto proxy configuration\" in System Settings → Network → %s → Details… → Proxies (the local proxy.pac server is now stopped)",
		strings.Join(matching, " / "))
}
