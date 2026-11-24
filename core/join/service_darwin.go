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
	_, _ = run("/bin/launchctl", "bootout", domain+"/"+launchLabel(c.Zone))
	if out, err := run("/bin/launchctl", "bootstrap", domain, path); err != nil {
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
	_, _ = run("/bin/launchctl", "bootout", domain+"/"+launchLabel(c.Zone))
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
	out, err := run("/bin/ps", "-u", strconv.Itoa(os.Getuid()), "-o", "pid=,args=")
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
	_, _ = run("/bin/launchctl", "bootout", domain+"/"+shareLaunchLabel(c))
	if out, err := run("/bin/launchctl", "bootstrap", domain, path); err != nil {
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
	_, _ = run("/bin/launchctl", "bootout", domain+"/"+shareLaunchLabel(c))
	_ = os.Remove(sharePlist(c))
}

func startDetached(bin, dir string) error {
	_, err := spawnDetached(filepath.Join(dir, "agent.log"), bin, "agent", dir)
	return err
}

// networkServices lists the Mac's enabled network services (Wi-Fi, Ethernet...).
func networkServices() []string {
	out, err := run("/usr/sbin/networksetup", "-listallnetworkservices")
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

// hardwareNetworkServices lists enabled macOS hardware network services (e.g.
// Wi-Fi, USB 10/100/1000 LAN), excluding disabled services, VPN apps, and
// virtual bridges like Thunderbolt Bridge.
func hardwareNetworkServices() []string {
	out, err := run("/usr/sbin/networksetup", "-listnetworkserviceorder")
	if err != nil {
		return nil
	}
	return hardwareServiceNamesFromOrder(out)
}

func autoProxyState(svc string) (string, bool) {
	out, _ := run("/usr/sbin/networksetup", "-getautoproxyurl", svc)
	return parseAutoProxyOutput(out)
}

// setSystemProxy checks (read-only, no password) whether macOS already points
// at a Hogman automatic proxy URL. If any enabled hardware service is missing
// it, it names those exact services and gives step-by-step System Settings
// instructions using the stable local PAC URL so Hogman never asks for the
// user's Mac password or administrator privileges (D-41).
func setSystemProxy(c *agentConfig, pens []*agentConfig) (string, bool, error) {
	known := normalizePenConfigs(pens, c)
	stableURL := c.pacURL()
	if host := pickPACHost(known); host != nil {
		stableURL = host.pacURL()
	}

	var configured, missing, left []string
	configuredURL := ""
	seen := map[string]bool{}
	for _, svc := range hardwareNetworkServices() {
		seen[svc] = true
		cur, enabled := autoProxyState(svc)
		if enabled && cur != "" && isHogmanPACURL(cur, known) {
			configured = append(configured, svc)
			if configuredURL == "" {
				configuredURL = cur
			}
		} else if shouldLeaveAutoProxy(cur, enabled, known) {
			left = append(left, svc+" ("+cur+")")
		} else {
			missing = append(missing, svc)
		}
	}
	// If the user configured a non-hardware service with Hogman's PAC, recognize it.
	if len(configured) == 0 {
		for _, svc := range networkServices() {
			if seen[svc] {
				continue
			}
			cur, enabled := autoProxyState(svc)
			if enabled && cur != "" && isHogmanPACURL(cur, known) {
				configured = append(configured, svc)
				if configuredURL == "" {
					configuredURL = cur
				}
			}
		}
	}

	if len(left) > 0 {
		note("another automatic proxy is already set on %s (left untouched)", strings.Join(left, ", "))
	}
	if len(configured) > 0 {
		return formatDarwinProxySummary(configured, missing, configuredURL, stableURL, c.Zone, penZoneNames(known)), true, nil
	}
	return formatBrowserProxyInstructions("darwin", stableURL, c.Zone, penZoneNames(known), missing), false, nil
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
		return fmt.Sprintf("in System Settings → Network → %s → Details… → Proxies, update \"Automatic proxy configuration\" to %s for your remaining pen(s): %s",
			strings.Join(matching, " / "), nextURL, strings.Join(penZoneNames(remaining), ", "))
	}
	return fmt.Sprintf("turn off \"Automatic proxy configuration\" in System Settings → Network → %s → Details… → Proxies (the local proxy.pac server is now stopped)",
		strings.Join(matching, " / "))
}
