package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"hogman/join/internal/agent"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/state"
)

func LaunchPlistPath(zone string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", LaunchLabel(zone)+".plist")
}

func SharePlistPath(c *state.ShareConfig) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", ShareLaunchLabel(c)+".plist")
}

func ServiceConfigured(zone string) bool {
	_, err := os.Stat(LaunchPlistPath(zone))
	return err == nil
}

func ShareServiceConfigured(c *state.ShareConfig) bool {
	_, err := os.Stat(SharePlistPath(c))
	return err == nil
}

// installLaunchAgent writes plist atomically and loads it into the current
// user's launchd GUI domain, removing the plist if bootstrap fails.
func installLaunchAgent(label, path, plist string) (string, error) {
	if err := fsutil.WriteFileAtomic(path, []byte(plist), 0o644); err != nil {
		return "", err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = Run("/bin/launchctl", "bootout", domain+"/"+label)
	out, err := Run("/bin/launchctl", "bootstrap", domain, path)
	if err != nil {
		_ = os.Remove(path)
		return out, err
	}
	return out, nil
}

// StartAgentService runs the agent as a per-user LaunchAgent (or detached when
// noService is true or launchd has no desktop session). Stops any previous agent first.
func StartAgentService(bin, dir string, c *state.AgentConfig, noService bool, note func(string, ...any)) error {
	StopAgent(dir, c)
	if noService {
		return StartDetached(bin, dir)
	}
	plist, err := RenderLaunchPlist(LaunchLabel(c.Zone), bin, dir, filepath.Join(dir, "agent.log"))
	if err != nil {
		return err
	}
	if out, err := installLaunchAgent(LaunchLabel(c.Zone), LaunchPlistPath(c.Zone), plist); err != nil {
		if out == "" {
			return err
		}
		// No desktop session (for example over SSH): fall back to a plain background process.
		emitNote(note, "could not register a login item (%s); running in the background until restart", link.SingleLine(out))
		return StartDetached(bin, dir)
	}
	emitNote(note, "it will start by itself when you log in")
	return nil
}

// StartExistingBinary starts an already-installed binary as a login item (used during updates).
func StartExistingBinary(bin, dir string, c *state.AgentConfig, noService bool, note func(string, ...any)) error {
	if noService {
		return StartDetached(bin, dir)
	}
	plist, err := RenderLaunchPlist(LaunchLabel(c.Zone), bin, dir, filepath.Join(dir, "agent.log"))
	if err != nil {
		emitNote(note, "could not render login item for %s (%v); running in the background until restart", c.Zone, err)
		return StartDetached(bin, dir)
	}
	if out, err := installLaunchAgent(LaunchLabel(c.Zone), LaunchPlistPath(c.Zone), plist); err != nil {
		if out != "" {
			emitNote(note, "could not register login item for %s (%s); running in the background until restart", c.Zone, link.SingleLine(out))
		} else {
			emitNote(note, "could not write login item for %s (%v); running in the background until restart", c.Zone, err)
		}
		return StartDetached(bin, dir)
	}
	return nil
}

func RewriteAgentService(bin, dir string, c *state.AgentConfig) error {
	plist, err := RenderLaunchPlist(LaunchLabel(c.Zone), bin, dir, filepath.Join(dir, "agent.log"))
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(LaunchPlistPath(c.Zone), []byte(plist), 0o644)
}

func RewriteShareService(bin, dir string, c *state.ShareConfig) error {
	plist, err := RenderShareLaunchPlist(c, bin, dir)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(SharePlistPath(c), []byte(plist), 0o644)
}

func StopAgent(dir string, c *state.AgentConfig) {
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = Run("/bin/launchctl", "bootout", domain+"/"+LaunchLabel(c.Zone))
	_ = os.Remove(LaunchPlistPath(c.Zone))
	StopDetached(dir)
}

// StopOrphanAgentForDir finds and stops any hogman or legacy hogman-join agent
// process owned by our UID running `agent <dir>` even if agent.pid is missing
// or stale.
func StopOrphanAgentForDir(dir string) {
	cleanDir := filepath.Clean(dir)
	if cleanDir == "" || cleanDir == "." || cleanDir == "/" {
		return
	}
	out, err := Run("/bin/ps", "-u", strconv.Itoa(os.Getuid()), "-o", "pid=,args=")
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
		tail := args[idx+len(needle):]
		if tail != "" && tail[0] != ' ' && tail[0] != '\t' {
			continue
		}
		exeBase := filepath.Base(strings.TrimSpace(args[:idx]))
		if !strings.HasPrefix(exeBase, "hogman") {
			continue
		}
		StopProcess(pid, 3*time.Second)
	}
}

func StartShareServiceWithBinary(bin, dir string, c *state.ShareConfig, noService bool, note func(string, ...any)) (bool, int, error) {
	logPath := filepath.Join(dir, "share.log")
	if noService {
		pid, err := SpawnDetached(logPath, bin, "__share-run", dir)
		return false, pid, err
	}
	plist, err := RenderShareLaunchPlist(c, bin, dir)
	if err != nil {
		return false, 0, err
	}
	if out, err := installLaunchAgent(ShareLaunchLabel(c), SharePlistPath(c), plist); err != nil {
		if out == "" {
			return false, 0, err
		}
		emitNote(note, "could not register a login item (%s); running in the background until restart", link.SingleLine(out))
		pid, serr := SpawnDetached(logPath, bin, "__share-run", dir)
		return false, pid, serr
	}
	emitNote(note, "it will start by itself when you log in")
	return true, 0, nil
}

func StopShareService(c *state.ShareConfig) {
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = Run("/bin/launchctl", "bootout", domain+"/"+ShareLaunchLabel(c))
	_ = os.Remove(SharePlistPath(c))
}

// networkServices lists the Mac's enabled network services (Wi-Fi, Ethernet...).
func networkServices() []string {
	out, err := Run("/usr/sbin/networksetup", "-listallnetworkservices")
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
	out, err := Run("/usr/sbin/networksetup", "-listnetworkserviceorder")
	if err != nil {
		return nil
	}
	return HardwareServiceNamesFromOrder(out)
}

func autoProxyState(svc string) (string, bool) {
	out, _ := Run("/usr/sbin/networksetup", "-getautoproxyurl", svc)
	return ParseAutoProxyOutput(out)
}

// SetSystemProxy checks (read-only, no password) whether macOS already points
// at a Hogman automatic proxy URL and returns clear instructions when any
// enabled hardware service still needs configuring (D-41).
func SetSystemProxy(c *state.AgentConfig, pens []*state.AgentConfig, note func(string, ...any)) (string, bool, error) {
	known := state.NormalizePenConfigs(pens, c)
	stableURL := c.PACURL()
	if host := agent.PickPACHost(known); host != nil {
		stableURL = host.PACURL()
	}

	var configured, missing, left []string
	configuredURL := ""
	seen := map[string]bool{}
	for _, svc := range hardwareNetworkServices() {
		seen[svc] = true
		cur, enabled := autoProxyState(svc)
		if enabled && cur != "" && state.IsHogmanPACURL(cur, known) {
			configured = append(configured, svc)
			if configuredURL == "" {
				configuredURL = cur
			}
		} else if ShouldLeaveAutoProxy(cur, enabled, known) {
			left = append(left, svc+" ("+cur+")")
		} else {
			missing = append(missing, svc)
		}
	}
	if len(configured) == 0 {
		for _, svc := range networkServices() {
			if seen[svc] {
				continue
			}
			cur, enabled := autoProxyState(svc)
			if enabled && cur != "" && state.IsHogmanPACURL(cur, known) {
				configured = append(configured, svc)
				if configuredURL == "" {
					configuredURL = cur
				}
			}
		}
	}

	if len(left) > 0 {
		emitNote(note, "another automatic proxy is already set on %s (left untouched)", strings.Join(left, ", "))
	}
	if len(configured) > 0 {
		return FormatDarwinProxySummary(configured, missing, configuredURL, stableURL, c.Zone, state.PenZoneNames(known)), true, nil
	}
	return FormatBrowserProxyInstructions("darwin", stableURL, c.Zone, state.PenZoneNames(known), missing), false, nil
}

// ClearSystemProxy checks (read-only, no password) whether macOS still points
// at a leaving or orphaned Hogman automatic proxy URL and returns clear steps
// to update or turn it off in System Settings (D-41).
func ClearSystemProxy(leaving *state.AgentConfig, remaining []*state.AgentConfig) string {
	known := state.NormalizePenConfigs(remaining, leaving)
	nextURL := ""
	if host := agent.PickPACHost(remaining); host != nil {
		nextURL = host.PACURL()
	}
	var matching []string
	for _, svc := range networkServices() {
		cur, enabled := autoProxyState(svc)
		if !enabled || cur == "" {
			continue
		}
		if leaving != nil {
			if state.IsHogmanPACURL(cur, []*state.AgentConfig{leaving}) {
				matching = append(matching, svc)
			}
		} else if IsOurPAC(cur, known) {
			if nextURL == "" || !state.IsHogmanPACURL(cur, remaining) {
				matching = append(matching, svc)
			}
		}
	}
	if len(matching) == 0 {
		return ""
	}
	if nextURL != "" {
		return fmt.Sprintf("in System Settings → Network → %s → Details… → Proxies, update \"Automatic proxy configuration\" to %s for your remaining pen(s): %s",
			strings.Join(matching, " / "), nextURL, strings.Join(state.PenZoneNames(remaining), ", "))
	}
	return fmt.Sprintf("turn off \"Automatic proxy configuration\" in System Settings → Network → %s → Details… → Proxies (the local proxy.pac server is now stopped)",
		strings.Join(matching, " / "))
}
