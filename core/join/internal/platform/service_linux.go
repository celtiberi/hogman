package platform

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"hogman/join/internal/agent"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/state"
)

func UnitPath(zone string) string {
	base, _ := os.UserConfigDir()
	return filepath.Join(base, "systemd", "user", UnitName(zone))
}

func ShareUnitPath(c *state.ShareConfig) string {
	base, _ := os.UserConfigDir()
	return filepath.Join(base, "systemd", "user", ShareUnitName(c))
}

func ServiceConfigured(zone string) bool {
	_, err := os.Stat(UnitPath(zone))
	return err == nil
}

func ShareServiceConfigured(c *state.ShareConfig) bool {
	_, err := os.Stat(ShareUnitPath(c))
	return err == nil
}

func systemctlBin() string {
	if p := LinuxSystemTool("systemctl"); p != "" {
		return p
	}
	return "/usr/bin/systemctl"
}

func haveUserSystemd() bool {
	sc := LinuxSystemTool("systemctl")
	if sc == "" {
		return false
	}
	_, err := Run(sc, "--user", "show-environment")
	return err == nil
}

// installSystemdUnit writes content atomically to path, reloads systemd --user,
// and enables + starts unit. If removeOnFail is true, path is removed and
// daemon-reload is re-run when enable fails.
func installSystemdUnit(unit, path, content string, removeOnFail bool) (string, error) {
	if err := fsutil.WriteFileAtomic(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	sc := systemctlBin()
	_, _ = Run(sc, "--user", "daemon-reload")
	out, err := Run(sc, "--user", "enable", "--now", unit)
	if err != nil && removeOnFail {
		_ = os.Remove(path)
		_, _ = Run(sc, "--user", "daemon-reload")
	}
	return out, err
}

// StartAgentService runs the agent as a systemd user service where available,
// otherwise as a plain background process. Stops any previous agent first.
func StartAgentService(bin, dir string, c *state.AgentConfig, noService bool, note func(string, ...any)) error {
	StopAgent(dir, c)
	if noService || !haveUserSystemd() {
		if !noService {
			emitNote(note, "no user service manager here; running in the background until restart")
		}
		return StartDetached(bin, dir)
	}
	unit := RenderSystemdUnit(c.Zone, bin, dir)
	if out, err := installSystemdUnit(UnitName(c.Zone), UnitPath(c.Zone), unit, false); err != nil {
		if out == "" {
			return err
		}
		return link.Errorf("could not start the background service: %v\n%s", err, out)
	}
	emitNote(note, "it will start by itself when you log in")
	return nil
}

func StartExistingBinary(bin, dir string, c *state.AgentConfig, noService bool, note func(string, ...any)) error {
	if noService || !haveUserSystemd() {
		return StartDetached(bin, dir)
	}
	unit := RenderSystemdUnit(c.Zone, bin, dir)
	if out, err := installSystemdUnit(UnitName(c.Zone), UnitPath(c.Zone), unit, false); err != nil {
		if out != "" {
			emitNote(note, "could not start user service for %s (%s); running in the background until restart", c.Zone, link.SingleLine(out))
		} else {
			emitNote(note, "could not write user service for %s (%v); running in the background until restart", c.Zone, err)
		}
		return StartDetached(bin, dir)
	}
	return nil
}

func RewriteAgentService(bin, dir string, c *state.AgentConfig) error {
	unit := RenderSystemdUnit(c.Zone, bin, dir)
	if err := fsutil.WriteFileAtomic(UnitPath(c.Zone), []byte(unit), 0o644); err != nil {
		return err
	}
	if haveUserSystemd() {
		_, _ = Run(systemctlBin(), "--user", "daemon-reload")
	}
	return nil
}

func RewriteShareService(bin, dir string, c *state.ShareConfig) error {
	unit := RenderShareSystemdUnit(c, bin, dir)
	if err := fsutil.WriteFileAtomic(ShareUnitPath(c), []byte(unit), 0o644); err != nil {
		return err
	}
	if haveUserSystemd() {
		_, _ = Run(systemctlBin(), "--user", "daemon-reload")
	}
	return nil
}

func StopAgent(dir string, c *state.AgentConfig) {
	if haveUserSystemd() {
		sc := systemctlBin()
		_, _ = Run(sc, "--user", "disable", "--now", UnitName(c.Zone))
		_ = os.Remove(UnitPath(c.Zone))
		_, _ = Run(sc, "--user", "daemon-reload")
	}
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
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	myPID := os.Getpid()
	myUID := uint32(os.Getuid())
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 || pid == myPID {
			continue
		}
		fi, err := os.Stat(filepath.Join("/proc", e.Name()))
		if err != nil {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != myUID {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		parts := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
		if len(parts) < 3 {
			continue
		}
		exeBase := filepath.Base(string(parts[0]))
		if !strings.HasPrefix(exeBase, "hogman") {
			continue
		}
		if string(parts[1]) != "agent" || filepath.Clean(string(parts[2])) != cleanDir {
			continue
		}
		StopProcess(pid, 3*time.Second)
	}
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
	lc := LinuxSystemTool("loginctl")
	if lc == "" {
		return false
	}
	out, err := Run(lc, "show-user", name, "-p", "Linger", "--value")
	return err == nil && strings.EqualFold(strings.TrimSpace(out), "yes")
}

func StartShareServiceWithBinary(bin, dir string, c *state.ShareConfig, noService bool, note func(string, ...any)) (bool, int, error) {
	logPath := filepath.Join(dir, "share.log")
	if noService || !haveUserSystemd() {
		if !noService {
			emitNote(note, "no user service manager here; running in the background until restart")
		}
		pid, err := SpawnDetached(logPath, bin, "__share-run", dir)
		return false, pid, err
	}
	unit := RenderShareSystemdUnit(c, bin, dir)
	if out, err := installSystemdUnit(ShareUnitName(c), ShareUnitPath(c), unit, true); err != nil {
		if out == "" {
			return false, 0, err
		}
		return false, 0, link.Errorf("could not start the background service: %v\n%s", err, out)
	}
	emitNote(note, "it will start by itself when you log in")
	if !linuxLingerEnabled() {
		if name := currentUsername(); name != "" {
			emitNote(note, "to keep running after you log out (e.g. on a server): sudo loginctl enable-linger %s", name)
		} else {
			emitNote(note, "to keep running after you log out (e.g. on a server): sudo loginctl enable-linger $USER")
		}
	}
	return true, 0, nil
}

func StopShareService(c *state.ShareConfig) {
	path := ShareUnitPath(c)
	if haveUserSystemd() {
		sc := systemctlBin()
		_, _ = Run(sc, "--user", "disable", "--now", ShareUnitName(c))
		_ = os.Remove(path)
		_, _ = Run(sc, "--user", "daemon-reload")
		return
	}
	_ = os.Remove(path)
}

func SetSystemProxy(c *state.AgentConfig, pens []*state.AgentConfig, _ func(string, ...any)) (string, bool, error) {
	pens = state.NormalizePenConfigs(pens, c)
	stableURL := c.PACURL()
	if host := agent.PickPACHost(pens); host != nil {
		stableURL = host.PACURL()
	}
	return FormatBrowserProxyInstructions("linux", stableURL, c.Zone, state.PenZoneNames(pens), nil), false, nil
}

func ClearSystemProxy(leaving *state.AgentConfig, remaining []*state.AgentConfig) string {
	remaining = state.NormalizePenConfigs(remaining, nil)
	host := agent.PickPACHost(remaining)
	if host == nil {
		return ""
	}
	if leaving == nil {
		return "make sure your browser's automatic proxy configuration points to " + host.PACURL() +
			" for your remaining pen(s): " + strings.Join(state.PenZoneNames(remaining), ", ")
	}
	return "if your browser's automatic proxy configuration was pointing at " + leaving.PACURL() +
		", update it to " + host.PACURL() + " for your remaining pen(s): " + strings.Join(state.PenZoneNames(remaining), ", ")
}
