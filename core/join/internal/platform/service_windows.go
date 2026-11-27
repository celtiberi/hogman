//go:build windows

package platform

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"hogman/join/internal/agent"
	"hogman/join/internal/state"
)

// windowsRunRegPath is the per-user autostart registry key under HKCU
// (overridable in tests so unit tests never touch the host's real Run key).
var windowsRunRegPath = `Software\Microsoft\Windows\CurrentVersion\Run`

func hasWindowsRunValue(name string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, windowsRunRegPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	val, _, err := k.GetStringValue(name)
	return err == nil && strings.TrimSpace(val) != ""
}

func setWindowsRunValue(name, cmd string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, windowsRunRegPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, cmd)
}

func deleteWindowsRunValue(name string) {
	k, err := registry.OpenKey(registry.CURRENT_USER, windowsRunRegPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return
	}
}

func ServiceConfigured(zone string) bool {
	return hasWindowsRunValue(WindowsRunValueName(zone))
}

func ShareServiceConfigured(c *state.ShareConfig) bool {
	return hasWindowsRunValue(WindowsShareRunValueName(c))
}

func RewriteAgentService(bin, dir string, c *state.AgentConfig) error {
	cmd, err := RenderWindowsRunCommand(bin, "agent", dir)
	if err != nil {
		return err
	}
	return setWindowsRunValue(WindowsRunValueName(c.Zone), cmd)
}

func RewriteShareService(bin, dir string, c *state.ShareConfig) error {
	cmd, err := RenderWindowsRunCommand(bin, "share", dir)
	if err != nil {
		return err
	}
	return setWindowsRunValue(WindowsShareRunValueName(c), cmd)
}

// StartAgentService registers an unprivileged HKCU Run entry (unless noService
// is true) and launches the agent detached with no console window.
func StartAgentService(bin, dir string, c *state.AgentConfig, noService bool, note func(string, ...any)) error {
	StopAgent(dir, c)
	if !noService {
		if err := RewriteAgentService(bin, dir, c); err != nil {
			emitNote(note, "could not register Windows login autostart (%v); running in the background until restart", err)
		} else {
			emitNote(note, "it will start by itself when you log in")
		}
	}
	return StartDetached(bin, dir)
}

// StartExistingBinary starts an already-installed binary and refreshes its
// Windows login autostart entry unless noService is true (used during updates).
func StartExistingBinary(bin, dir string, c *state.AgentConfig, noService bool, note func(string, ...any)) error {
	if !noService {
		if err := RewriteAgentService(bin, dir, c); err != nil {
			emitNote(note, "could not update Windows login autostart for %s (%v); running in the background until restart", c.Zone, err)
		}
	}
	return StartDetached(bin, dir)
}

func StopAgent(dir string, c *state.AgentConfig) {
	deleteWindowsRunValue(WindowsRunValueName(c.Zone))
	StopDetached(dir)
}

func StopOrphanAgentForDir(string) {}

func StartShareServiceWithBinary(bin, dir string, c *state.ShareConfig, noService bool, note func(string, ...any)) (bool, int, error) {
	managed := false
	if !noService {
		if err := RewriteShareService(bin, dir, c); err != nil {
			emitNote(note, "could not register Windows login autostart (%v); running in the background until restart", err)
		} else {
			managed = true
			emitNote(note, "it will start by itself when you log in")
		}
	}
	pid, err := SpawnDetached(filepath.Join(dir, "share.log"), bin, "__share-run", dir)
	if err != nil {
		if managed {
			deleteWindowsRunValue(WindowsShareRunValueName(c))
		}
		return false, 0, err
	}
	return managed, pid, nil
}

func StopShareService(c *state.ShareConfig) {
	deleteWindowsRunValue(WindowsShareRunValueName(c))
}

func SetSystemProxy(c *state.AgentConfig, pens []*state.AgentConfig, _ func(string, ...any)) (string, bool, error) {
	pens = state.NormalizePenConfigs(pens, c)
	stableURL := c.PACURL()
	if host := agent.PickPACHost(pens); host != nil {
		stableURL = host.PACURL()
	}
	return FormatBrowserProxyInstructions("windows", stableURL, c.Zone, state.PenZoneNames(pens), nil), false, nil
}

func ClearSystemProxy(leaving *state.AgentConfig, remaining []*state.AgentConfig) string {
	remaining = state.NormalizePenConfigs(remaining, nil)
	host := agent.PickPACHost(remaining)
	if host == nil {
		return ""
	}
	if leaving == nil {
		return "make sure Windows proxy \"Use setup script\" points to " + host.PACURL() +
			" for your remaining pen(s): " + strings.Join(state.PenZoneNames(remaining), ", ")
	}
	return "if Windows proxy \"Use setup script\" was pointing at " + leaving.PACURL() +
		", update it to " + host.PACURL() + " for your remaining pen(s): " + strings.Join(state.PenZoneNames(remaining), ", ")
}
