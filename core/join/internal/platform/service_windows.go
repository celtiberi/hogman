package platform

import (
	"path/filepath"
	"strings"

	"hogman/join/internal/agent"
	"hogman/join/internal/state"
)

func ServiceConfigured(string) bool { return false }

func ShareServiceConfigured(*state.ShareConfig) bool { return false }

// StartAgentService runs the agent as a plain background process on Windows.
func StartAgentService(bin, dir string, c *state.AgentConfig, _ bool, note func(string, ...any)) error {
	StopAgent(dir, c)
	emitNote(note, "on Windows the pen connection does not yet restart by itself; run this command again after a restart")
	return StartDetached(bin, dir)
}

func StartExistingBinary(bin, dir string, _ *state.AgentConfig, _ bool, _ func(string, ...any)) error {
	return StartDetached(bin, dir)
}

func RewriteAgentService(string, string, *state.AgentConfig) error { return nil }

func RewriteShareService(string, string, *state.ShareConfig) error { return nil }

func StopAgent(dir string, _ *state.AgentConfig) { StopDetached(dir) }

func StopOrphanAgentForDir(string) {}

func StartShareServiceWithBinary(bin, dir string, _ *state.ShareConfig, _ bool, _ func(string, ...any)) (bool, int, error) {
	pid, err := SpawnDetached(filepath.Join(dir, "share.log"), bin, "__share-run", dir)
	return false, pid, err
}

func StopShareService(*state.ShareConfig) {}

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
