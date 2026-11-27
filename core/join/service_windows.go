package main

import (
	"path/filepath"
	"strings"

	"hogman/join/internal/state"
)

// Windows: the agent runs as a plain background process for now. It does not
// yet start by itself at login. Untested.
func startAgent(dir string, c *state.AgentConfig, o options) error {
	if currentAgentHealthy(dir, c) {
		return nil
	}
	bin, err := installedBinary(dir)
	if err != nil {
		return err
	}
	stopAgent(dir, c)
	note("on Windows the pen connection does not yet restart by itself; run this command again after a restart")
	return startDetached(bin, dir)
}

func stopAgent(dir string, c *state.AgentConfig) { stopDetached(dir) }

func stopOrphanAgentForDir(string) {}

func shareServiceConfigured(*state.ShareConfig) bool { return false }

func startShareBackground(dir string, c *state.ShareConfig, _ options) (bool, int, error) {
	bin, err := installedBinary(dir)
	if err != nil {
		return false, 0, err
	}
	note("on Windows shares do not yet restart by themselves; run this command again after a restart")
	return startShareServiceWithBinary(bin, dir, c, true)
}

func startShareServiceWithBinary(bin, dir string, _ *state.ShareConfig, _ bool) (bool, int, error) {
	pid, err := spawnDetached(filepath.Join(dir, "share.log"), bin, "__share-run", dir)
	return false, pid, err
}

func stopShareService(*state.ShareConfig) {}

func startDetached(bin, dir string) error {
	_, err := spawnDetached(filepath.Join(dir, "agent.log"), bin, "agent", dir)
	return err
}

func setSystemProxy(c *state.AgentConfig, pens []*state.AgentConfig) (string, bool, error) {
	pens = state.NormalizePenConfigs(pens, c)
	stableURL := c.PACURL()
	if host := pickPACHost(pens); host != nil {
		stableURL = host.PACURL()
	}
	return formatBrowserProxyInstructions("windows", stableURL, c.Zone, state.PenZoneNames(pens), nil), false, nil
}

func clearSystemProxy(leaving *state.AgentConfig, remaining []*state.AgentConfig) string {
	remaining = state.NormalizePenConfigs(remaining, nil)
	host := pickPACHost(remaining)
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
