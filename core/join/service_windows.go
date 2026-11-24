package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Windows: the agent runs as a plain background process for now. It does not
// yet start by itself at login. Untested.
func startAgent(dir string, c *agentConfig, o options) error {
	bin, err := installedBinary(dir)
	if err != nil {
		return err
	}
	if currentAgentHealthy(dir, c) {
		return nil
	}
	stopAgent(dir, c)
	note("on Windows the pen connection does not yet restart by itself; run this command again after a restart")
	return startDetached(bin, dir)
}

func stopAgent(dir string, c *agentConfig) { stopDetached(dir) }

func stopOrphanAgentForDir(string) {}

func shareServiceConfigured(*shareConfig) bool { return false }

func startShareBackground(dir string, c *shareConfig, _ options) (bool, int, error) {
	bin, err := installedBinary(dir)
	if err != nil {
		return false, 0, err
	}
	note("on Windows shares do not yet restart by themselves; run this command again after a restart")
	return startShareServiceWithBinary(bin, dir, c, true)
}

func startShareServiceWithBinary(bin, dir string, _ *shareConfig, _ bool) (bool, int, error) {
	pid, err := spawnDetached(filepath.Join(dir, "share.log"), bin, "__share-run", dir)
	return false, pid, err
}

func stopShareService(*shareConfig) {}

func startDetached(bin, dir string) error {
	logf, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "agent", dir)
	cmd.Stdout, cmd.Stderr = logf, logf
	return cmd.Start()
}

func setSystemProxy(c *agentConfig, pens []*agentConfig) (string, bool, error) {
	pens = normalizePenConfigs(pens, c)
	stableURL := c.pacURL()
	if host := pickPACHost(pens); host != nil {
		stableURL = host.pacURL()
	}
	return formatBrowserProxyInstructions("windows", stableURL, c.Zone, penZoneNames(pens)), false, nil
}

func clearSystemProxy(leaving *agentConfig, remaining []*agentConfig) string {
	remaining = normalizePenConfigs(remaining, nil)
	host := pickPACHost(remaining)
	if host == nil {
		return ""
	}
	return "if Windows proxy \"Use setup script\" was pointing at " + leaving.pacURL() +
		", update it to " + host.pacURL() + " for your remaining pen(s): " + strings.Join(penZoneNames(remaining), ", ")
}
