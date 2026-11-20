package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Windows: the agent runs as a plain background process for now. It does not
// yet start by itself at login. Untested.
func startAgent(dir string, c *agentConfig, o options) error {
	bin, err := installedBinary(dir)
	if err != nil {
		return err
	}
	note("on Windows the pen connection does not yet restart by itself; run this command again after a restart")
	return startDetached(bin, dir)
}

func stopAgent(dir string, c *agentConfig) { stopDetached(dir) }

func startDetached(bin, dir string) error {
	logf, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "agent", dir)
	cmd.Stdout, cmd.Stderr = logf, logf
	return cmd.Start()
}

func setSystemProxy(c *agentConfig, pens []*agentConfig) (string, error) {
	pens = normalizePenConfigs(pens, c)
	if len(pens) <= 1 {
		return "set Settings → Network & Internet → Proxy → \"Use setup script\" to " + c.pacURL(), nil
	}
	return "set Settings → Network & Internet → Proxy → \"Use setup script\" to " + c.pacURL() +
		" (covers all " + strconv.Itoa(len(pens)) + " pens: " + strings.Join(penZoneNames(pens), ", ") +
		"; if your proxy already uses another pen's proxy.pac, reload it)", nil
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
