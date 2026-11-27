package main

import (
	"os"
	"path/filepath"

	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/state"
)

func serviceConfigured(zone string) bool {
	_, err := os.Stat(launchPlist(zone))
	return err == nil
}

func startExistingBinary(bin, dir string, c *state.AgentConfig, noService bool) error {
	if noService {
		return startDetached(bin, dir)
	}
	plist, err := renderLaunchPlist(launchLabel(c.Zone), bin, dir, filepath.Join(dir, "agent.log"))
	if err != nil {
		note("could not render login item for %s (%v); running in the background until restart", c.Zone, err)
		return startDetached(bin, dir)
	}
	if out, err := installLaunchAgent(launchLabel(c.Zone), launchPlist(c.Zone), plist); err != nil {
		if out != "" {
			note("could not register login item for %s (%s); running in the background until restart", c.Zone, link.FirstLine(out))
		} else {
			note("could not write login item for %s (%v); running in the background until restart", c.Zone, err)
		}
		return startDetached(bin, dir)
	}
	return nil
}

func rewriteAgentService(bin, dir string, c *state.AgentConfig) error {
	plist, err := renderLaunchPlist(launchLabel(c.Zone), bin, dir, filepath.Join(dir, "agent.log"))
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(launchPlist(c.Zone), []byte(plist), 0o644)
}

func rewriteShareService(bin, dir string, c *state.ShareConfig) error {
	plist, err := renderShareLaunchPlist(c, bin, dir)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(sharePlist(c), []byte(plist), 0o644)
}
