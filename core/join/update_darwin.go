package main

import (
	"os"
	"path/filepath"
)

func serviceConfigured(zone string) bool {
	_, err := os.Stat(launchPlist(zone))
	return err == nil
}

func replaceExecutable(tmpPath, dstPath string) error {
	return os.Rename(tmpPath, dstPath)
}

func startExistingBinary(bin, dir string, c *agentConfig, noService bool) error {
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
			note("could not register login item for %s (%s); running in the background until restart", c.Zone, firstLine(out))
		} else {
			note("could not write login item for %s (%v); running in the background until restart", c.Zone, err)
		}
		return startDetached(bin, dir)
	}
	return nil
}

func rewriteAgentService(bin, dir string, c *agentConfig) error {
	plist, err := renderLaunchPlist(launchLabel(c.Zone), bin, dir, filepath.Join(dir, "agent.log"))
	if err != nil {
		return err
	}
	return writeFileAtomic(launchPlist(c.Zone), []byte(plist), 0o644)
}

func rewriteShareService(bin, dir string, c *shareConfig) error {
	plist, err := renderShareLaunchPlist(c, bin, dir)
	if err != nil {
		return err
	}
	return writeFileAtomic(sharePlist(c), []byte(plist), 0o644)
}
