package main

import (
	"os"

	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/state"
)

func serviceConfigured(zone string) bool {
	_, err := os.Stat(unitPath(zone))
	return err == nil
}

func startExistingBinary(bin, dir string, c *state.AgentConfig, noService bool) error {
	if noService || !haveUserSystemd() {
		return startDetached(bin, dir)
	}
	unit := renderSystemdUnit(c.Zone, bin, dir)
	if out, err := installSystemdUnit(unitName(c.Zone), unitPath(c.Zone), unit, false); err != nil {
		if out != "" {
			note("could not start user service for %s (%s); running in the background until restart", c.Zone, link.FirstLine(out))
		} else {
			note("could not write user service for %s (%v); running in the background until restart", c.Zone, err)
		}
		return startDetached(bin, dir)
	}
	return nil
}

func rewriteAgentService(bin, dir string, c *state.AgentConfig) error {
	unit := renderSystemdUnit(c.Zone, bin, dir)
	if err := fsutil.WriteFileAtomic(unitPath(c.Zone), []byte(unit), 0o644); err != nil {
		return err
	}
	if haveUserSystemd() {
		_, _ = run(systemctlBin(), "--user", "daemon-reload")
	}
	return nil
}

func rewriteShareService(bin, dir string, c *state.ShareConfig) error {
	unit := renderShareSystemdUnit(c, bin, dir)
	if err := fsutil.WriteFileAtomic(shareUnitPath(c), []byte(unit), 0o644); err != nil {
		return err
	}
	if haveUserSystemd() {
		_, _ = run(systemctlBin(), "--user", "daemon-reload")
	}
	return nil
}
