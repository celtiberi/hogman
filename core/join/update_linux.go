package main

import "os"

func serviceConfigured(zone string) bool {
	_, err := os.Stat(unitPath(zone))
	return err == nil
}

func replaceExecutable(tmpPath, dstPath string) error {
	return os.Rename(tmpPath, dstPath)
}

func startExistingBinary(bin, dir string, c *agentConfig, noService bool) error {
	if noService || !haveUserSystemd() {
		return startDetached(bin, dir)
	}
	unit := renderSystemdUnit(c.Zone, bin, dir)
	if out, err := installSystemdUnit(unitName(c.Zone), unitPath(c.Zone), unit, false); err != nil {
		if out != "" {
			note("could not start user service for %s (%s); running in the background until restart", c.Zone, firstLine(out))
		} else {
			note("could not write user service for %s (%v); running in the background until restart", c.Zone, err)
		}
		return startDetached(bin, dir)
	}
	return nil
}

func rewriteAgentService(bin, dir string, c *agentConfig) error {
	unit := renderSystemdUnit(c.Zone, bin, dir)
	if err := writeFileAtomic(unitPath(c.Zone), []byte(unit), 0o644); err != nil {
		return err
	}
	if haveUserSystemd() {
		_, _ = run(systemctlBin(), "--user", "daemon-reload")
	}
	return nil
}

func rewriteShareService(bin, dir string, c *shareConfig) error {
	unit := renderShareSystemdUnit(c, bin, dir)
	if err := writeFileAtomic(shareUnitPath(c), []byte(unit), 0o644); err != nil {
		return err
	}
	if haveUserSystemd() {
		_, _ = run(systemctlBin(), "--user", "daemon-reload")
	}
	return nil
}
