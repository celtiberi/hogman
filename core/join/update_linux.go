package main

import (
	"os"
	"path/filepath"
)

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
	path := unitPath(c.Zone)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		note("could not write user service for %s (%v); running in the background until restart", c.Zone, err)
		return startDetached(bin, dir)
	}
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		note("could not write user service for %s (%v); running in the background until restart", c.Zone, err)
		return startDetached(bin, dir)
	}
	sc := systemctlBin()
	_, _ = run(false, sc, "--user", "daemon-reload")
	if out, err := run(false, sc, "--user", "enable", "--now", unitName(c.Zone)); err != nil {
		note("could not start user service for %s (%s); running in the background until restart", c.Zone, firstLine(out))
		return startDetached(bin, dir)
	}
	return nil
}
