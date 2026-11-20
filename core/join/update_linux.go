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
		return startDetached(bin, dir)
	}
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return startDetached(bin, dir)
	}
	_, _ = run(false, "systemctl", "--user", "daemon-reload")
	if _, err := run(false, "systemctl", "--user", "enable", "--now", unitName(c.Zone)); err != nil {
		return startDetached(bin, dir)
	}
	return nil
}
