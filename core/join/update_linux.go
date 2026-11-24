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

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hogman-unit-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	keep = true
	return nil
}

func rewriteAgentService(bin, dir string, c *agentConfig) error {
	unit := renderSystemdUnit(c.Zone, bin, dir)
	if err := writeFileAtomic(unitPath(c.Zone), []byte(unit), 0o644); err != nil {
		return err
	}
	if haveUserSystemd() {
		_, _ = run(false, systemctlBin(), "--user", "daemon-reload")
	}
	return nil
}

func rewriteShareService(bin, dir string, c *shareConfig) error {
	unit := renderShareSystemdUnit(c, bin, dir)
	if err := writeFileAtomic(shareUnitPath(c), []byte(unit), 0o644); err != nil {
		return err
	}
	if haveUserSystemd() {
		_, _ = run(false, systemctlBin(), "--user", "daemon-reload")
	}
	return nil
}
