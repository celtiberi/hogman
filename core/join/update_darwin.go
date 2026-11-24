package main

import (
	"os"
	"path/filepath"
	"strconv"
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
	path := launchPlist(c.Zone)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		note("could not write login item for %s (%v); running in the background until restart", c.Zone, err)
		return startDetached(bin, dir)
	}
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		note("could not write login item for %s (%v); running in the background until restart", c.Zone, err)
		return startDetached(bin, dir)
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = run("/bin/launchctl", "bootout", domain+"/"+launchLabel(c.Zone))
	if out, err := run("/bin/launchctl", "bootstrap", domain, path); err != nil {
		_ = os.Remove(path)
		note("could not register login item for %s (%s); running in the background until restart", c.Zone, firstLine(out))
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
