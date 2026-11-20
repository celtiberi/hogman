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
		return startDetached(bin, dir)
	}
	path := launchPlist(c.Zone)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return startDetached(bin, dir)
	}
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		return startDetached(bin, dir)
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = run(false, "launchctl", "bootout", domain+"/"+launchLabel(c.Zone))
	if _, err := run(false, "launchctl", "bootstrap", domain, path); err != nil {
		_ = os.Remove(path)
		return startDetached(bin, dir)
	}
	return nil
}
