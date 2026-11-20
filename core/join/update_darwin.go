package main

import "os"

func serviceConfigured(zone string) bool {
	_, err := os.Stat(launchPlist(zone))
	return err == nil
}

func replaceExecutable(tmpPath, dstPath string) error {
	return os.Rename(tmpPath, dstPath)
}
