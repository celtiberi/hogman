package main

import (
	"os"
	"os/exec"
)

// spawnDetached starts bin with args in the background, logging to logPath.
// Untested on Windows.
func spawnDetached(logPath, bin string, args ...string) error {
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	return cmd.Start()
}

// processAlive: on Windows, FindProcess fails for a process that has gone.
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
