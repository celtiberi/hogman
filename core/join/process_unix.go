//go:build !windows

package main

import (
	"os"
	"syscall"
	"time"
)

// stopProcess sends SIGTERM to pid and waits up to termTimeout for it to exit
// cleanly, escalating to SIGKILL (waiting up to 1s) if it is still running.
func stopProcess(pid int, termTimeout time.Duration) {
	if pid <= 0 {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Signal(syscall.SIGTERM)
	if waitProcessExit(pid, termTimeout) {
		return
	}
	_ = p.Kill()
	_ = waitProcessExit(pid, time.Second)
}

func waitProcessExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !processAlive(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}
