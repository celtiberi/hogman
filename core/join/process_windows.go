//go:build windows

package main

import (
	"os"
	"time"
)

// stopProcess terminates pid on Windows (where SIGTERM is unsupported) and
// waits briefly for the process handle to disappear.
func stopProcess(pid int, _ time.Duration) {
	if pid <= 0 {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	defer func() { _ = p.Release() }()
	_ = p.Kill()
	deadline := time.Now().Add(time.Second)
	for processAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
}
