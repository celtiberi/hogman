//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// SpawnDetached starts bin with args in the background, logging to logPath.
func SpawnDetached(logPath, bin string, args ...string) (int, error) {
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer logf.Close()
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	go func() { _ = cmd.Wait() }() // reap it if it exits while we watch
	return pid, nil
}

// ProcessAlive reports whether pid refers to a running Windows process.
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}

// StopProcess terminates pid on Windows (where SIGTERM is unsupported) and
// waits briefly for the process handle to disappear.
func StopProcess(pid int, _ time.Duration) {
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
	for ProcessAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
}

// StopDetached stops a detached pen agent recorded in dir/agent.pid.
func StopDetached(dir string) {
	pidPath := filepath.Join(dir, "agent.pid")
	if b, err := os.ReadFile(pidPath); err == nil {
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err == nil && pid > 0 {
			StopProcess(pid, 4*time.Second)
		}
		_ = os.Remove(pidPath)
	}
	StopOrphanAgentForDir(dir)
}

// StartDetached starts the pen agent directly as a detached background process.
func StartDetached(bin, dir string) error {
	_, err := SpawnDetached(filepath.Join(dir, "agent.log"), bin, "agent", dir)
	return err
}
