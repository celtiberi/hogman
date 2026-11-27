//go:build !windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SpawnDetached starts bin with args in its own session, logging to logPath,
// so it keeps running after this window closes.
func SpawnDetached(logPath, bin string, args ...string) (int, error) {
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer logf.Close()
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	go func() { _ = cmd.Wait() }() // reap it if it exits while we watch
	return pid, nil
}

// ProcessAlive reports whether pid refers to a live (non-zombie) process.
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil || p.Signal(syscall.Signal(0)) != nil {
		return false
	}
	return !isZombiePID(pid)
}

// StopProcess sends SIGTERM to pid and waits up to termTimeout for it to exit
// cleanly, escalating to SIGKILL (waiting up to 1s) if it is still running.
func StopProcess(pid int, termTimeout time.Duration) {
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
		if !ProcessAlive(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// StopDetached stops an agent that was started as a plain background process,
// waiting until the process has actually exited so its proxy port is released,
// and also stops any orphaned legacy hogman-join agent still bound to dir.
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
