//go:build !windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
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

// StopProcess sends SIGTERM to pid only after verifying it is our hogman
// executable, waiting up to termTimeout for clean exit before escalating to
// SIGKILL (waiting up to 1s).
func StopProcess(pid int, termTimeout time.Duration) {
	StopProcessVerified(pid, "", termTimeout)
}

// StopProcessVerified verifies executable identity (and optional startTag)
// before sending SIGTERM and again before escalating to SIGKILL.
func StopProcessVerified(pid int, startTag string, termTimeout time.Duration) {
	if pid <= 0 || !ProcessMatchesPIDRecord(pid, startTag, "") {
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
	if !ProcessMatchesPIDRecord(pid, startTag, "") {
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

// StopDetached stops an agent that was started as a plain background process
// only if dir/agent.pid still refers to our hogman binary (and matching start
// time), otherwise removing the stale PID file without killing unrelated
// processes, then also stops any orphaned legacy hogman-join agent for dir.
func StopDetached(dir string) {
	StopPIDFile(filepath.Join(dir, "agent.pid"), 4*time.Second)
	StopOrphanAgentForDir(dir)
}

// StartDetached starts the pen agent directly as a detached background process.
func StartDetached(bin, dir string) error {
	_, err := SpawnDetached(filepath.Join(dir, "agent.log"), bin, "agent", dir)
	return err
}
