//go:build windows

package platform

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const winStillActive = 259 // Win32 STILL_ACTIVE

// SpawnDetached starts bin with args detached in its own process group with no
// console window, logging to logPath, so it survives closing the parent shell.
func SpawnDetached(logPath, bin string, args ...string) (int, error) {
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer logf.Close()
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW,
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	go func() { _ = cmd.Wait() }() // reap handle if it exits while we watch
	return pid, nil
}

// ProcessAlive reports whether pid refers to a currently running Windows process
// (returning false for exited processes even if another handle keeps the PID alive).
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer windows.CloseHandle(h)
	if event, err := windows.WaitForSingleObject(h, 0); err == nil {
		return event == uint32(windows.WAIT_TIMEOUT)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == winStillActive
}

// StopProcess terminates pid on Windows and waits until kernel teardown finishes
// so executable locks and local proxy ports are released before returning.
func StopProcess(pid int, termTimeout time.Duration) {
	if pid <= 0 {
		return
	}
	waitTimeout := termTimeout
	if waitTimeout < 2*time.Second {
		waitTimeout = 2 * time.Second
	}
	if waitTimeout > 5*time.Second {
		waitTimeout = 5 * time.Second
	}
	if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid)); err == nil {
		defer windows.CloseHandle(h)
		_ = windows.TerminateProcess(h, 1)
		_, _ = windows.WaitForSingleObject(h, uint32(waitTimeout/time.Millisecond))
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	defer func() { _ = p.Release() }()
	_ = p.Kill()
	deadline := time.Now().Add(waitTimeout)
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
