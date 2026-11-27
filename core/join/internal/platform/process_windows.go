//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"hogman/join/internal/fsutil"
	"hogman/join/internal/state"
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

// ProcessAlive reports whether pid refers to a currently running, accessible
// Windows process (returning false for exited processes and for access-denied
// system/elevated processes that cannot be ours).
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
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

// StopProcess terminates pid on Windows only after verifying it is our hogman
// executable, and waits until kernel teardown finishes so executable locks and
// local proxy ports are released before returning.
func StopProcess(pid int, termTimeout time.Duration) {
	StopProcessVerified(pid, "", termTimeout)
}

// StopProcessVerified opens a single Windows process handle, verifies liveness,
// executable image path, and optional creation timestamp on that handle (closing
// the PID-reuse TOCTOU window), and terminates only if every check matches.
func StopProcessVerified(pid int, startTag string, termTimeout time.Duration) {
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
	access := uint32(windows.PROCESS_TERMINATE | windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.SYNCHRONIZE)
	h, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	if event, err := windows.WaitForSingleObject(h, 0); err != nil || event != uint32(windows.WAIT_TIMEOUT) {
		return
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil || size == 0 {
		return
	}
	gotExe := windows.UTF16ToString(buf[:size])
	wantExe, _ := fsutil.ResolvedExePath()
	canonicalBin := state.CanonicalBinaryPath(state.ConfigBase())
	if !ExeMatchesHogman(gotExe, wantExe, canonicalBin) {
		return
	}
	if startTag != "" {
		var creation, exit, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
			return
		}
		if ns := creation.Nanoseconds(); ns <= 0 || strconv.FormatInt(ns, 10) != startTag {
			return
		}
	}
	_ = windows.TerminateProcess(h, 1)
	_, _ = windows.WaitForSingleObject(h, uint32(waitTimeout/time.Millisecond))
}

// StopDetached stops a detached pen agent recorded in dir/agent.pid only if the
// PID still refers to our hogman binary (and matching start time), otherwise
// removing the stale PID file without killing unrelated processes.
func StopDetached(dir string) {
	StopPIDFile(filepath.Join(dir, "agent.pid"), 4*time.Second)
	StopOrphanAgentForDir(dir)
}

// StartDetached starts the pen agent directly as a detached background process.
func StartDetached(bin, dir string) error {
	_, err := SpawnDetached(filepath.Join(dir, "agent.log"), bin, "agent", dir)
	return err
}
