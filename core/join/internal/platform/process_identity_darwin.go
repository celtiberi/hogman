//go:build darwin

package platform

import (
	"bytes"

	"golang.org/x/sys/unix"
)

const darwinSZOMB = 5 // SZOMB from <sys/proc.h>

// parseDarwinProcArgs2Exe extracts the kernel exec_path from a KERN_PROCARGS2
// sysctl buffer (4-byte argc followed by a NUL-terminated executable path).
func parseDarwinProcArgs2Exe(raw []byte) string {
	if len(raw) <= 4 {
		return ""
	}
	rest := raw[4:]
	end := bytes.IndexByte(rest, 0)
	if end <= 0 {
		return ""
	}
	return string(rest[:end])
}

func processExePath(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil || kp.Proc.P_stat == darwinSZOMB {
		return "", false
	}
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", false
	}
	exe := parseDarwinProcArgs2Exe(raw)
	if exe == "" {
		return "", false
	}
	return exe, true
}
