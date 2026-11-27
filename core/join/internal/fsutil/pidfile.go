package fsutil

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProcessStartTag returns an OS-native process creation identifier for pid
// (Win32 creation FILETIME nanoseconds, Linux /proc/<pid>/stat starttime ticks,
// or macOS kinfo_proc start timestamp), or "" if unavailable.
func ProcessStartTag(pid int) string {
	if pid <= 0 {
		return ""
	}
	return processStartTag(pid)
}

// PIDStartPath returns the sibling metadata path recording "<pid> <startTag>"
// alongside a standard single-integer PID file (agent.pid / share.pid).
func PIDStartPath(pidPath string) string {
	return pidPath + ".start"
}

// WritePIDFile records the current process's PID in path (as a standard
// single-integer PID file for compatibility with older binaries and tools) and
// writes "<pid> <startTag>" to path+".start" when an OS creation tag is
// available so later stops and liveness checks can reject reused PIDs.
func WritePIDFile(path string) error {
	pid := os.Getpid()
	if err := WriteFileAtomic(path, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		return err
	}
	if tag := ProcessStartTag(pid); tag != "" {
		_ = WriteFileAtomic(PIDStartPath(path), []byte(fmt.Sprintf("%d %s\n", pid, tag)), 0o600)
	} else {
		_ = os.Remove(PIDStartPath(path))
	}
	return nil
}

// RemovePIDFile removes both the PID file and its sibling start-tag metadata.
func RemovePIDFile(path string) {
	_ = os.Remove(path)
	_ = os.Remove(PIDStartPath(path))
}

// ReadPIDFile parses a PID file written by WritePIDFile (accepting either a
// standard "<pid>" file plus optional sibling "<pid>.start", or an inline
// "<pid> <startTag>" file).
func ReadPIDFile(path string) (pid int, startTag string, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, "", false
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, "", false
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil || n <= 0 {
		return 0, "", false
	}
	if len(fields) >= 2 {
		return n, fields[1], true
	}
	if sb, err := os.ReadFile(PIDStartPath(path)); err == nil {
		sfields := strings.Fields(string(sb))
		if len(sfields) >= 2 {
			if sn, err := strconv.Atoi(sfields[0]); err == nil && sn == n {
				return n, sfields[1], true
			}
		}
	}
	return n, "", true
}
