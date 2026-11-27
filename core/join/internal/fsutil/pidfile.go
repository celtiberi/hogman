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

// WritePIDFile records the current process's PID (and OS start tag when
// available) so later stops or liveness checks can reject reused PIDs.
func WritePIDFile(path string) error {
	pid := os.Getpid()
	content := strconv.Itoa(pid)
	if tag := ProcessStartTag(pid); tag != "" {
		content = fmt.Sprintf("%d %s", pid, tag)
	}
	return WriteFileAtomic(path, []byte(content+"\n"), 0o600)
}

// ReadPIDFile parses a PID file written by WritePIDFile (or a legacy single-PID
// file containing only "<pid>").
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
	return n, "", true
}
