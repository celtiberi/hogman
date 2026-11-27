//go:build linux

package fsutil

import (
	"bytes"
	"os"
	"strconv"
)

// parseProcStatStartTime extracts field 22 (starttime in clock ticks since boot)
// from a Linux /proc/<pid>/stat line, returning "" for zombies or malformed lines.
func parseProcStatStartTime(stat []byte) string {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 || i+2 >= len(stat) {
		return ""
	}
	fields := bytes.Fields(stat[i+2:])
	// fields[0] is state (field 3); field 22 (starttime) is index 19.
	if len(fields) <= 19 || len(fields[0]) == 0 {
		return ""
	}
	if fields[0][0] == 'Z' || fields[0][0] == 'X' {
		return ""
	}
	tag := string(fields[19])
	if _, err := strconv.ParseUint(tag, 10, 64); err != nil {
		return ""
	}
	return tag
}

func processStartTag(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	return parseProcStatStartTime(b)
}
