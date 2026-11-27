//go:build linux

package platform

import (
	"bytes"
	"os"
	"strconv"
)

// parseProcStatZombie reports whether a Linux /proc/<pid>/stat line indicates
// a dead or unreaped zombie process ('Z' or 'X'). In containers whose PID 1
// does not reap children, Signal(0) still succeeds on zombies even after the
// process has exited and released all sockets.
func parseProcStatZombie(stat []byte) bool {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 || i+2 >= len(stat) {
		return false
	}
	state := stat[i+2]
	return state == 'Z' || state == 'X'
}

func isZombiePID(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	return parseProcStatZombie(b)
}
