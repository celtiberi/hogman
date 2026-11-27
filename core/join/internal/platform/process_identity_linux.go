//go:build linux

package platform

import (
	"os"
	"strconv"
)

func processExePath(pid int) (string, bool) {
	if pid <= 0 || !ProcessAlive(pid) {
		return "", false
	}
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil || exe == "" {
		return "", false
	}
	return exe, true
}
