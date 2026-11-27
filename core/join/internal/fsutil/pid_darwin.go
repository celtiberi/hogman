//go:build darwin

package fsutil

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const darwinProcZombie = 5 // SZOMB from <sys/proc.h>

func processStartTag(pid int) string {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil || kp.Proc.P_stat == darwinProcZombie {
		return ""
	}
	if kp.Proc.P_starttime.Sec <= 0 && kp.Proc.P_starttime.Usec <= 0 {
		return ""
	}
	return fmt.Sprintf("%d.%06d", kp.Proc.P_starttime.Sec, kp.Proc.P_starttime.Usec)
}
