//go:build windows

package fsutil

import (
	"strconv"

	"golang.org/x/sys/windows"
)

func processStartTag(pid int) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return ""
	}
	ns := creation.Nanoseconds()
	if ns <= 0 {
		return ""
	}
	return strconv.FormatInt(ns, 10)
}
