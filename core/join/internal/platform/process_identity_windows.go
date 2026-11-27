//go:build windows

package platform

import (
	"golang.org/x/sys/windows"
)

func processExePath(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)
	if event, err := windows.WaitForSingleObject(h, 0); err != nil || event != uint32(windows.WAIT_TIMEOUT) {
		return "", false
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil || size == 0 {
		return "", false
	}
	return windows.UTF16ToString(buf[:size]), true
}
