package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	kernel32DLL       = syscall.NewLazyDLL("kernel32.dll")
	procGetSystemDirW = kernel32DLL.NewProc("GetSystemDirectoryW")
)

func winSystem32(rel ...string) string {
	sysDir := ""
	buf := make([]uint16, 260)
	if n, _, _ := procGetSystemDirW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); n > 0 && int(n) < len(buf) {
		sysDir = syscall.UTF16ToString(buf[:n])
	}
	if sysDir == "" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		sysDir = filepath.Join(root, "System32")
	}
	parts := append([]string{sysDir}, rel...)
	return filepath.Join(parts...)
}

// isRoot reports whether we are elevated ("Run as administrator").
func isRoot() bool {
	return exec.Command(winSystem32("net.exe"), "session").Run() == nil
}

func tailscaleCandidates() []string {
	return []string{`C:\Program Files\Tailscale\tailscale.exe`}
}

func tailscaleInstallHelp() string {
	return "Install Tailscale from https://tailscale.com/download/windows, then run this again."
}

func openURL(u string) {
	_, _ = run(winSystem32("rundll32.exe"), "url.dll,FileProtocolHandler", u)
}
