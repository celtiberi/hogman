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

func removeLegacyHogmanRoot(zone, rootFP string) (bool, error) {
	var sha1s []string
	ps := winSystem32("WindowsPowerShell", "v1.0", "powershell.exe")
	certutil := winSystem32("certutil.exe")
	if psOut, err := run(false, ps, "-NoProfile", "-Command",
		"Get-ChildItem Cert:\\LocalMachine\\Root | ForEach-Object { [Convert]::ToBase64String($_.RawData) }"); err == nil {
		for _, m := range parseWindowsBase64CertsLegacyRoots(psOut, zone, rootFP) {
			sha1s = append(sha1s, m.SHA1)
		}
	} else if out, err := run(false, certutil, "-store", "Root"); err == nil {
		sha1s = parseWindowsLegacyRootSHA1s(out, zone)
	}
	if len(sha1s) == 0 {
		return false, nil
	}
	if !isRoot() {
		return false, errorf("removing old network certificate(s) needs administrator rights: open a terminal with \"Run as administrator\" and run this again")
	}
	removed := false
	for _, h := range sha1s {
		if out, err := run(false, certutil, "-delstore", "Root", h); err != nil {
			return removed, errorf("could not remove old certificate (%s): %v\n%s", h, err, out)
		}
		removed = true
	}
	return removed, nil
}

func tailscaleCandidates() []string {
	return []string{`C:\Program Files\Tailscale\tailscale.exe`}
}

func tailscaleInstallHelp() string {
	return "Install Tailscale from https://tailscale.com/download/windows, then run this again."
}

func openURL(u string) {
	_, _ = run(false, winSystem32("rundll32.exe"), "url.dll,FileProtocolHandler", u)
}
