//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
)

func isolateNativeStdout() (*os.File, error) {
	out := os.Stdout
	os.Stdout = os.Stderr
	return out, nil
}

var windowsNativeRegKeys = []struct {
	kind string
	key  string
}{
	{kind: "chrome", key: `HKCU\Software\Google\Chrome\NativeMessagingHosts\` + nativeHostName},
	{kind: "chrome", key: `HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\` + nativeHostName},
	{kind: "chrome", key: `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\` + nativeHostName},
	{kind: "firefox", key: `HKCU\Software\Mozilla\NativeMessagingHosts\` + nativeHostName},
}

func installNativeHostBinary(canonicalBin, hostPath string) error {
	if fsutil.SameFilePath(canonicalBin, hostPath) {
		return nil
	}
	return fsutil.CopyExecutableAtomic(canonicalBin, hostPath)
}

func registerNativeManifests(configBase, hostPath string, chromeIDs, firefoxIDs []string) (int, error) {
	binDir := filepath.Join(configBase, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return 0, err
	}
	chromePath := filepath.Join(binDir, nativeHostName+".chrome.json")
	firefoxPath := filepath.Join(binDir, nativeHostName+".firefox.json")

	hasChrome := false
	if len(chromeIDs) > 0 {
		b, err := renderChromeNativeManifest(hostPath, chromeIDs)
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(chromePath, b, 0o644); err != nil {
			return 0, err
		}
		hasChrome = true
	}
	hasFirefox := false
	if len(firefoxIDs) > 0 {
		b, err := renderFirefoxNativeManifest(hostPath, firefoxIDs)
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(firefoxPath, b, 0o644); err != nil {
			return 0, err
		}
		hasFirefox = true
	}

	written := 0
	for _, rk := range windowsNativeRegKeys {
		var manifestPath string
		switch rk.kind {
		case "chrome":
			if !hasChrome {
				continue
			}
			manifestPath = chromePath
		case "firefox":
			if !hasFirefox {
				continue
			}
			manifestPath = firefoxPath
		}
		if out, err := exec.Command(winSystem32("reg.exe"), "add", rk.key, "/ve", "/t", "REG_SZ", "/d", manifestPath, "/f").CombinedOutput(); err != nil {
			return written, fmt.Errorf("register %s: %v (%s)", rk.key, err, link.FirstLine(string(out)))
		}
		written++
	}
	return written, nil
}

func unregisterNativeManifests(configBase string) {
	regExe := winSystem32("reg.exe")
	for _, rk := range windowsNativeRegKeys {
		_ = exec.Command(regExe, "delete", rk.key, "/f").Run()
	}
	binDir := filepath.Join(configBase, "bin")
	_ = os.Remove(filepath.Join(binDir, nativeHostName+".chrome.json"))
	_ = os.Remove(filepath.Join(binDir, nativeHostName+".firefox.json"))
}
