//go:build windows

package nativehost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"

	"hogman/join/internal/fsutil"
)

func isolateNativeStdout() (*os.File, error) {
	out := os.Stdout
	os.Stdout = os.Stderr
	return out, nil
}

// windowsNativeRegPrefix is the HKCU subkey root (overridable in tests so unit
// tests never modify the runner's real Chrome/Edge/Firefox registry keys).
var windowsNativeRegPrefix = "Software"

var windowsNativeBrowsers = []struct {
	kind   string
	subkey string
}{
	{kind: "chrome", subkey: `Google\Chrome\NativeMessagingHosts\` + HostName},
	{kind: "chrome", subkey: `BraveSoftware\Brave-Browser\NativeMessagingHosts\` + HostName},
	{kind: "chrome", subkey: `Microsoft\Edge\NativeMessagingHosts\` + HostName},
	{kind: "chrome", subkey: `Chromium\NativeMessagingHosts\` + HostName},
	{kind: "firefox", subkey: `Mozilla\NativeMessagingHosts\` + HostName},
}

func InstallBinary(canonicalBin, hostPath string) error {
	if fsutil.SameFilePath(canonicalBin, hostPath) {
		return nil
	}
	return fsutil.CopyExecutableAtomic(canonicalBin, hostPath)
}

func registerNativeManifests(configBase, hostPath string, chromeIDs, firefoxIDs []string, _ func(string, ...any)) (int, error) {
	return registerNativeManifestsUnder(windowsNativeRegPrefix, configBase, hostPath, chromeIDs, firefoxIDs)
}

func registerNativeManifestsUnder(regPrefix, configBase, hostPath string, chromeIDs, firefoxIDs []string) (int, error) {
	binDir := filepath.Join(configBase, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return 0, err
	}
	chromePath := filepath.Join(binDir, HostName+".chrome.json")
	firefoxPath := filepath.Join(binDir, HostName+".firefox.json")

	hasChrome := false
	if len(chromeIDs) > 0 {
		b, err := RenderChromeManifest(hostPath, chromeIDs)
		if err != nil {
			return 0, err
		}
		if err := fsutil.WriteFileAtomic(chromePath, b, 0o644); err != nil {
			return 0, err
		}
		hasChrome = true
	}
	hasFirefox := false
	if len(firefoxIDs) > 0 {
		b, err := RenderFirefoxManifest(hostPath, firefoxIDs)
		if err != nil {
			return 0, err
		}
		if err := fsutil.WriteFileAtomic(firefoxPath, b, 0o644); err != nil {
			return 0, err
		}
		hasFirefox = true
	}

	written := 0
	for _, b := range windowsNativeBrowsers {
		var manifestPath string
		switch b.kind {
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
		keyPath := regPrefix + `\` + b.subkey
		k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
		if err != nil {
			return written, fmt.Errorf("register HKCU\\%s: %w", keyPath, err)
		}
		err = k.SetStringValue("", manifestPath)
		_ = k.Close()
		if err != nil {
			return written, fmt.Errorf("register HKCU\\%s: %w", keyPath, err)
		}
		written++
	}
	return written, nil
}

func unregisterNativeManifests(configBase string) {
	unregisterNativeManifestsUnder(windowsNativeRegPrefix, configBase)
}

func unregisterNativeManifestsUnder(regPrefix, configBase string) {
	for _, b := range windowsNativeBrowsers {
		keyPath := regPrefix + `\` + b.subkey
		if err := registry.DeleteKey(registry.CURRENT_USER, keyPath); err != nil && !errors.Is(err, registry.ErrNotExist) {
			continue
		}
	}
	binDir := filepath.Join(configBase, "bin")
	_ = os.Remove(filepath.Join(binDir, HostName+".chrome.json"))
	_ = os.Remove(filepath.Join(binDir, HostName+".firefox.json"))
}
