//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// isolateNativeStdout duplicates fd 1 for exclusive Native Messaging framing
// and redirects fd 1 and os.Stdout to stderr so stray prints never corrupt JSON frames.
func isolateNativeStdout() (*os.File, error) {
	fd, err := syscall.Dup(int(os.Stdout.Fd()))
	if err != nil {
		return nil, err
	}
	if err := syscall.Dup2(int(os.Stderr.Fd()), int(os.Stdout.Fd())); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	os.Stdout = os.Stderr
	return os.NewFile(uintptr(fd), "native-stdout"), nil
}

type nativeManifestTarget struct {
	browser string
	kind    string // "chrome" or "firefox"
	dir     string
}

func browserNativeManifestTargets(goos, home string) []nativeManifestTarget {
	if home == "" {
		return nil
	}
	switch goos {
	case "darwin":
		appSupport := filepath.Join(home, "Library", "Application Support")
		return []nativeManifestTarget{
			{browser: "Chrome", kind: "chrome", dir: filepath.Join(appSupport, "Google", "Chrome", "NativeMessagingHosts")},
			{browser: "Chrome Beta", kind: "chrome", dir: filepath.Join(appSupport, "Google", "Chrome Beta", "NativeMessagingHosts")},
			{browser: "Chrome Canary", kind: "chrome", dir: filepath.Join(appSupport, "Google", "Chrome Canary", "NativeMessagingHosts")},
			{browser: "Brave", kind: "chrome", dir: filepath.Join(appSupport, "BraveSoftware", "Brave-Browser", "NativeMessagingHosts")},
			{browser: "Edge", kind: "chrome", dir: filepath.Join(appSupport, "Microsoft Edge", "NativeMessagingHosts")},
			{browser: "Arc", kind: "chrome", dir: filepath.Join(appSupport, "Arc", "User Data", "NativeMessagingHosts")},
			{browser: "Vivaldi", kind: "chrome", dir: filepath.Join(appSupport, "Vivaldi", "NativeMessagingHosts")},
			{browser: "Chromium", kind: "chrome", dir: filepath.Join(appSupport, "Chromium", "NativeMessagingHosts")},
			{browser: "Firefox", kind: "firefox", dir: filepath.Join(appSupport, "Mozilla", "NativeMessagingHosts")},
			{browser: "LibreWolf", kind: "firefox", dir: filepath.Join(appSupport, "LibreWolf", "NativeMessagingHosts")},
		}
	case "linux":
		cfg := filepath.Join(home, ".config")
		return []nativeManifestTarget{
			{browser: "Chrome", kind: "chrome", dir: filepath.Join(cfg, "google-chrome", "NativeMessagingHosts")},
			{browser: "Brave", kind: "chrome", dir: filepath.Join(cfg, "BraveSoftware", "Brave-Browser", "NativeMessagingHosts")},
			{browser: "Edge", kind: "chrome", dir: filepath.Join(cfg, "microsoft-edge", "NativeMessagingHosts")},
			{browser: "Chromium", kind: "chrome", dir: filepath.Join(cfg, "chromium", "NativeMessagingHosts")},
			{browser: "Vivaldi", kind: "chrome", dir: filepath.Join(cfg, "vivaldi", "NativeMessagingHosts")},
			{browser: "Firefox", kind: "firefox", dir: filepath.Join(home, ".mozilla", "native-messaging-hosts")},
			{browser: "LibreWolf", kind: "firefox", dir: filepath.Join(home, ".librewolf", "native-messaging-hosts")},
		}
	default:
		return nil
	}
}

func registerNativeManifests(_ string, hostPath string, chromeIDs, firefoxIDs []string) (int, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0, err
	}
	return writeUnixNativeManifests(runtime.GOOS, home, hostPath, chromeIDs, firefoxIDs)
}

func writeUnixNativeManifests(goos, home, hostPath string, chromeIDs, firefoxIDs []string) (int, error) {
	var chromeJSON, firefoxJSON []byte
	var err error
	if len(chromeIDs) > 0 {
		chromeJSON, err = renderChromeNativeManifest(hostPath, chromeIDs)
		if err != nil {
			return 0, err
		}
	}
	if len(firefoxIDs) > 0 {
		firefoxJSON, err = renderFirefoxNativeManifest(hostPath, firefoxIDs)
		if err != nil {
			return 0, err
		}
	}
	written := 0
	for _, t := range browserNativeManifestTargets(goos, home) {
		var data []byte
		switch t.kind {
		case "chrome":
			data = chromeJSON
		case "firefox":
			data = firefoxJSON
		}
		if len(data) == 0 {
			continue
		}
		if err := os.MkdirAll(t.dir, 0o755); err != nil {
			return written, fmt.Errorf("create %s: %w", t.dir, err)
		}
		dst := filepath.Join(t.dir, nativeHostName+".json")
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return written, fmt.Errorf("write %s: %w", dst, err)
		}
		written++
	}
	return written, nil
}

func unregisterNativeManifests(_ string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	for _, t := range browserNativeManifestTargets(runtime.GOOS, home) {
		_ = os.Remove(filepath.Join(t.dir, nativeHostName+".json"))
	}
}
