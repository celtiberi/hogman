//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"hogman/join/internal/fsutil"
)

// isolateNativeStdout duplicates fd 1 for exclusive Native Messaging framing
// and redirects fd 1 and os.Stdout to stderr so stray prints never corrupt JSON frames.
func isolateNativeStdout() (*os.File, error) {
	fd, err := syscall.Dup(int(os.Stdout.Fd()))
	if err != nil {
		return nil, err
	}
	if err := dup2FD(int(os.Stderr.Fd()), int(os.Stdout.Fd())); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	os.Stdout = os.Stderr
	return os.NewFile(uintptr(fd), "native-stdout"), nil
}

type nativeManifestTarget struct {
	browser   string
	kind      string // "chrome" or "firefox"
	detectDir string // existing browser data dir required before creating manifest dir
	dir       string
}

func browserNativeManifestTargets(goos, home string) []nativeManifestTarget {
	if home == "" {
		return nil
	}
	switch goos {
	case "darwin":
		appSupport := filepath.Join(home, "Library", "Application Support")
		return []nativeManifestTarget{
			{browser: "Chrome", kind: "chrome", detectDir: filepath.Join(appSupport, "Google", "Chrome"), dir: filepath.Join(appSupport, "Google", "Chrome", "NativeMessagingHosts")},
			{browser: "Chrome Beta", kind: "chrome", detectDir: filepath.Join(appSupport, "Google", "Chrome Beta"), dir: filepath.Join(appSupport, "Google", "Chrome Beta", "NativeMessagingHosts")},
			{browser: "Chrome Canary", kind: "chrome", detectDir: filepath.Join(appSupport, "Google", "Chrome Canary"), dir: filepath.Join(appSupport, "Google", "Chrome Canary", "NativeMessagingHosts")},
			{browser: "Brave", kind: "chrome", detectDir: filepath.Join(appSupport, "BraveSoftware", "Brave-Browser"), dir: filepath.Join(appSupport, "BraveSoftware", "Brave-Browser", "NativeMessagingHosts")},
			{browser: "Edge", kind: "chrome", detectDir: filepath.Join(appSupport, "Microsoft Edge"), dir: filepath.Join(appSupport, "Microsoft Edge", "NativeMessagingHosts")},
			{browser: "Arc", kind: "chrome", detectDir: filepath.Join(appSupport, "Arc", "User Data"), dir: filepath.Join(appSupport, "Arc", "User Data", "NativeMessagingHosts")},
			{browser: "Vivaldi", kind: "chrome", detectDir: filepath.Join(appSupport, "Vivaldi"), dir: filepath.Join(appSupport, "Vivaldi", "NativeMessagingHosts")},
			{browser: "Chromium", kind: "chrome", detectDir: filepath.Join(appSupport, "Chromium"), dir: filepath.Join(appSupport, "Chromium", "NativeMessagingHosts")},
			{browser: "Firefox", kind: "firefox", detectDir: filepath.Join(appSupport, "Firefox"), dir: filepath.Join(appSupport, "Mozilla", "NativeMessagingHosts")},
			{browser: "LibreWolf", kind: "firefox", detectDir: filepath.Join(appSupport, "LibreWolf"), dir: filepath.Join(appSupport, "LibreWolf", "NativeMessagingHosts")},
		}
	case "linux":
		cfg := filepath.Join(home, ".config")
		return []nativeManifestTarget{
			{browser: "Chrome", kind: "chrome", detectDir: filepath.Join(cfg, "google-chrome"), dir: filepath.Join(cfg, "google-chrome", "NativeMessagingHosts")},
			{browser: "Brave", kind: "chrome", detectDir: filepath.Join(cfg, "BraveSoftware", "Brave-Browser"), dir: filepath.Join(cfg, "BraveSoftware", "Brave-Browser", "NativeMessagingHosts")},
			{browser: "Edge", kind: "chrome", detectDir: filepath.Join(cfg, "microsoft-edge"), dir: filepath.Join(cfg, "microsoft-edge", "NativeMessagingHosts")},
			{browser: "Chromium", kind: "chrome", detectDir: filepath.Join(cfg, "chromium"), dir: filepath.Join(cfg, "chromium", "NativeMessagingHosts")},
			{browser: "Vivaldi", kind: "chrome", detectDir: filepath.Join(cfg, "vivaldi"), dir: filepath.Join(cfg, "vivaldi", "NativeMessagingHosts")},
			{browser: "Firefox", kind: "firefox", detectDir: filepath.Join(home, ".mozilla"), dir: filepath.Join(home, ".mozilla", "native-messaging-hosts")},
			{browser: "LibreWolf", kind: "firefox", detectDir: filepath.Join(home, ".librewolf"), dir: filepath.Join(home, ".librewolf", "native-messaging-hosts")},
		}
	default:
		return nil
	}
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// installNativeHostBinary links <configBase>/bin/hogman-native-host to the
// canonical hogman binary in the same directory so the native host stays in
// sync automatically without duplicating ~25 MiB on disk.
func installNativeHostBinary(canonicalBin, hostPath string) error {
	if fsutil.SameFilePath(canonicalBin, hostPath) {
		// Already pointing at canonicalBin (check it is actually a symlink, not an old copy).
		if fi, err := os.Lstat(hostPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
	}
	target := filepath.Base(canonicalBin)
	if filepath.Dir(canonicalBin) != filepath.Dir(hostPath) {
		target = canonicalBin
	}
	tmp := hostPath + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, hostPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
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
	var errs []error
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
		// Only register for browsers that are already present on this machine.
		if t.detectDir != "" && !dirExists(t.detectDir) && !dirExists(t.dir) {
			continue
		}
		if err := os.MkdirAll(t.dir, 0o755); err != nil {
			note("could not register %s browser manifest (%v)", t.browser, err)
			errs = append(errs, fmt.Errorf("create %s: %w", t.dir, err))
			continue
		}
		dst := filepath.Join(t.dir, nativeHostName+".json")
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			note("could not register %s browser manifest (%v)", t.browser, err)
			errs = append(errs, fmt.Errorf("write %s: %w", dst, err))
			continue
		}
		written++
	}
	if len(errs) > 0 && written == 0 {
		return 0, errs[0]
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
