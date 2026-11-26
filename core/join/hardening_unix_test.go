//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRedTeamWriteUnixNativeManifestsContinuesOnSingleBrowserError(t *testing.T) {
	home := t.TempDir()
	// Simulate Chrome detectDir existing, with NativeMessagingHosts blocked by a regular file,
	// while Firefox detectDir is writable.
	targets := browserNativeManifestTargets(runtime.GOOS, home)
	var chromeT, firefoxT nativeManifestTarget
	for _, tgt := range targets {
		if tgt.browser == "Chrome" {
			chromeT = tgt
		}
		if tgt.browser == "Firefox" {
			firefoxT = tgt
		}
	}
	if chromeT.dir == "" || firefoxT.dir == "" {
		t.Skip("unexpected OS targets")
	}
	if err := os.MkdirAll(chromeT.detectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chromeT.dir, []byte("not-a-dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(firefoxT.detectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	n, err := writeUnixNativeManifests(runtime.GOOS, home, "/tmp/hogman-native-host", defaultChromeExtIDs, defaultFirefoxExtIDs)
	if err != nil || n != 1 {
		t.Fatalf("writeUnixNativeManifests = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := os.Stat(filepath.Join(firefoxT.dir, nativeHostName+".json")); err != nil {
		t.Fatalf("Firefox manifest was not written when Chrome failed: %v", err)
	}
}
