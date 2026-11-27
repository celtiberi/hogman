//go:build !windows

package nativehost

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteUnixManifestsOnlyForInstalledBrowsers(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "Library", "Application Support", "Google", "Chrome"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "Library", "Application Support", "Firefox"), 0o755); err != nil {
		t.Fatal(err)
	}

	n, err := WriteUnixManifests(
		"darwin",
		home,
		"/opt/hogman/bin/hogman-native-host",
		[]string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		[]string{"hogman-browser@hogman.network"},
		nil,
	)
	if err != nil {
		t.Fatalf("WriteUnixManifests: %v", err)
	}
	if n != 2 {
		t.Fatalf("wrote %d manifests, want 2 (Chrome + Firefox only)", n)
	}
	chromeManifest := filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts", HostName+".json")
	if _, err := os.Stat(chromeManifest); err != nil {
		t.Fatalf("expected Chrome manifest at %s: %v", chromeManifest, err)
	}
	ffManifest := filepath.Join(home, "Library", "Application Support", "Mozilla", "NativeMessagingHosts", HostName+".json")
	if _, err := os.Stat(ffManifest); err != nil {
		t.Fatalf("expected Firefox manifest at %s: %v", ffManifest, err)
	}
	vivaldiDir := filepath.Join(home, "Library", "Application Support", "Vivaldi")
	if _, err := os.Stat(vivaldiDir); !os.IsNotExist(err) {
		t.Fatalf("expected uninstalled browser dir %s not to be created", vivaldiDir)
	}
}

func TestWriteUnixManifestsContinuesOnSingleBrowserError(t *testing.T) {
	t.Parallel()
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
	n, err := WriteUnixManifests(runtime.GOOS, home, "/tmp/hogman-native-host", DefaultChromeExtIDs, DefaultFirefoxExtIDs, nil)
	if err != nil || n != 1 {
		t.Fatalf("WriteUnixManifests = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := os.Stat(filepath.Join(firefoxT.dir, HostName+".json")); err != nil {
		t.Fatalf("Firefox manifest was not written when Chrome failed: %v", err)
	}
}
