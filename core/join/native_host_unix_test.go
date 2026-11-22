//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteUnixNativeManifestsOnlyForInstalledBrowsers(t *testing.T) {
	home := t.TempDir()
	// Pretend only Chrome and Firefox are installed on macOS.
	if err := os.MkdirAll(filepath.Join(home, "Library", "Application Support", "Google", "Chrome"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "Library", "Application Support", "Firefox"), 0o755); err != nil {
		t.Fatal(err)
	}

	n, err := writeUnixNativeManifests(
		"darwin",
		home,
		"/opt/hogman/bin/hogman-native-host",
		[]string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		[]string{"hogman-browser@hogman.network"},
	)
	if err != nil {
		t.Fatalf("writeUnixNativeManifests: %v", err)
	}
	if n != 2 {
		t.Fatalf("wrote %d manifests, want 2 (Chrome + Firefox only)", n)
	}
	chromeManifest := filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts", nativeHostName+".json")
	if _, err := os.Stat(chromeManifest); err != nil {
		t.Fatalf("expected Chrome manifest at %s: %v", chromeManifest, err)
	}
	ffManifest := filepath.Join(home, "Library", "Application Support", "Mozilla", "NativeMessagingHosts", nativeHostName+".json")
	if _, err := os.Stat(ffManifest); err != nil {
		t.Fatalf("expected Firefox manifest at %s: %v", ffManifest, err)
	}
	// Uninstalled browsers must not have directories created.
	vivaldiDir := filepath.Join(home, "Library", "Application Support", "Vivaldi")
	if _, err := os.Stat(vivaldiDir); !os.IsNotExist(err) {
		t.Fatalf("expected uninstalled browser dir %s not to be created", vivaldiDir)
	}
}
