package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScanInstalledPensValidCorruptAndIgnoredDirs(t *testing.T) {
	base := t.TempDir()

	// Valid pens (written out of lexical order to verify deterministic sort).
	for _, z := range []string{"zebra.pens.example.com", "alpha.pens.example.com"} {
		d := filepath.Join(base, z)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := (&agentConfig{
			Zone:        z,
			LoginServer: "https://" + z,
			ProxyAddr:   "127.0.0.1:18000",
		}).save(d); err != nil {
			t.Fatal(err)
		}
	}

	// Ignored directories: bin, shares, hidden dotdir, empty non-pen dir.
	for _, ignored := range []string{"bin", "shares", ".staging", "empty-dir"} {
		if err := os.MkdirAll(filepath.Join(base, ignored), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Even a stray config.json inside bin/ or dotfiles is ignored.
	_ = os.WriteFile(filepath.Join(base, "bin", "config.json"), []byte("{}"), 0o600)
	_ = os.WriteFile(filepath.Join(base, ".staging", "config.json"), []byte("{}"), 0o600)

	// Corrupt JSON pen dir.
	corruptDir := filepath.Join(base, "broken.pens.example.com")
	_ = os.MkdirAll(corruptDir, 0o700)
	_ = os.WriteFile(filepath.Join(corruptDir, "config.json"), []byte("{bad"), 0o600)

	// Mismatched zone vs directory basename.
	mismatchDir := filepath.Join(base, "claimed.pens.example.com")
	_ = os.MkdirAll(mismatchDir, 0o700)
	_ = (&agentConfig{Zone: "evil.pens.example.com", ProxyAddr: "127.0.0.1:18001"}).save(mismatchDir)

	// Invalid zone characters.
	invalidDir := filepath.Join(base, "BAD_ZONE")
	_ = os.MkdirAll(invalidDir, 0o700)
	_ = (&agentConfig{Zone: "BAD_ZONE", ProxyAddr: "127.0.0.1:18002"}).save(invalidDir)

	res := scanInstalledPens(base)
	var gotZones []string
	for _, p := range res.Pens {
		gotZones = append(gotZones, p.Zone)
	}
	wantZones := []string{"alpha.pens.example.com", "zebra.pens.example.com"}
	if !reflect.DeepEqual(gotZones, wantZones) {
		t.Fatalf("valid zones = %v, want %v", gotZones, wantZones)
	}
	wantCorrupt := []string{"BAD_ZONE", "broken.pens.example.com", "claimed.pens.example.com"}
	if !reflect.DeepEqual(res.Corrupt, wantCorrupt) {
		t.Fatalf("corrupt = %v, want %v", res.Corrupt, wantCorrupt)
	}

	// Non-existent configBase returns empty without error.
	empty := scanInstalledPens(filepath.Join(base, "does-not-exist"))
	if len(empty.Pens) != 0 || len(empty.Corrupt) != 0 {
		t.Fatalf("missing base scan = %+v, want empty", empty)
	}
}
