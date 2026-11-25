package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"tailscale.com/feature/buildfeatures"
)

func TestPeerAPIServerDisabled(t *testing.T) {
	if buildfeatures.HasPeerAPIServer {
		t.Fatal("HasPeerAPIServer must be false (build with -tags ts_omit_peerapiserver)")
	}
}

func TestLeftoverHogmanBinariesListsHomeCopies(t *testing.T) {
	home := t.TempDir()
	other := t.TempDir()
	self := filepath.Join(other, cliBinaryName())
	homeCopy := filepath.Join(home, cliBinaryName())
	legacyCopy := filepath.Join(home, legacyBinaryName(runtime.GOOS))
	for _, p := range []string{self, homeCopy, legacyCopy} {
		if err := os.WriteFile(p, []byte("bin"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got := leftoverHogmanBinaries(self, home)
	if len(got) != 3 {
		t.Fatalf("leftoverHogmanBinaries = %v, want 3 distinct binaries", got)
	}
	// When self IS ~/hogman, don't duplicate it.
	gotSame := leftoverHogmanBinaries(homeCopy, home)
	if len(gotSame) != 2 {
		t.Fatalf("leftoverHogmanBinaries(same) = %v, want 2 distinct binaries", gotSame)
	}
}
