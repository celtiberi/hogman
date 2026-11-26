package main

import (
	"testing"

	"tailscale.com/feature/buildfeatures"
)

func TestPeerAPIServerDisabled(t *testing.T) {
	if buildfeatures.HasPeerAPIServer {
		t.Fatal("HasPeerAPIServer must be false (build with -tags ts_omit_peerapiserver)")
	}
}
