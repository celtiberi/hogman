package main

import (
	"testing"

	"tailscale.com/envknob"
)

func TestNoLogUploadToTailscale(t *testing.T) {
	if !envknob.NoLogsNoSupport() {
		t.Fatal("tsnet log upload to log.tailscale.com must be disabled (envknob.SetNoLogsNoSupport)")
	}
}
