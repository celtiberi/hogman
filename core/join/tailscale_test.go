package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTailscalePrivilegeErrorsNeverEscalateOrLeakAuthKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub test runs on unix")
	}
	if isRoot() {
		t.Skip("running as root")
	}

	dir := t.TempDir()
	stub := filepath.Join(dir, "tailscale")
	// Simulate Tailscale rejecting an unprivileged call (and echoing an error line
	// containing the secret to confirm redaction without printing a login command).
	script := "#!/bin/sh\necho \"Access denied: check operator permissions (got key tskey-auth-supersecret-12345)\" >&2\nexit 1\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	ts := &Tailscale{bin: stub}
	const secretKey = "tskey-auth-supersecret-12345"

	err := ts.Login("https://hs.example.com", secretKey, "laptop")
	if err == nil {
		t.Fatal("expected Login privilege error")
	}
	msg := err.Error()
	if strings.Contains(msg, secretKey) {
		t.Fatalf("Login error leaked auth key: %s", msg)
	}
	if strings.Contains(msg, "--authkey") {
		t.Fatalf("Login error must not print a login command with --authkey: %s", msg)
	}
	if !strings.Contains(msg, "sudo "+stub+" set --operator=$USER") {
		t.Fatalf("Login error missing operator hint: %s", msg)
	}

	err = ts.Logout()
	if err == nil || !strings.Contains(err.Error(), "sudo "+stub+" logout") {
		t.Fatalf("Logout error = %v, want manual sudo logout hint", err)
	}

	err = ts.Down()
	if err == nil || !strings.Contains(err.Error(), "sudo "+stub+" down") {
		t.Fatalf("Down error = %v, want manual sudo down hint", err)
	}
}
