package platform

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestTailscalePrivilegeErrorsNeverEscalate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub test runs on unix")
	}
	if IsRoot() {
		t.Skip("running as root")
	}

	dir := t.TempDir()
	stub := filepath.Join(dir, "tailscale")
	script := "#!/bin/sh\necho \"Access denied: check operator permissions\" >&2\nexit 1\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	ts := NewTailscale(stub)

	err := ts.Logout()
	if err == nil || !strings.Contains(err.Error(), "sudo "+stub+" logout") {
		t.Fatalf("Logout error = %v, want manual sudo logout hint", err)
	}

	err = ts.Down()
	if err == nil || !strings.Contains(err.Error(), "sudo "+stub+" down") {
		t.Fatalf("Down error = %v, want manual sudo down hint", err)
	}
}

func TestRedactCommandArgsAndVerboseRun(t *testing.T) {
	const secret = "tskey-auth-supersecret-99999"

	gotEq := RedactCommandArgs([]string{"login", "--login-server=https://hs.example.com", "--authkey=" + secret, "--hostname=laptop"})
	wantEq := []string{"login", "--login-server=https://hs.example.com", "--authkey=[redacted]", "--hostname=laptop"}
	if !slices.Equal(gotEq, wantEq) {
		t.Fatalf("RedactCommandArgs(=) = %v, want %v", gotEq, wantEq)
	}

	gotSep := RedactCommandArgs([]string{"login", "--authkey", secret, "--hostname=laptop"})
	wantSep := []string{"login", "--authkey", "[redacted]", "--hostname=laptop"}
	if !slices.Equal(gotSep, wantSep) {
		t.Fatalf("RedactCommandArgs(sep) = %v, want %v", gotSep, wantSep)
	}

	if runtime.GOOS == "windows" {
		return
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStderr := os.Stderr
	origVerbose := Verbose()
	os.Stderr = w
	SetVerbose(true)
	_, _ = Run("/bin/echo", "--authkey="+secret)
	SetVerbose(origVerbose)
	os.Stderr = origStderr
	_ = w.Close()

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()

	logged := buf.String()
	if strings.Contains(logged, secret) {
		t.Fatalf("verbose Run() leaked auth key to stderr: %s", logged)
	}
	if !strings.Contains(logged, "--authkey=[redacted]") {
		t.Fatalf("verbose Run() missing redacted placeholder: %s", logged)
	}
}
