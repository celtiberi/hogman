package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestAskPreservesBufferedInput(t *testing.T) {
	t.Parallel()
	var errOut bytes.Buffer
	u := &UI{
		In:  strings.NewReader("alice\nbob\n"),
		Err: &errOut,
	}
	if got := u.Ask("first: "); got != "alice" {
		t.Fatalf("first Ask = %q, want alice", got)
	}
	if got := u.Ask("second: "); got != "bob" {
		t.Fatalf("second Ask = %q, want bob", got)
	}
}

func TestReadJoinLinkStdinAndOversizeRejection(t *testing.T) {
	t.Parallel()
	u := &UI{IsTerminalFn: func() bool { return false }}

	got, err := u.ReadJoinLink(true, strings.NewReader("  https://bobo.gate.example.com/join#k=xyz\n"))
	if err != nil || got != "https://bobo.gate.example.com/join#k=xyz" {
		t.Fatalf("ReadJoinLink(stdin) = (%q, %v)", got, err)
	}

	if _, err := u.ReadJoinLink(true, strings.NewReader("   \n")); err == nil {
		t.Fatal("expected error for empty stdin")
	}

	oversize := strings.Repeat("a", MaxStdinLinkBytes+1)
	if _, err := u.ReadJoinLink(true, strings.NewReader(oversize)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize stdin err = %v, want size limit error (no silent truncation)", err)
	}

	if _, err := u.ReadJoinLink(false, nil); err == nil || !strings.Contains(err.Error(), "--link-stdin") {
		t.Fatalf("non-tty ReadJoinLink err = %v, want --link-stdin hint", err)
	}
}

func TestWriteJSONAndConfirm(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	u := &UI{
		In:  strings.NewReader("yes\nno\n"),
		Out: &out,
		Err: &errOut,
	}
	if !u.Confirm("Proceed?") {
		t.Fatal("expected yes to confirm")
	}
	if u.Confirm("Proceed again?") {
		t.Fatal("expected no to decline")
	}
	if err := u.WriteJSON(map[string]bool{"ok": true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"ok": true`) {
		t.Fatalf("unexpected JSON output: %q", out.String())
	}
}
