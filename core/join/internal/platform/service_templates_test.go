package platform

import (
	"strings"
	"testing"

	"hogman/join/internal/state"
)

func TestSystemdQuoteAndSingleLine(t *testing.T) {
	t.Parallel()
	quoted := systemdQuote("/tmp/foo%h/$HOME/bar\nExecStart=/evil\r")
	if strings.ContainsAny(quoted, "\r\n") {
		t.Fatalf("systemdQuote left newline: %q", quoted)
	}
	if !strings.Contains(quoted, "%%h") {
		t.Fatalf("systemdQuote did not escape %%: %q", quoted)
	}
	if !strings.Contains(quoted, "$$HOME") {
		t.Fatalf("systemdQuote did not escape $: %q", quoted)
	}

	line := systemdSingleLine("line1\nExecStart=/bin/evil\rline2")
	if strings.ContainsAny(line, "\r\n") {
		t.Fatalf("systemdSingleLine retained newline: %q", line)
	}
}

func TestRenderWindowsRunCommand(t *testing.T) {
	t.Parallel()
	if got := WindowsRunValueName("acme.pens.example.com"); got != "Hogman.acme.pens.example.com" {
		t.Fatalf("WindowsRunValueName = %q", got)
	}
	sc := &state.ShareConfig{Name: "blog", Zone: "acme.pens.example.com"}
	if got := WindowsShareRunValueName(sc); got != "Hogman.share.blog.acme.pens.example.com" {
		t.Fatalf("WindowsShareRunValueName = %q", got)
	}

	got, err := RenderWindowsRunCommand(
		`C:\Users\Jane Doe\AppData\Roaming\hogman\bin\hogman.exe`,
		"agent",
		`C:\Users\Jane Doe\AppData\Roaming\hogman\pens\acme.pens.example.com`,
	)
	if err != nil {
		t.Fatalf("RenderWindowsRunCommand(agent): %v", err)
	}
	want := `"C:\Users\Jane Doe\AppData\Roaming\hogman\bin\hogman.exe" __start-detached agent "C:\Users\Jane Doe\AppData\Roaming\hogman\pens\acme.pens.example.com"`
	if got != want {
		t.Fatalf("RenderWindowsRunCommand(agent) = %q, want %q", got, want)
	}

	// Trailing backslash before closing quote must be doubled for CommandLineToArgvW.
	gotTrail, err := RenderWindowsRunCommand(`C:\hogman\hogman.exe`, "share", `C:\shares\blog\`)
	if err != nil {
		t.Fatalf("RenderWindowsRunCommand(trailing backslash): %v", err)
	}
	wantTrail := `"C:\hogman\hogman.exe" __start-detached share "C:\shares\blog\\"`
	if gotTrail != wantTrail {
		t.Fatalf("RenderWindowsRunCommand(trailing backslash) = %q, want %q", gotTrail, wantTrail)
	}

	for _, bad := range []struct {
		bin, kind, dir string
	}{
		{`C:\hogman.exe`, "evil", `C:\dir`},
		{`C:\hogman.exe`, "", `C:\dir`},
		{"", "agent", `C:\dir`},
		{`C:\hogman.exe`, "agent", ""},
		{`C:\hogman"evil.exe`, "agent", `C:\dir`},
		{`C:\hogman.exe`, "agent", "C:\\dir\ncalc.exe"},
		{`C:\hogman.exe`, "agent", "C:\\dir\rcalc.exe"},
		{`C:\hogman.exe`, "agent", "C:\\dir\x00evil"},
	} {
		if cmd, err := RenderWindowsRunCommand(bad.bin, bad.kind, bad.dir); err == nil {
			t.Errorf("RenderWindowsRunCommand(%q, %q, %q) unexpectedly succeeded: %q", bad.bin, bad.kind, bad.dir, cmd)
		}
	}
}
