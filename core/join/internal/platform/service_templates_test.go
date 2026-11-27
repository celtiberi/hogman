package platform

import (
	"strings"
	"testing"
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
