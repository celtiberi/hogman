package link

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()
	l, err := Parse("https://bobo.gate.example.com/join#t=hmi_abc")
	if err != nil {
		t.Fatal(err)
	}
	if l.Host != "bobo.gate.example.com" || l.InviteToken != "hmi_abc" || l.DeviceKey != "" || l.ForShare {
		t.Fatalf("invite: %+v", l)
	}

	l, err = Parse("  'https://bobo.gate.example.com/join#k=hskey-123&for=share'  ")
	if err != nil {
		t.Fatal(err)
	}
	if l.DeviceKey != "hskey-123" || !l.ForShare {
		t.Fatalf("share device: %+v", l)
	}

	for _, bad := range []string{
		"http://bobo.gate.example.com/join#t=hmi_abc",
		"https://user:pass@bobo.gate.example.com/join#t=hmi_abc",
		"https://bobo.gate.example.com/other#t=hmi_abc",
		"https://bobo.gate.example.com/join#t=hmi_abc&fp=deadbeef",
		"https://bobo.gate.example.com/join",
		"https://bobo.gate.example.com/join#t=hmi_abc&k=hskey-123",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", bad)
		}
	}
}

func TestValidatePublicZoneAndQueries(t *testing.T) {
	t.Parallel()
	if err := ValidatePublicZone("bobo.gate.hogman.network", "bobo.pens.hogman.network"); err != nil {
		t.Fatalf("valid hosted zone rejected: %v", err)
	}
	if err := ValidatePublicZone("bobo.gate.hogman.network", "other.pens.hogman.network"); err == nil {
		t.Fatal("mismatched hosted zone accepted")
	}
	if err := ValidatePublicZone("gate.example.com", "pen.example.com"); err != nil {
		t.Fatalf("valid self-hosted zone rejected: %v", err)
	}
	if err := ValidatePublicZone("gate.example.com", "evil.other.com"); err == nil {
		t.Fatal("cross-domain self-hosted zone accepted")
	}
	if err := ValidatePublicZone("gate.example.com", "bobo.hogman"); err == nil {
		t.Fatal("legacy .hogman zone accepted")
	}
	if got, err := SanitizeHostname("My MacBook Pro.local"); err != nil || got != "my-macbook-pro" {
		t.Fatalf("SanitizeHostname = (%q, %v)", got, err)
	}
	if got, err := SanitizeHostname("!!!"); err != nil || got != "" {
		t.Fatalf("SanitizeHostname(!!!) = (%q, %v)", got, err)
	}
	if got, err := SanitizeHostname(strings.Repeat("a", 63)); err != nil || len(got) != 63 {
		t.Fatalf("SanitizeHostname(63) = (%q, %v)", got, err)
	}
	if got, err := SanitizeHostname(strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "--hostname") {
		t.Fatalf("SanitizeHostname(64) = (%q, %v), want error mentioning --hostname", got, err)
	}
	if !PenMatchesQuery("bobo.pens.example.com", "https://bobo.gate.example.com", "bobo") {
		t.Fatal("short label query did not match")
	}
	if PenMatchesQuery("bobo.pens.example.com", "https://bobo.gate.example.com", "bob") {
		t.Fatal("partial prefix falsely matched")
	}
	if q, err := ValidatePenQuery("  BOBO.Pens.Example.COM. "); err != nil || q != "bobo.pens.example.com" {
		t.Fatalf("ValidatePenQuery = (%q, %v)", q, err)
	}
	if _, err := ValidatePenQuery("../etc"); err == nil || !strings.Contains(err.Error(), "invalid pen name") {
		t.Fatalf("ValidatePenQuery(../etc) = %v", err)
	}
}

func TestValidatePublicZoneMatrix(t *testing.T) {
	t.Parallel()
	hostedOK := []struct {
		host string
		zone string
	}{
		{"bobo.gate.example.com", "bobo.pens.example.com"},
		{"bobo.gate.example.com:8443", "bobo.pens.example.com"},
		{"bobo.gate.hogman.test", "bobo.pens.hogman.test"},
		{"hs.example.com", "bobo.example.com"},
		{"gate.hogman.test", "bobo.pens.hogman.test"},
		{"login.corp.example.co.uk", "bobo.example.co.uk"},
	}
	for _, tc := range hostedOK {
		if err := ValidatePublicZone(tc.host, tc.zone); err != nil {
			t.Errorf("ValidatePublicZone(%q, %q) unexpected error: %v", tc.host, tc.zone, err)
		}
	}

	hostedBad := []struct {
		host string
		zone string
	}{
		{"bobo.gate.example.com", "alice.pens.example.com"},
		{"bobo.gate.example.com", "bobo.other.example.com"},
		{"bobo.gate.example.com", "bobo.example.com"},
		{"bobo.gate.example.com", "example.com"},
		{"bobo.gate.example.com", "bobo.hogman"},
		{"evil.gate.co.uk", "evil.pens.co.uk"},
		{"hs.example.com", "example.com"},
		{"hs.example.com", "bobo.other.com"},
		{"hs.example.com", "bobo.hogman"},
		{"hs.example.com", "Bobo.example.com"},
		{"hs.example.com", "bobo.example.com."},
		{"127.0.0.1:8443", "bobo.example.com"},
	}
	for _, tc := range hostedBad {
		if err := ValidatePublicZone(tc.host, tc.zone); err == nil {
			t.Errorf("ValidatePublicZone(%q, %q) expected error, got nil", tc.host, tc.zone)
		}
	}
}

func TestSingleLinePreservesAllLinesAndSanitizes(t *testing.T) {
	t.Parallel()
	threeLine := "Bootstrap failed: 5: Input/output error\nTry re-running the command\r\nfor richer \x1b[31m\u009b\u202Eerrors."
	got := SingleLine(threeLine)
	want := "Bootstrap failed: 5: Input/output error; Try re-running the command; for richer ?[31m??errors."
	if got != want {
		t.Fatalf("SingleLine = %q, want %q", got, want)
	}
	if got := SingleLine("\n  \r\n"); got != "" {
		t.Fatalf("SingleLine(whitespace) = %q, want empty", got)
	}
}
