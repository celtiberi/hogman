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
