package state

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestScanInstalledPensValidCorruptAndIgnoredDirs(t *testing.T) {
	t.Parallel()
	base := t.TempDir()

	for _, z := range []string{"zebra.pens.example.com", "alpha.pens.example.com"} {
		d := filepath.Join(base, z)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := (&AgentConfig{
			Zone:        z,
			LoginServer: "https://" + z,
			ProxyAddr:   "127.0.0.1:18000",
		}).Save(d); err != nil {
			t.Fatal(err)
		}
	}

	for _, ignored := range []string{"bin", "shares", ".staging", "empty-dir"} {
		if err := os.MkdirAll(filepath.Join(base, ignored), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(base, "bin", "config.json"), []byte("{}"), 0o600)
	_ = os.WriteFile(filepath.Join(base, ".staging", "config.json"), []byte("{}"), 0o600)

	corruptDir := filepath.Join(base, "broken.pens.example.com")
	_ = os.MkdirAll(corruptDir, 0o700)
	_ = os.WriteFile(filepath.Join(corruptDir, "config.json"), []byte("{bad"), 0o600)

	mismatchDir := filepath.Join(base, "claimed.pens.example.com")
	_ = os.MkdirAll(mismatchDir, 0o700)
	_ = (&AgentConfig{Zone: "evil.pens.example.com", ProxyAddr: "127.0.0.1:18001"}).Save(mismatchDir)

	invalidDir := filepath.Join(base, "BAD_ZONE")
	_ = os.MkdirAll(invalidDir, 0o700)
	_ = (&AgentConfig{Zone: "BAD_ZONE", ProxyAddr: "127.0.0.1:18002"}).Save(invalidDir)

	res := ScanInstalledPens(base)
	var gotZones []string
	for _, p := range res.Pens {
		gotZones = append(gotZones, p.Zone)
	}
	wantZones := []string{"alpha.pens.example.com", "zebra.pens.example.com"}
	if !reflect.DeepEqual(gotZones, wantZones) {
		t.Fatalf("valid zones = %v, want %v", gotZones, wantZones)
	}
	wantCorrupt := []string{"BAD_ZONE", "broken.pens.example.com", "claimed.pens.example.com"}
	if !reflect.DeepEqual(res.Corrupt, wantCorrupt) {
		t.Fatalf("corrupt = %v, want %v", res.Corrupt, wantCorrupt)
	}

	empty := ScanInstalledPens(filepath.Join(base, "does-not-exist"))
	if len(empty.Pens) != 0 || len(empty.Corrupt) != 0 {
		t.Fatalf("missing base scan = %+v, want empty", empty)
	}
}

func TestPACPortTokensAndMarkers(t *testing.T) {
	t.Parallel()
	if port, ok := ParseStrictHogmanPort("127.0.0.1:17000"); !ok || port != 17000 {
		t.Fatalf("17000 = (%d, %v)", port, ok)
	}
	for _, bad := range []string{"127.0.0.1:017000", "127.0.0.1:16999", "127.0.0.1:27000", "localhost:18000", "[::1]:18000"} {
		if _, ok := ParseStrictHogmanPort(bad); ok {
			t.Errorf("ParseStrictHogmanPort(%q) accepted", bad)
		}
	}

	pac := RenderPAC([]*AgentConfig{
		{Zone: "short.example.com", ProxyAddr: "127.0.0.1:18000"},
		{Zone: "sub.short.example.com", ProxyAddr: "127.0.0.1:18001"},
	})
	if !strings.HasPrefix(pac, PACMarker) {
		t.Fatalf("PAC missing marker: %q", pac)
	}
	if strings.Index(pac, "sub.short.example.com") > strings.Index(pac, `"short.example.com"`) {
		t.Fatalf("longest zone must come first in PAC:\n%s", pac)
	}

	dir := t.TempDir()
	tok, err := WriteStatusToken(dir)
	if err != nil || len(tok) != 32 {
		t.Fatalf("WriteStatusToken = (%q, %v)", tok, err)
	}
	p1 := ComputeStatusProof(tok, "nonce1", "bobo.pens.example.com")
	p2 := ComputeStatusProof(tok, "nonce1", "other.pens.example.com")
	if p1 == "" || p1 == p2 {
		t.Fatalf("ComputeStatusProof zone binding failed: %q vs %q", p1, p2)
	}

	WriteUpdatingMarker(dir, true)
	if present, svc := ReadUpdatingMarker(dir); !present || !svc {
		t.Fatalf("ReadUpdatingMarker = (%v, %v), want (true, true)", present, svc)
	}
	ClearUpdatingMarker(dir)
	if present, _ := ReadUpdatingMarker(dir); present {
		t.Fatal("ClearUpdatingMarker did not remove marker")
	}
}
