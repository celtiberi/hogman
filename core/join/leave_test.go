package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLeaveKey(t *testing.T) {
	for in, want := range map[string]string{
		"https://qa.gate.example.network/join":         "qa.gate.example.network",
		"https://qa.gate.example.network/join#k=abc":   "qa.gate.example.network",
		"https://QA.gate.example.network:443/join?x=1": "qa.gate.example.network",
		"qa.pens.example.network":                      "qa.pens.example.network",
		"  QA.Pens.Example.Network. ":                  "qa.pens.example.network",
		"qa.gate.example.network/join#k=abc":           "qa.gate.example.network",
		"":                                             "",
	} {
		if got := leaveKey(in); got != want {
			t.Errorf("leaveKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchLeaveTargets(t *testing.T) {
	local := []leaveTarget{
		{zone: "a.pens.example.network", host: "a.gate.example.network"},
		{zone: "b.pens.example.network", host: "b.gate.example.network"},
	}
	for key, want := range map[string]string{
		"a.pens.example.network": "a.pens.example.network",
		"b.gate.example.network": "b.pens.example.network",
	} {
		got := matchLeaveTargets(local, key)
		if len(got) != 1 || got[0].zone != want {
			t.Errorf("match %q = %+v, want %s", key, got, want)
		}
	}
	if got := matchLeaveTargets(local, "c.pens.example.network"); len(got) != 0 {
		t.Errorf("unknown pen matched: %+v", got)
	}
}

// localLeaveTargets must find joined pens and share-only pens from saved
// settings alone, so leaving works when a pen's server is gone.
func TestLocalLeaveTargetsFromDisk(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if runtime.GOOS == "windows" {
		t.Setenv("AppData", filepath.Join(home, "AppData"))
	}
	write := func(path string, v any) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(v)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(stateDir("a.pens.example.network"), "config.json"),
		agentConfig{Zone: "a.pens.example.network", LoginServer: "https://a.gate.example.network"})
	write(filepath.Join(shareDir("a.pens.example.network", "blog"), "share.json"),
		shareConfig{Name: "blog", Zone: "a.pens.example.network", LoginServer: "https://a.gate.example.network"})
	write(filepath.Join(shareDir("s.pens.example.network", "cooler"), "share.json"),
		shareConfig{Name: "cooler", Zone: "s.pens.example.network", LoginServer: "https://s.gate.example.network"})

	got := localLeaveTargets()
	if len(got) != 2 {
		t.Fatalf("got %d targets, want 2: %+v", len(got), got)
	}
	if got[0].zone != "a.pens.example.network" || got[0].host != "a.gate.example.network" || got[0].cfg == nil {
		t.Errorf("joined pen = %+v", got[0])
	}
	if got[1].zone != "s.pens.example.network" || got[1].host != "s.gate.example.network" || got[1].cfg != nil {
		t.Errorf("share-only pen = %+v", got[1])
	}
	if m := matchLeaveTargets(got, leaveKey("https://s.gate.example.network/join")); len(m) != 1 {
		t.Errorf("a keyless link should match the share-only pen: %+v", m)
	}
}
