package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hogman/join/internal/agent"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
	"hogman/join/internal/updater"
)

func TestAgentRunningStaleBinaryAndMigrateRestartsStaleAgent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)

	const wantHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const oldHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	makeAgent := func(zone, reportedHex string) updater.PenTarget {
		dir := state.StateDir(zone)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		tok, err := state.WriteStatusToken(dir)
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if nonce := strings.TrimSpace(r.Header.Get("X-Hogman-Challenge")); nonce != "" {
				w.Header().Set("X-Hogman-Proof", state.ComputeStatusProof(tok, nonce, zone))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(agent.Status{
				Zone:      zone,
				Up:        true,
				BinSHA256: reportedHex,
			})
		}))
		t.Cleanup(srv.Close)
		cfg := &state.AgentConfig{
			Zone:        zone,
			LoginServer: "https://gate.example.test",
			ProxyAddr:   strings.TrimPrefix(srv.URL, "http://"),
		}
		return updater.PenTarget{Zone: zone, Dir: dir, Cfg: cfg}
	}

	pCurrent := makeAgent("current.pens.example.test", wantHex)
	pStale := makeAgent("stale.pens.example.test", oldHex)
	pPreI20 := makeAgent("legacy-agent.pens.example.test", "")

	if updater.AgentRunningStaleBinary(&pCurrent, wantHex) {
		t.Fatal("agent matching wantHex should not be marked stale")
	}
	if !updater.AgentRunningStaleBinary(&pStale, wantHex) {
		t.Fatal("agent reporting older bin_sha256 should be marked stale")
	}
	if !updater.AgentRunningStaleBinary(&pPreI20, wantHex) {
		t.Fatal("older agent omitting bin_sha256 should be marked stale")
	}

	// Verify MigratePens restarts stale pens even when forceAll=false,
	// no legacy copy exists, and an earlier deleted pen returns HTTP 404.
	deadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer deadSrv.Close()
	pDead := updater.PenTarget{
		Zone: "aaa-deleted.pens.example.test",
		Dir:  filepath.Join(home, "aaa-deleted"),
		Cfg:  &state.AgentConfig{Zone: "aaa-deleted.pens.example.test", LoginServer: deadSrv.URL},
	}

	var restarted []string
	var startedNoWait []string
	ops := updater.PenOps{
		IsRunning: func(string, *state.AgentConfig) bool { return true },
		RunningStale: func(p *updater.PenTarget) bool {
			return p.Zone == pDead.Zone || updater.AgentRunningStaleBinary(p, wantHex)
		},
		HasService: func(string) bool { return false },
		ProbeReachable: func(p *updater.PenTarget, _ updater.Options) error {
			if p.Zone == pDead.Zone {
				return errorf("pen server returned HTTP 404")
			}
			return nil
		},
		Stop: func(string, *state.AgentConfig) {},
		StartNoWait: func(p *updater.PenTarget, _ string, _ bool, _ updater.Options) error {
			startedNoWait = append(startedNoWait, p.Zone)
			return nil
		},
		RestartNew: func(p *updater.PenTarget, _ string, _ bool, _ updater.Options) error {
			restarted = append(restarted, p.Zone)
			return nil
		},
	}
	results := updater.MigratePens(
		[]updater.PenTarget{pDead, pCurrent, pStale, pPreI20},
		"/tmp/canon/hogman",
		"/tmp/self",
		func(string) string { return "" },
		false, // on-disk binaries are ALREADY up to date!
		updater.Options{},
		ops,
		ui.Default(),
	)
	if len(results) != 3 {
		t.Fatalf("expected 3 migrated pens (dead, stale, pre-I20; current skipped), got %+v", results)
	}
	if results[0].Zone != pDead.Zone || results[0].Err == nil {
		t.Fatalf("expected dead 404 pen to record error, got %+v", results[0])
	}
	if len(startedNoWait) != 1 || startedNoWait[0] != pDead.Zone {
		t.Fatalf("startedNoWait = %v, want [%s]", startedNoWait, pDead.Zone)
	}
	if strings.Join(restarted, ",") != pStale.Zone+","+pPreI20.Zone {
		t.Fatalf("restarted = %v, want [%s, %s]", restarted, pStale.Zone, pPreI20.Zone)
	}
}
