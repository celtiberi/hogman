package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hogman/join/internal/state"
)

func TestAgentRunningStaleBinaryAndMigrateRestartsStaleAgent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)

	const wantHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const oldHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	makeAgent := func(zone, reportedHex string) penTarget {
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
			_ = json.NewEncoder(w).Encode(agentStatus{
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
		return penTarget{zone: zone, dir: dir, cfg: cfg}
	}

	pCurrent := makeAgent("current.pens.example.test", wantHex)
	pStale := makeAgent("stale.pens.example.test", oldHex)
	pPreI20 := makeAgent("legacy-agent.pens.example.test", "")

	if agentRunningStaleBinary(&pCurrent, wantHex) {
		t.Fatal("agent matching wantHex should not be marked stale")
	}
	if !agentRunningStaleBinary(&pStale, wantHex) {
		t.Fatal("agent reporting older bin_sha256 should be marked stale")
	}
	if !agentRunningStaleBinary(&pPreI20, wantHex) {
		t.Fatal("older agent omitting bin_sha256 should be marked stale")
	}

	// Verify migratePensForUpdate restarts stale pens even when forceAll=false,
	// no legacy copy exists, and an earlier deleted pen returns HTTP 404.
	deadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer deadSrv.Close()
	pDead := penTarget{
		zone: "aaa-deleted.pens.example.test",
		dir:  filepath.Join(home, "aaa-deleted"),
		cfg:  &state.AgentConfig{Zone: "aaa-deleted.pens.example.test", LoginServer: deadSrv.URL},
	}

	var restarted []string
	var startedNoWait []string
	ops := penUpdateOps{
		isRunning: func(string, *state.AgentConfig) bool { return true },
		runningStale: func(p *penTarget) bool {
			return p.zone == pDead.zone || agentRunningStaleBinary(p, wantHex)
		},
		hasService: func(string) bool { return false },
		probeReachable: func(p *penTarget, _ options) error {
			if p.zone == pDead.zone {
				return errorf("pen server returned HTTP 404")
			}
			return nil
		},
		stop: func(string, *state.AgentConfig) {},
		startNoWait: func(p *penTarget, _ string, _ bool, _ options) error {
			startedNoWait = append(startedNoWait, p.zone)
			return nil
		},
		restartNew: func(p *penTarget, _ string, _ bool, _ options) error {
			restarted = append(restarted, p.zone)
			return nil
		},
	}
	results := migratePensForUpdate(
		[]penTarget{pDead, pCurrent, pStale, pPreI20},
		"/tmp/canon/hogman",
		"/tmp/self",
		func(string) string { return "" },
		false, // on-disk binaries are ALREADY up to date!
		options{},
		ops,
	)
	if len(results) != 3 {
		t.Fatalf("expected 3 migrated pens (dead, stale, pre-I20; current skipped), got %+v", results)
	}
	if results[0].Zone != pDead.zone || results[0].Err == nil {
		t.Fatalf("expected dead 404 pen to record error, got %+v", results[0])
	}
	if len(startedNoWait) != 1 || startedNoWait[0] != pDead.zone {
		t.Fatalf("startedNoWait = %v, want [%s]", startedNoWait, pDead.zone)
	}
	if strings.Join(restarted, ",") != pStale.zone+","+pPreI20.zone {
		t.Fatalf("restarted = %v, want [%s, %s]", restarted, pStale.zone, pPreI20.zone)
	}
}
