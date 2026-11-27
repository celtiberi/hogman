package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hogman/join/internal/state"
)

func TestProbeAgentStatusMatrix(t *testing.T) {
	const zone = "bobo.pens.example.com"

	newServer := func(t *testing.T, handler http.HandlerFunc) (*state.AgentConfig, string) {
		t.Helper()
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		dir := t.TempDir()
		cfg := &state.AgentConfig{
			Zone:      zone,
			ProxyAddr: strings.TrimPrefix(srv.URL, "http://"),
		}
		return cfg, dir
	}

	t.Run("verified up", func(t *testing.T) {
		var tok string
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			nonce := r.Header.Get("X-Hogman-Challenge")
			w.Header().Set("X-Hogman-Proof", state.ComputeStatusProof(tok, nonce, zone))
			_ = json.NewEncoder(w).Encode(agentStatus{Zone: zone, Up: true, IPs: []string{"100.64.0.2"}})
		})
		var err error
		tok, err = state.WriteStatusToken(dir)
		if err != nil {
			t.Fatal(err)
		}
		res := probeAgentStatus(dir, cfg, time.Second)
		if res.state != agentEndpointUp || !res.verified || res.status == nil || !res.status.Up {
			t.Fatalf("got %+v, want verified up", res)
		}
	})

	t.Run("verified down with needsLogin", func(t *testing.T) {
		var tok string
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			nonce := r.Header.Get("X-Hogman-Challenge")
			w.Header().Set("X-Hogman-Proof", state.ComputeStatusProof(tok, nonce, zone))
			_ = json.NewEncoder(w).Encode(agentStatus{Zone: zone, Up: false, NeedsLogin: true, Error: "device removed"})
		})
		var err error
		tok, err = state.WriteStatusToken(dir)
		if err != nil {
			t.Fatal(err)
		}
		st, detail := verifyAgentEndpointDetail(dir, cfg)
		if st != agentEndpointDown || !detail.verified || !detail.needsLogin || detail.reason != "device removed" {
			t.Fatalf("got (%v, %+v), want verified down NeedsLogin", st, detail)
		}
		status, err := agentStateInDir(dir, cfg)
		if err != nil || !status.NeedsLogin {
			t.Fatalf("agentStateInDir = (%+v, %v), want NeedsLogin without error", status, err)
		}
	})

	t.Run("missing status token fails closed as squatted", func(t *testing.T) {
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(agentStatus{Zone: zone, Up: true})
		})
		st, detail := verifyAgentEndpointDetail(dir, cfg)
		if st != agentEndpointSquatted || detail.verified {
			t.Fatalf("got (%v, %+v), want squatted unverified", st, detail)
		}
		if _, err := agentStateInDir(dir, cfg); err == nil {
			t.Fatal("agentStateInDir succeeded without status.token")
		}
	})

	t.Run("wrong hmac fails closed as squatted", func(t *testing.T) {
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Hogman-Proof", "deadbeef")
			_ = json.NewEncoder(w).Encode(agentStatus{Zone: zone, Up: true})
		})
		if _, err := state.WriteStatusToken(dir); err != nil {
			t.Fatal(err)
		}
		res := probeAgentStatus(dir, cfg, time.Second)
		if res.state != agentEndpointSquatted || res.verified || res.err == nil {
			t.Fatalf("got %+v, want squatted error", res)
		}
	})

	t.Run("wrong zone fails closed as squatted", func(t *testing.T) {
		var tok string
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			nonce := r.Header.Get("X-Hogman-Challenge")
			w.Header().Set("X-Hogman-Proof", state.ComputeStatusProof(tok, nonce, "other.pens.example.com"))
			_ = json.NewEncoder(w).Encode(agentStatus{Zone: "other.pens.example.com", Up: true})
		})
		var err error
		tok, err = state.WriteStatusToken(dir)
		if err != nil {
			t.Fatal(err)
		}
		res := probeAgentStatus(dir, cfg, time.Second)
		if res.state != agentEndpointSquatted || res.verified {
			t.Fatalf("got %+v, want squatted", res)
		}
	})

	t.Run("redirect refused as squatted", func(t *testing.T) {
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/other", http.StatusFound)
		})
		_ = os.WriteFile(filepath.Join(dir, state.StatusTokenFilename), []byte("abc"), 0o600)
		res := probeAgentStatus(dir, cfg, time.Second)
		if res.state != agentEndpointSquatted || res.verified {
			t.Fatalf("got %+v, want squatted on redirect", res)
		}
	})
}
