package agent

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

func TestProbeStatusMatrix(t *testing.T) {
	t.Parallel()
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
		t.Parallel()
		var tok string
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			nonce := r.Header.Get("X-Hogman-Challenge")
			w.Header().Set("X-Hogman-Proof", state.ComputeStatusProof(tok, nonce, zone))
			_ = json.NewEncoder(w).Encode(Status{Zone: zone, Up: true, IPs: []string{"100.64.0.2"}})
		})
		var err error
		tok, err = state.WriteStatusToken(dir)
		if err != nil {
			t.Fatal(err)
		}
		res := ProbeStatus(dir, cfg, time.Second)
		if res.State != EndpointUp || !res.Verified || res.Status == nil || !res.Status.Up {
			t.Fatalf("got %+v, want verified up", res)
		}
	})

	t.Run("verified down with needsLogin", func(t *testing.T) {
		t.Parallel()
		var tok string
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			nonce := r.Header.Get("X-Hogman-Challenge")
			w.Header().Set("X-Hogman-Proof", state.ComputeStatusProof(tok, nonce, zone))
			_ = json.NewEncoder(w).Encode(Status{Zone: zone, Up: false, NeedsLogin: true, Error: "device removed"})
		})
		var err error
		tok, err = state.WriteStatusToken(dir)
		if err != nil {
			t.Fatal(err)
		}
		st, detail := VerifyEndpointDetail(dir, cfg)
		if st != EndpointDown || !detail.Verified || !detail.NeedsLogin || detail.Reason != "device removed" {
			t.Fatalf("got (%v, %+v), want verified down NeedsLogin", st, detail)
		}
		status, err := StateInDir(dir, cfg)
		if err != nil || !status.NeedsLogin {
			t.Fatalf("StateInDir = (%+v, %v), want NeedsLogin without error", status, err)
		}
	})

	t.Run("missing status token fails closed as squatted", func(t *testing.T) {
		t.Parallel()
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Status{Zone: zone, Up: true})
		})
		st, detail := VerifyEndpointDetail(dir, cfg)
		if st != EndpointSquatted || detail.Verified {
			t.Fatalf("got (%v, %+v), want squatted unverified", st, detail)
		}
		if _, err := StateInDir(dir, cfg); err == nil {
			t.Fatal("StateInDir succeeded without status.token")
		}
	})

	t.Run("wrong hmac fails closed as squatted", func(t *testing.T) {
		t.Parallel()
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Hogman-Proof", "deadbeef")
			_ = json.NewEncoder(w).Encode(Status{Zone: zone, Up: true})
		})
		if _, err := state.WriteStatusToken(dir); err != nil {
			t.Fatal(err)
		}
		res := ProbeStatus(dir, cfg, time.Second)
		if res.State != EndpointSquatted || res.Verified || res.Err == nil {
			t.Fatalf("got %+v, want squatted error", res)
		}
	})

	t.Run("wrong zone fails closed as squatted", func(t *testing.T) {
		t.Parallel()
		var tok string
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			nonce := r.Header.Get("X-Hogman-Challenge")
			w.Header().Set("X-Hogman-Proof", state.ComputeStatusProof(tok, nonce, "other.pens.example.com"))
			_ = json.NewEncoder(w).Encode(Status{Zone: "other.pens.example.com", Up: true})
		})
		var err error
		tok, err = state.WriteStatusToken(dir)
		if err != nil {
			t.Fatal(err)
		}
		res := ProbeStatus(dir, cfg, time.Second)
		if res.State != EndpointSquatted || res.Verified {
			t.Fatalf("got %+v, want squatted", res)
		}
	})

	t.Run("redirect refused as squatted", func(t *testing.T) {
		t.Parallel()
		cfg, dir := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/other", http.StatusFound)
		})
		_ = os.WriteFile(filepath.Join(dir, state.StatusTokenFilename), []byte("abc"), 0o600)
		res := ProbeStatus(dir, cfg, time.Second)
		if res.State != EndpointSquatted || res.Verified {
			t.Fatalf("got %+v, want squatted on redirect", res)
		}
	})
}
