package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newVerifiedStatusServer(t *testing.T, zone string, fn func(call int32) agentStatus) *agentConfig {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	dir := stateDir(zone)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tok, err := writeStatusToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if nonce := strings.TrimSpace(r.Header.Get("X-Hogman-Challenge")); nonce != "" {
			w.Header().Set("X-Hogman-Proof", computeStatusProof(tok, nonce, zone))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fn(n))
	}))
	t.Cleanup(srv.Close)
	return &agentConfig{
		Zone:      zone,
		ProxyAddr: strings.TrimPrefix(srv.URL, "http://"),
	}
}

func TestWaitAgentUpSurvivesTransientACLSyncWindow(t *testing.T) {
	// Reproduces I-21: right after tsnet.Up() succeeds, registrar's Sync loop
	// may not have pushed the new device's IP into Headscale's ACL yet, so
	// /status briefly reports Up=false, Enrolled=true, Error="not connected to pen".
	// waitAgentUpCtx must wait for the ACL to arrive instead of aborting and
	// running __agent-logout.
	const zone = "bobo.pens.example.com"
	var seen atomic.Int32
	cfg := newVerifiedStatusServer(t, zone, func(n int32) agentStatus {
		seen.Store(n)
		if n < 3 {
			return agentStatus{
				Zone:     zone,
				Up:       false,
				Enrolled: true,
				Error:    "not connected to pen",
				IPs:      []string{"100.64.0.9"},
			}
		}
		return agentStatus{
			Zone:     zone,
			Up:       true,
			Enrolled: true,
			IPs:      []string{"100.64.0.9"},
		}
	})
	st, err := waitAgentUpCtx(context.Background(), cfg, 10*time.Second)
	if err != nil {
		t.Fatalf("waitAgentUpCtx should survive transient ACL sync window, got: %v", err)
	}
	if !st.Up || len(st.IPs) != 1 || st.IPs[0] != "100.64.0.9" {
		t.Fatalf("unexpected status: %+v", st)
	}
	if seen.Load() < 3 {
		t.Fatalf("expected at least 3 polls, got %d", seen.Load())
	}
}

func TestWaitAgentUpFailsFastOnStartupErrorAndReportsTransientTimeout(t *testing.T) {
	const zone = "bobo.pens.example.com"

	t.Run("fatal startup error (!Enrolled) fails fast as agentJoinError", func(t *testing.T) {
		cfg := newVerifiedStatusServer(t, zone, func(int32) agentStatus {
			return agentStatus{
				Zone:     zone,
				Up:       false,
				Enrolled: false,
				Error:    "tsnet.Up: backend: authkey already used",
			}
		})
		_, err := waitAgentUpCtx(context.Background(), cfg, 10*time.Second)
		var aje *agentJoinError
		if !errors.As(err, &aje) || !strings.Contains(aje.msg, "authkey already used") {
			t.Fatalf("expected *agentJoinError for rejected authkey, got %T: %v", err, err)
		}
	})

	t.Run("enrolled NeedsLogin fails fast as agentJoinError", func(t *testing.T) {
		cfg := newVerifiedStatusServer(t, zone, func(int32) agentStatus {
			return agentStatus{
				Zone:       zone,
				Up:         false,
				Enrolled:   true,
				NeedsLogin: true,
				Error:      "device removed from pen",
			}
		})
		_, err := waitAgentUpCtx(context.Background(), cfg, 10*time.Second)
		var aje *agentJoinError
		if !errors.As(err, &aje) || !strings.Contains(aje.msg, "device removed from pen") {
			t.Fatalf("expected *agentJoinError on NeedsLogin, got %T: %v", err, err)
		}
	})

	t.Run("stuck transient status times out with real reason and not agentJoinError", func(t *testing.T) {
		cfg := newVerifiedStatusServer(t, zone, func(int32) agentStatus {
			return agentStatus{
				Zone:     zone,
				Up:       false,
				Enrolled: true,
				Error:    "not connected to pen",
				IPs:      []string{"100.64.0.9"},
			}
		})
		_, err := waitAgentUpCtx(context.Background(), cfg, 50*time.Millisecond)
		if err == nil {
			t.Fatal("expected timeout error")
		}
		var aje *agentJoinError
		if errors.As(err, &aje) {
			t.Fatalf("transient timeout must not return *agentJoinError: %v", err)
		}
		if !strings.Contains(err.Error(), "last status: not connected to pen") || !strings.Contains(err.Error(), "not orphaned") {
			t.Fatalf("expected real last status and non-orphan message, got: %v", err)
		}
	})
}

func TestAgentStatusSetsEnrolledOnLiveStatusOverride(t *testing.T) {
	a := &agent{
		cfg: &agentConfig{Zone: "bobo.pens.example.com", DNSServer: "100.64.0.1", ProxyAddr: "127.0.0.1:18123"},
		up:  true,
		ips: []string{"100.64.0.9"},
		liveStatus: func(context.Context) (bool, bool, string, bool) {
			return false, false, "not connected to pen", true
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Host = "127.0.0.1:18123"
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/status = %d, want 200", rec.Code)
	}
	var st agentStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Up || !st.Enrolled || st.NeedsLogin || st.Error != "not connected to pen" {
		t.Fatalf("unexpected /status payload: %+v", st)
	}
}
