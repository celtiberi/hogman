package agent

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

	"hogman/join/internal/state"
)

func newVerifiedStatusServer(t *testing.T, zone string, fn func(call int32) Status) *state.AgentConfig {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	dir := state.StateDir(zone)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tok, err := state.WriteStatusToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if nonce := strings.TrimSpace(r.Header.Get("X-Hogman-Challenge")); nonce != "" {
			w.Header().Set("X-Hogman-Proof", state.ComputeStatusProof(tok, nonce, zone))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fn(n))
	}))
	t.Cleanup(srv.Close)
	return &state.AgentConfig{
		Zone:      zone,
		ProxyAddr: strings.TrimPrefix(srv.URL, "http://"),
	}
}

func TestWaitUpSurvivesTransientACLSyncWindow(t *testing.T) {
	const zone = "bobo.pens.example.com"
	var seen atomic.Int32
	cfg := newVerifiedStatusServer(t, zone, func(n int32) Status {
		seen.Store(n)
		if n < 3 {
			return Status{
				Zone:     zone,
				Up:       false,
				Enrolled: true,
				Error:    "not connected to pen",
				IPs:      []string{"100.64.0.9"},
			}
		}
		return Status{
			Zone:     zone,
			Up:       true,
			Enrolled: true,
			IPs:      []string{"100.64.0.9"},
		}
	})
	st, err := WaitUpCtx(context.Background(), cfg, 10*time.Second)
	if err != nil {
		t.Fatalf("WaitUpCtx should survive transient ACL sync window, got: %v", err)
	}
	if !st.Up || len(st.IPs) != 1 || st.IPs[0] != "100.64.0.9" {
		t.Fatalf("unexpected status: %+v", st)
	}
	if seen.Load() < 3 {
		t.Fatalf("expected at least 3 polls, got %d", seen.Load())
	}
}

func TestWaitUpFailsFastOnStartupErrorAndReportsTransientTimeout(t *testing.T) {
	const zone = "bobo.pens.example.com"

	t.Run("fatal startup error (!Enrolled) fails fast as JoinError", func(t *testing.T) {
		cfg := newVerifiedStatusServer(t, zone, func(int32) Status {
			return Status{
				Zone:     zone,
				Up:       false,
				Enrolled: false,
				Error:    "tsnet.Up: backend: authkey already used",
			}
		})
		_, err := WaitUpCtx(context.Background(), cfg, 10*time.Second)
		var aje *JoinError
		if !errors.As(err, &aje) || !strings.Contains(aje.Msg, "authkey already used") {
			t.Fatalf("expected *JoinError for rejected authkey, got %T: %v", err, err)
		}
	})

	t.Run("enrolled NeedsLogin fails fast as JoinError", func(t *testing.T) {
		cfg := newVerifiedStatusServer(t, zone, func(int32) Status {
			return Status{
				Zone:       zone,
				Up:         false,
				Enrolled:   true,
				NeedsLogin: true,
				Error:      "device removed from pen",
			}
		})
		_, err := WaitUpCtx(context.Background(), cfg, 10*time.Second)
		var aje *JoinError
		if !errors.As(err, &aje) || !strings.Contains(aje.Msg, "device removed from pen") {
			t.Fatalf("expected *JoinError on NeedsLogin, got %T: %v", err, err)
		}
	})

	t.Run("stuck transient status times out with real reason and not JoinError", func(t *testing.T) {
		cfg := newVerifiedStatusServer(t, zone, func(int32) Status {
			return Status{
				Zone:     zone,
				Up:       false,
				Enrolled: true,
				Error:    "not connected to pen",
				IPs:      []string{"100.64.0.9"},
			}
		})
		_, err := WaitUpCtx(context.Background(), cfg, 50*time.Millisecond)
		if err == nil {
			t.Fatal("expected timeout error")
		}
		var aje *JoinError
		if errors.As(err, &aje) {
			t.Fatalf("transient timeout must not return *JoinError: %v", err)
		}
		if !strings.Contains(err.Error(), "last status: not connected to pen") || !strings.Contains(err.Error(), "not orphaned") {
			t.Fatalf("expected real last status and non-orphan message, got: %v", err)
		}
	})
}
