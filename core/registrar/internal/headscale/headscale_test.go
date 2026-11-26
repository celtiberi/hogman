package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClientNodeValidationAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/node/42":
			_, _ = w.Write([]byte(`{"node":{"id":"42","name":"laptop","tags":["tag:server"]}}`))
		case "/api/v1/node/mismatch":
			_, _ = w.Write([]byte(`{"node":{"id":"99"}}`))
		case "/api/v1/node/missing":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`node not found`))
		case "/api/v1/user":
			_, _ = w.Write([]byte(`{"users":[{"id":"1","name":"bob"}]}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(strings.Repeat("é", maxErrorBytes)))
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "secret")
	ctx := context.Background()

	n, err := c.Node(ctx, "42")
	if err != nil || n.ID != "42" || !n.HasTag("tag:server") {
		t.Fatalf("Node(42) = %+v, %v", n, err)
	}
	if _, err := c.Node(ctx, "../etc"); err == nil {
		t.Fatal("expected invalid node id error")
	}
	if _, err := c.Node(ctx, "mismatch"); err == nil {
		t.Fatal("expected mismatched node id error")
	}
	if _, err := c.Node(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Node(missing) err = %v, want ErrNotFound", err)
	}
	if err := c.DeleteNode(ctx, "missing"); err != nil {
		t.Fatalf("DeleteNode(missing) should be idempotent, got %v", err)
	}
	if _, err := c.UserByName(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UserByName(alice) err = %v, want ErrNotFound", err)
	}
	if err := c.Health(ctx); err == nil {
		t.Fatal("expected 500 error on /health")
	} else {
		var he *Error
		if !errors.As(err, &he) || he.Status != 500 || !strings.HasSuffix(he.Body, "...(truncated)") || !utf8.ValidString(he.Body) {
			t.Fatalf("unexpected truncated error: %v", err)
		}
	}
}

func TestHeadscaleClientHardening(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/node", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxResponseBytes+16))
	})
	mux.HandleFunc("GET /api/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(bytes.Repeat([]byte("E"), maxErrorBytes+500))
	})
	mux.HandleFunc("GET /api/v1/node/{id}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("id") {
		case "42":
			_ = json.NewEncoder(w).Encode(map[string]any{"node": Node{ID: "99"}})
		case "404":
			http.Error(w, "node not found", http.StatusNotFound)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"node": Node{ID: r.PathValue("id")}})
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	hs := New(srv.URL, "k")

	if _, err := hs.Nodes(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("oversized Nodes() err = %v, want overflow error", err)
	}
	_, err := hs.Policy(context.Background())
	var he *Error
	if !errors.As(err, &he) || !strings.HasSuffix(he.Body, "...(truncated)") || len(he.Body) > maxErrorBytes+32 {
		t.Fatalf("oversized error body not truncated properly: err=%v len=%d", err, len(he.Body))
	}
	for _, badID := range []string{"  ", ".", "..", "1/2", "1\\2"} {
		if _, err := hs.Node(context.Background(), badID); err == nil {
			t.Fatalf("Node(%q) succeeded, want error", badID)
		}
	}
	if _, err := hs.Node(context.Background(), "42"); err == nil || !strings.Contains(err.Error(), "mismatched") {
		t.Fatalf("Node(42) with id=99 response: err=%v, want mismatched error", err)
	}
	if _, err := hs.Node(context.Background(), "404"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Node(404) err=%v, want ErrNotFound", err)
	}
	if n, err := hs.Node(context.Background(), "7"); err != nil || n.ID != "7" {
		t.Fatalf("Node(7) = (%+v, %v)", n, err)
	}
}
