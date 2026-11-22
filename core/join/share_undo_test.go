package main

import (
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type closeCounter struct{ n int }

func (c *closeCounter) Close() error { c.n++; return nil }

// A brand-new share that never got a certificate gives its name back, takes its
// server out of the pen, and forgets itself here (so it isn't listed as a site
// that doesn't answer, and running the same command again starts clean).
func TestUndoFreshShare(t *testing.T) {
	const zone = "bobo.pens.example.com"
	var mu sync.Mutex
	var calls []string
	srv := newTLSServerForHost(t, "home."+zone, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/me":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"member":{"handle":"piggy"},"this_device":{"id":7,"kind":"server"}}`))
		case r.Method == "DELETE" && (r.URL.Path == "/api/names/hello" || r.URL.Path == "/api/devices/7"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	hc := homeMeshTestClient(srv, zone)

	dir := t.TempDir()
	for _, f := range []string{"node/state", "acme/retry.json", "share.json", "authkey"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	node := &closeCounter{}
	undoFreshShare(hc, node, dir, &shareConfig{Name: "hello", Zone: zone})

	want := map[string]bool{"DELETE /api/names/hello": false, "GET /api/me": false, "DELETE /api/devices/7": false}
	for _, c := range calls {
		if _, ok := want[c]; ok {
			want[c] = true
		}
	}
	for c, seen := range want {
		if !seen {
			t.Errorf("expected %q; calls were %v", c, calls)
		}
	}
	if node.n == 0 {
		t.Error("the share's node was not closed")
	}
	for _, f := range []string{"node", "acme", "share.json", "authkey"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("%s left behind", f)
		}
	}
}
