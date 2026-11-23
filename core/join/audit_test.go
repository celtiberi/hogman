package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditAgentBlocksBrowserProbesAndSetsSecurityHeaders(t *testing.T) {
	cfg := &agentConfig{Zone: "farm.pens.hogman.network", ProxyAddr: "127.0.0.1:22111"}
	a := newAgent(cfg, nil)
	a.up = true
	a.statusToken = "abcdef0123456789abcdef0123456789"

	for _, path := range []string{"/proxy.pac", "/status"} {
		// Clean local request succeeds with hardening headers.
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1:22111"
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s clean request = %d, want 200", path, rec.Code)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("%s X-Content-Type-Options = %q, want nosniff", path, got)
		}
		if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
			t.Fatalf("%s CORP = %q, want same-origin", path, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s Cache-Control = %q, want no-store", path, got)
		}

		// Any browser probe header is rejected with 403.
		for _, hdr := range []struct{ k, v string }{
			{"Origin", "https://evil.example"},
			{"Referer", "https://evil.example/page"},
			{"Sec-Fetch-Site", "cross-site"},
			{"Sec-Fetch-Dest", "script"},
			{"Sec-Fetch-Mode", "no-cors"},
		} {
			req2 := httptest.NewRequest(http.MethodGet, path, nil)
			req2.Host = "127.0.0.1:22111"
			req2.Header.Set(hdr.k, hdr.v)
			rec2 := httptest.NewRecorder()
			a.ServeHTTP(rec2, req2)
			if rec2.Code != http.StatusForbidden {
				t.Fatalf("%s with %s=%q = %d, want 403", path, hdr.k, hdr.v, rec2.Code)
			}
		}
	}
}

func TestAuditAgentStateVerifiesStatusTokenHMAC(t *testing.T) {
	dir := t.TempDir()
	ln, port := listenInHogmanRange(t)
	cfg := &agentConfig{Zone: "verify.pens.hogman.network", ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port)}
	a := newAgent(cfg, nil)
	a.up = true
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: a}}
	srv.Start()
	defer srv.Close()

	// Without status.token on disk, agentStateInDir must fail closed.
	if _, err := agentStateInDir(dir, cfg); err == nil {
		t.Fatal("agentStateInDir succeeded with missing status.token")
	}

	tok, err := writeStatusToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, statusTokenFilename))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("status.token mode = %v (err=%v), want 0600", info.Mode(), err)
	}
	// Wrong token in agent -> rejected.
	a.statusToken = "wrong-token"
	if _, err := agentStateInDir(dir, cfg); err == nil {
		t.Fatal("agentStateInDir accepted mismatched HMAC proof")
	}
	// Matching token -> accepted.
	a.statusToken = tok
	st, err := agentStateInDir(dir, cfg)
	if err != nil || !st.Up || st.Zone != cfg.Zone {
		t.Fatalf("agentStateInDir valid token = (%+v, %v), want up", st, err)
	}
}

func TestAuditShareSubpathBlocksTraversal(t *testing.T) {
	var gotPaths []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	h, closeH, err := shareHandler(&shareConfig{
		Name:   "app",
		Zone:   "farm.pens.hogman.network",
		Target: upstream.URL + "/sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeH()

	for _, bad := range []string{
		"/../secret",
		"/a/../../secret",
		"/%2e%2e/secret",
		"/%2E%2E%2Fsecret",
		"/%5csecret",
	} {
		req := httptest.NewRequest(http.MethodGet, "https://app.farm.pens.hogman.network"+bad, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("traversal path %q = %d, want 400", bad, rec.Code)
		}
	}
	if len(gotPaths) != 0 {
		t.Fatalf("traversal requests reached upstream: %v", gotPaths)
	}

	req := httptest.NewRequest(http.MethodGet, "https://app.farm.pens.hogman.network/items", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || len(gotPaths) != 1 || gotPaths[0] != "/sub/items" {
		t.Fatalf("valid subpath request: code=%d paths=%v", rec.Code, gotPaths)
	}
}

func TestAuditControlClientBlocksCrossHostRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}))
	defer redir.Close()

	c, err := controlClient("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(redir.URL); err == nil || !strings.Contains(err.Error(), "cross-host") {
		t.Fatalf("cross-host redirect err = %v, want cross-host refusal", err)
	}
}

func TestAuditSystemdQuoteEscapesPercentAndNewlines(t *testing.T) {
	got := systemdQuote("/tmp/foo%h/bar\nExecStart=/evil\r")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("systemdQuote left newline: %q", got)
	}
	if !strings.Contains(got, "%%h") {
		t.Fatalf("systemdQuote did not escape %%: %q", got)
	}
}

func TestAuditACMEValidatesCARootBeforeMkdir(t *testing.T) {
	storageDir := filepath.Join(t.TempDir(), "should-not-exist")
	_, err := newShareCertManager(shareACMEConfig{
		Zone:       "farm.pens.hogman.network",
		Host:       "web.farm.pens.hogman.network",
		StorageDir: storageDir,
		HTTPClient: &http.Client{},
		CARootFile: filepath.Join(t.TempDir(), "missing-ca.pem"),
	})
	if err == nil {
		t.Fatal("expected error for missing CARootFile")
	}
	if _, statErr := os.Stat(storageDir); !os.IsNotExist(statErr) {
		t.Fatalf("StorageDir was created despite invalid CARootFile (stat err=%v)", statErr)
	}
}
