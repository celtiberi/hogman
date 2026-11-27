package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hogman/join/internal/agent"
	"hogman/join/internal/penapi"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
)

func listenInHogmanRange(t *testing.T) (net.Listener, int) {
	t.Helper()
	for port := state.PortMin; port <= state.PortMax; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return ln, port
		}
	}
	t.Fatalf("no free port in %d-%d", state.PortMin, state.PortMax)
	return nil, 0
}

func TestAuditAgentBlocksBrowserProbesAndSetsSecurityHeaders(t *testing.T) {
	cfg := &state.AgentConfig{Zone: "farm.pens.hogman.network", ProxyAddr: "127.0.0.1:22111"}
	a := agent.New(cfg, nil)
	a.SetReady(true, nil)
	a.StatusToken = "abcdef0123456789abcdef0123456789"

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

		// Firefox's internal PAC loader sends Sec-Fetch-Site: none with Dest: empty
		// (and same-origin direct loads send Sec-Fetch-Site: same-origin): allow both.
		for _, allowed := range []map[string]string{
			{"Sec-Fetch-Site": "none", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "no-cors"},
			{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty"},
		} {
			reqOK := httptest.NewRequest(http.MethodGet, path, nil)
			reqOK.Host = "127.0.0.1:22111"
			for k, v := range allowed {
				reqOK.Header.Set(k, v)
			}
			recOK := httptest.NewRecorder()
			a.ServeHTTP(recOK, reqOK)
			if recOK.Code != http.StatusOK {
				t.Fatalf("%s with %v = %d, want 200", path, allowed, recOK.Code)
			}
		}

		// Cross-site, same-site, Origin, Referer, and subresource loads are rejected.
		for _, blocked := range []map[string]string{
			{"Origin": "https://evil.example"},
			{"Referer": "https://evil.example/page"},
			{"Sec-Fetch-Site": "cross-site"},
			{"Sec-Fetch-Site": "same-site"},
			{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "script"},
			{"Sec-Fetch-Dest": "script"},
			{"Sec-Fetch-Mode": "no-cors"},
		} {
			req2 := httptest.NewRequest(http.MethodGet, path, nil)
			req2.Host = "127.0.0.1:22111"
			for k, v := range blocked {
				req2.Header.Set(k, v)
			}
			rec2 := httptest.NewRecorder()
			a.ServeHTTP(rec2, req2)
			if rec2.Code != http.StatusForbidden {
				t.Fatalf("%s with %v = %d, want 403", path, blocked, rec2.Code)
			}
		}
	}
}

func TestAuditDuplicateAgentBindFailurePreservesRunningToken(t *testing.T) {
	dir := t.TempDir()
	ln, port := listenInHogmanRange(t)
	cfg := &state.AgentConfig{Zone: "dup.pens.hogman.network", ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port)}
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}
	tok, err := state.WriteStatusToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := agent.New(cfg, nil)
	a.SetReady(true, nil)
	a.StatusToken = tok
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: a}}
	srv.Start()
	defer srv.Close()

	// A second agent.Run pointing at the same directory fails to bind ProxyAddr
	// and MUST NOT overwrite or delete the running agent's status.token.
	if err := agent.Run(dir); err == nil {
		t.Fatal("duplicate agent.Run unexpectedly succeeded on an occupied port")
	}
	st, err := agent.StateInDir(dir, cfg)
	if err != nil || !st.Up {
		t.Fatalf("running agent failed verification after duplicate bind failure: st=%+v err=%v", st, err)
	}
	if ep := agent.VerifyEndpoint(dir, cfg); ep != agent.EndpointUp {
		t.Fatalf("agent.VerifyEndpoint after duplicate bind failure = %v, want agent.EndpointUp", ep)
	}
}

func TestAuditAgentStateVerifiesStatusTokenHMAC(t *testing.T) {
	dir := t.TempDir()
	ln, port := listenInHogmanRange(t)
	cfg := &state.AgentConfig{Zone: "verify.pens.hogman.network", ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port)}
	a := agent.New(cfg, nil)
	a.SetReady(true, nil)
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: a}}
	srv.Start()
	defer srv.Close()

	// Without status.token on disk, agent.StateInDir must fail closed.
	if _, err := agent.StateInDir(dir, cfg); err == nil {
		t.Fatal("agent.StateInDir succeeded with missing status.token")
	}

	tok, err := state.WriteStatusToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, state.StatusTokenFilename))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("status.token mode = %v (err=%v), want 0600", info.Mode(), err)
	}
	// Wrong token in agent -> rejected.
	a.StatusToken = "wrong-token"
	if _, err := agent.StateInDir(dir, cfg); err == nil {
		t.Fatal("agent.StateInDir accepted mismatched HMAC proof")
	}
	// Matching token -> accepted.
	a.StatusToken = tok
	st, err := agent.StateInDir(dir, cfg)
	if err != nil || !st.Up || st.Zone != cfg.Zone {
		t.Fatalf("agent.StateInDir valid token = (%+v, %v), want up", st, err)
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

	h, closeH, err := shareHandler(&state.ShareConfig{
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

	req := httptest.NewRequest(http.MethodGet, "https://app.farm.pens.hogman.network/items/a%2Fb", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || len(gotPaths) != 1 || gotPaths[0] != "/sub/items/a/b" {
		t.Fatalf("valid subpath request with %%2F: code=%d paths=%v", rec.Code, gotPaths)
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

	c, err := penapi.ControlClient("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(redir.URL); err == nil || !strings.Contains(err.Error(), "cross-host") {
		t.Fatalf("cross-host redirect err = %v, want cross-host refusal", err)
	}
}

func TestAuditSystemdQuoteEscapesPercentAndNewlines(t *testing.T) {
	unit := platform.RenderSystemdUnit("farm.pens.hogman.network", "/tmp/foo%h/$HOME/bar\nExecStart=/evil\r", "/tmp/dir")
	if strings.Contains(unit, "\nExecStart=/evil") {
		t.Fatalf("RenderSystemdUnit allowed injected ExecStart line:\n%s", unit)
	}
	if !strings.Contains(unit, "%%h") {
		t.Fatalf("RenderSystemdUnit did not escape %%:\n%s", unit)
	}
	if !strings.Contains(unit, "$$HOME") {
		t.Fatalf("RenderSystemdUnit did not escape $:\n%s", unit)
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
