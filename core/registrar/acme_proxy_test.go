package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"hogman/registrar/internal/acme"
	"hogman/registrar/internal/api"
	"hogman/registrar/internal/headscale"
	"hogman/registrar/internal/registrar"
	"hogman/registrar/internal/store"
)

type stubACMEBackend struct {
	mu      sync.Mutex
	txt     map[string][]string
	setErr  error
	delErr  error
	eabErr  error
	eabPair *acme.EABPair
	eabHits int
}

func (b *stubACMEBackend) SetTXT(_ context.Context, fqdn, value string) error {
	if b.setErr != nil {
		return b.setErr
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.txt == nil {
		b.txt = map[string][]string{}
	}
	b.txt[fqdn] = append(b.txt[fqdn], value)
	return nil
}

func (b *stubACMEBackend) DeleteTXT(_ context.Context, fqdn, value string) error {
	if b.delErr != nil {
		return b.delErr
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	vals := b.txt[fqdn]
	kept := vals[:0]
	for _, v := range vals {
		if v != value {
			kept = append(kept, v)
		}
	}
	if len(kept) == 0 {
		delete(b.txt, fqdn)
	} else {
		b.txt[fqdn] = kept
	}
	return nil
}

func (b *stubACMEBackend) MintEAB(_ context.Context) (*acme.EABPair, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.eabHits++
	if b.eabErr != nil {
		return nil, b.eabErr
	}
	if b.eabPair != nil {
		cp := *b.eabPair
		return &cp, nil
	}
	return &acme.EABPair{KID: "test-kid", HMACB64URL: "dGVzdC1tYWM", Contact: "ops@example.com"}, nil
}

func TestMeshACMEEndpoints(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := registrar.Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "alice", "member"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")
	_, aliceOtherSrv := e.addDevice(t, "alice", "server", "alice-srv2", "100.64.0.12", "")
	_, bobSrv := e.addDevice(t, "bob", "server", "bob-srv", "100.64.0.13", "")

	h := api.MeshHandler(e.svc)
	jsonHdr := map[string]string{"Content-Type": "application/json"}
	validVal := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	// 503 when ACME backend is not configured (even with owned name).
	if _, err := e.svc.ServerClaim(registrar.Actor{CLI: false, Member: aliceSrvMember(t, e, "alice")}, aliceSrv, "photos", nil); err != nil {
		t.Fatal(err)
	}
	rec := doMeshReq(h, "POST", "/api/acme/txt", "100.64.0.11", `{"name":"photos","value":"`+validVal+`"}`, jsonHdr)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured backend: got %d want 503 body=%s", rec.Code, rec.Body.String())
	}

	// Attach mock backend and verify auth, ownership, and reserved checks.
	backend := &stubACMEBackend{}
	cfg := e.svc.Config()
	cfg.ACMEBackend = backend
	svcWithACME, err := registrar.NewService(cfg, e.st, e.hsClient)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svcWithACME
	h = api.MeshHandler(e.svc)

	rec = doMeshReq(h, "POST", "/api/acme/txt", "100.64.0.11", `{"name":"photos","value":"`+validVal+`"}`, jsonHdr)
	if rec.Code != http.StatusCreated {
		t.Fatalf("owner server POST txt: got %d want 201 body=%s", rec.Code, rec.Body.String())
	}
	wantFQDN := "_acme-challenge.photos.bobo.hogman"
	if got := backend.txt[wantFQDN]; len(got) != 1 || got[0] != validVal {
		t.Fatalf("backend txt mismatch: %+v", backend.txt)
	}

	// Claimed sub-name under owned top-level name succeeds too.
	if _, err := e.svc.ServerClaim(registrar.Actor{CLI: false, Member: aliceSrvMember(t, e, "alice")}, aliceSrv, "blog.photos", nil); err != nil {
		t.Fatal(err)
	}
	rec = doMeshReq(h, "POST", "/api/acme/txt", "100.64.0.11", `{"name":"blog.photos.bobo.hogman","value":"`+validVal+`"}`, jsonHdr)
	if rec.Code != http.StatusCreated {
		t.Fatalf("sub-name POST txt: got %d want 201 body=%s", rec.Code, rec.Body.String())
	}

	// Ordinary names starting with "ns" (e.g., nspire) must work while ^ns[0-9]*$ remain refused.
	if _, err := e.svc.ServerClaim(registrar.Actor{CLI: false, Member: aliceSrvMember(t, e, "alice")}, aliceSrv, "nspire", nil); err != nil {
		t.Fatal(err)
	}
	rec = doMeshReq(h, "POST", "/api/acme/txt", "100.64.0.11", `{"name":"nspire","value":"`+validVal+`"}`, jsonHdr)
	if rec.Code != http.StatusCreated {
		t.Fatalf("nspire POST txt: got %d want 201 body=%s", rec.Code, rec.Body.String())
	}
	rec = doMeshReq(h, "DELETE", "/api/acme/txt", "100.64.0.11", `{"name":"nspire","value":"`+validVal+`"}`, jsonHdr)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("nspire DELETE txt: got %d want 204 body=%s", rec.Code, rec.Body.String())
	}

	// Another server of same member, another member's server, personal device, unclaimed name -> refused.
	for _, tc := range []struct {
		desc, method, path, ip, body string
		hdrs                         map[string]string
		want                         int
	}{
		{"personal device txt", "POST", "/api/acme/txt", "100.64.0.10", `{"name":"photos","value":"` + validVal + `"}`, jsonHdr, 403},
		{"personal device eab", "POST", "/api/acme/eab", "100.64.0.10", ``, jsonHdr, 403},
		{"same member other server", "POST", "/api/acme/txt", aliceOtherSrv.IPv4, `{"name":"photos","value":"` + validVal + `"}`, jsonHdr, 403},
		{"other member server", "POST", "/api/acme/txt", bobSrv.IPv4, `{"name":"photos","value":"` + validVal + `"}`, jsonHdr, 403},
		{"unclaimed name", "POST", "/api/acme/txt", "100.64.0.11", `{"name":"unclaimed","value":"` + validVal + `"}`, jsonHdr, 403},
		{"reserved home", "POST", "/api/acme/txt", "100.64.0.11", `{"name":"home","value":"` + validVal + `"}`, jsonHdr, 403},
		{"reserved ns", "POST", "/api/acme/txt", "100.64.0.11", `{"name":"ns","value":"` + validVal + `"}`, jsonHdr, 403},
		{"reserved ns1", "POST", "/api/acme/txt", "100.64.0.11", `{"name":"ns1","value":"` + validVal + `"}`, jsonHdr, 403},
		{"reserved nodes", "POST", "/api/acme/txt", "100.64.0.11", `{"name":"nodes","value":"` + validVal + `"}`, jsonHdr, 403},
		{"reserved _acme-challenge", "POST", "/api/acme/txt", "100.64.0.11", `{"name":"_acme-challenge.photos","value":"` + validVal + `"}`, jsonHdr, 403},
		{"bad txt value", "POST", "/api/acme/txt", "100.64.0.11", `{"name":"photos","value":"bad!val"}`, jsonHdr, 400},
		{"csrf same-site blocked", "POST", "/api/acme/txt", "100.64.0.11", `{"name":"photos","value":"` + validVal + `"}`, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-site"}, 403},
		{"server without claimed name eab", "POST", "/api/acme/eab", bobSrv.IPv4, ``, jsonHdr, 403},
	} {
		rec := doMeshReq(h, tc.method, tc.path, tc.ip, tc.body, tc.hdrs)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d want %d body=%s", tc.desc, rec.Code, tc.want, rec.Body.String())
		}
	}

	// Owner server EAB succeeds once it owns a claimed name.
	rec = doMeshReq(h, "POST", "/api/acme/eab", "100.64.0.11", ``, jsonHdr)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"kid":"test-kid"`) {
		t.Fatalf("POST /api/acme/eab: got %d body=%s", rec.Code, rec.Body.String())
	}

	// Delete TXT cleans up.
	rec = doMeshReq(h, "DELETE", "/api/acme/txt", "100.64.0.11", `{"name":"photos","value":"`+validVal+`"}`, jsonHdr)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /api/acme/txt: got %d want 204 body=%s", rec.Code, rec.Body.String())
	}
	if len(backend.txt[wantFQDN]) != 0 {
		t.Fatalf("txt not cleared after DELETE: %+v", backend.txt)
	}
}

func TestMeshACMERateLimitPassthrough(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := registrar.Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "alice", "member"); err != nil {
		t.Fatal(err)
	}
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")
	if _, err := e.svc.ServerClaim(registrar.Actor{CLI: false, Member: aliceSrvMember(t, e, "alice")}, aliceSrv, "photos", nil); err != nil {
		t.Fatal(err)
	}

	// Simulate challenge-dns returning 429 with Retry-After on both /v1/txt and /v1/eab.
	cdns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/txt":
			w.Header().Set("Retry-After", "1800")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"too many new certificate names for this pen in the last hour"}`)
		case "/v1/eab":
			w.Header().Set("Retry-After", "2400")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"too many fallback account keys for this credential in the last hour"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer cdns.Close()

	cdnsCli, err := acme.NewChallengeDNSClient(cdns.URL, "hcd_test_token")
	if err != nil {
		t.Fatal(err)
	}
	cfg := e.svc.Config()
	cfg.ACMEBackend = cdnsCli
	svcWithACME, err := registrar.NewService(cfg, e.st, e.hsClient)
	if err != nil {
		t.Fatal(err)
	}
	h := api.MeshHandler(svcWithACME)
	jsonHdr := map[string]string{"Content-Type": "application/json"}
	validVal := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	rec := doMeshReq(h, "POST", "/api/acme/txt", "100.64.0.11", `{"name":"photos","value":"`+validVal+`"}`, jsonHdr)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("POST /api/acme/txt 429: got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "1800" {
		t.Fatalf("POST /api/acme/txt Retry-After = %q, want 1800", got)
	}
	if !strings.Contains(rec.Body.String(), "too many new certificate names for this pen in the last hour") {
		t.Fatalf("POST /api/acme/txt body = %s, want verbatim message", rec.Body.String())
	}

	rec = doMeshReq(h, "POST", "/api/acme/eab", "100.64.0.11", ``, jsonHdr)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("POST /api/acme/eab 429: got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "2400" {
		t.Fatalf("POST /api/acme/eab Retry-After = %q, want 2400", got)
	}
	if !strings.Contains(rec.Body.String(), "too many fallback account keys for this credential in the last hour") {
		t.Fatalf("POST /api/acme/eab body = %s, want verbatim message", rec.Body.String())
	}
}

func aliceSrvMember(t *testing.T, e *testEnv, handle string) *store.Member {
	t.Helper()
	m, err := e.st.MemberByHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPublicCertNetworkInfoAndLinks(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "registrar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DB().Close() })
	hs := newFakeHeadscale(t)
	pubSvc, err := registrar.NewService(registrar.Config{
		Zone:       "bobo.pens.example.com",
		PublicHost: "bobo.gate.example.com",
		CoreIP:     "100.64.0.1",
	}, st, headscale.New(hs.srv.URL, "test-key"))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	pubInfo := pubSvc.NetworkInfo()
	if pubInfo.CertMode != "public" {
		t.Fatalf("CertMode = %q, want public", pubInfo.CertMode)
	}
	if got := pubSvc.InviteLink("tok1"); got != "https://bobo.gate.example.com/join#t=tok1" {
		t.Fatalf("InviteLink = %q", got)
	}
	if got := pubSvc.DeviceLink("key1", "personal"); got != "https://bobo.gate.example.com/join#k=key1" {
		t.Fatalf("personal DeviceLink = %q", got)
	}
	if got := pubSvc.DeviceLink("key1", "server"); got != "https://bobo.gate.example.com/join#k=key1&for=share" {
		t.Fatalf("server DeviceLink = %q", got)
	}
	req, _ := http.NewRequest("GET", "/hogman/v1/network", nil)
	rec := httptest.NewRecorder()
	api.PublicHandler(pubSvc).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /hogman/v1/network status = %d", rec.Code)
	}
	rawJSON := rec.Body.String()
	if !strings.Contains(rawJSON, `"cert_mode":"public"`) || strings.Contains(rawJSON, "root_fingerprint") || strings.Contains(rawJSON, "root_ca") || strings.Contains(rawJSON, `"pens_zone"`) {
		t.Fatalf("unexpected /hogman/v1/network payload: %s", rawJSON)
	}
}
