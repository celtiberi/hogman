package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
)

type stubACMEBackend struct {
	mu      sync.Mutex
	txt     map[string][]string
	setErr  error
	delErr  error
	eabErr  error
	eabPair *EABPair
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

func (b *stubACMEBackend) MintEAB(_ context.Context) (*EABPair, error) {
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
	return &EABPair{KID: "test-kid", HMACB64URL: "dGVzdC1tYWM", Contact: "ops@example.com"}, nil
}

func newShortSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hgt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func TestChallengeDNSClientHTTPAndUnix(t *testing.T) {
	const wantTok = "hcd_test_token_1234"
	var sawMethod, sawPath, sawAuth, sawFQDN, sawVal string
	var statusToReturn int

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/txt", func(w http.ResponseWriter, r *http.Request) {
		sawMethod = r.Method
		sawPath = r.URL.Path
		sawAuth = r.Header.Get("Authorization")
		if sawAuth != "Bearer "+wantTok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var in struct {
			FQDN  string `json:"fqdn"`
			Value string `json:"value"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		sawFQDN, sawVal = in.FQDN, in.Value
		if statusToReturn != 0 {
			w.WriteHeader(statusToReturn)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "limit exceeded"})
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/eab", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+wantTok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(EABPair{KID: "kid-1", HMACB64URL: "bWFjLTE"})
	})

	// 1. TCP HTTP client
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cli, err := NewChallengeDNSClient(srv.URL, wantTok)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	val := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := cli.SetTXT(ctx, "_acme-challenge.Photos.abcdefghijk2.pens.hogman.network.", val); err != nil {
		t.Fatalf("SetTXT: %v", err)
	}
	if sawMethod != http.MethodPost || sawPath != "/v1/txt" || sawFQDN != "_acme-challenge.photos.abcdefghijk2.pens.hogman.network" || sawVal != val {
		t.Fatalf("unexpected SetTXT request: method=%s path=%s fqdn=%q val=%q", sawMethod, sawPath, sawFQDN, sawVal)
	}
	if err := cli.DeleteTXT(ctx, "_acme-challenge.photos.abcdefghijk2.pens.hogman.network", val); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if sawMethod != http.MethodDelete {
		t.Fatalf("expected DELETE, got %s", sawMethod)
	}
	pair, err := cli.MintEAB(ctx)
	if err != nil || pair.KID != "kid-1" || pair.HMACB64URL != "bWFjLTE" {
		t.Fatalf("MintEAB = %+v, %v", pair, err)
	}

	for _, code := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusConflict, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		statusToReturn = code
		err := cli.SetTXT(ctx, "_acme-challenge.photos.abcdefghijk2.pens.hogman.network", val)
		var p *Problem
		if !errors.As(err, &p) || p.Status != code {
			t.Fatalf("status %d: got err=%v", code, err)
		}
	}
	statusToReturn = 0

	// 2. Unix domain socket client (both unix:/// and unix: forms)
	sockPath := newShortSocketPath(t, "api.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	uSrv := &http.Server{Handler: mux}
	go func() { _ = uSrv.Serve(ln) }()
	t.Cleanup(func() { _ = uSrv.Close() })

	for _, urlForm := range []string{"unix://" + sockPath, "unix:" + sockPath} {
		uCli, err := NewChallengeDNSClient(urlForm, wantTok)
		if err != nil {
			t.Fatalf("%s: %v", urlForm, err)
		}
		if err := uCli.SetTXT(ctx, "_acme-challenge.home.abcdefghijk2.pens.hogman.network", val); err != nil {
			t.Fatalf("%s SetTXT: %v", urlForm, err)
		}
		if err := uCli.DeleteTXT(ctx, "_acme-challenge.home.abcdefghijk2.pens.hogman.network", val); err != nil {
			t.Fatalf("%s DeleteTXT: %v", urlForm, err)
		}
	}
}

func TestMeshACMEEndpoints(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

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

	h := MeshHandler(e.svc)
	jsonHdr := map[string]string{"Content-Type": "application/json"}
	validVal := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	// 503 when ACME backend is not configured (even with owned name).
	if _, err := e.svc.ServerClaim(Actor{CLI: false, Member: aliceSrvMember(t, e, "alice")}, aliceSrv, "photos", nil); err != nil {
		t.Fatal(err)
	}
	rec := doMeshReq(h, "POST", "/api/acme/txt", "100.64.0.11", `{"name":"photos","value":"`+validVal+`"}`, jsonHdr)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured backend: got %d want 503 body=%s", rec.Code, rec.Body.String())
	}

	// Attach mock backend and verify auth, ownership, and reserved checks.
	backend := &stubACMEBackend{}
	e.svc.acme = backend

	rec = doMeshReq(h, "POST", "/api/acme/txt", "100.64.0.11", `{"name":"photos","value":"`+validVal+`"}`, jsonHdr)
	if rec.Code != http.StatusCreated {
		t.Fatalf("owner server POST txt: got %d want 201 body=%s", rec.Code, rec.Body.String())
	}
	wantFQDN := "_acme-challenge.photos.bobo.hogman"
	if got := backend.txt[wantFQDN]; len(got) != 1 || got[0] != validVal {
		t.Fatalf("backend txt mismatch: %+v", backend.txt)
	}

	// Claimed sub-name under owned top-level name succeeds too.
	if _, err := e.svc.ServerClaim(Actor{CLI: false, Member: aliceSrvMember(t, e, "alice")}, aliceSrv, "blog.photos", nil); err != nil {
		t.Fatal(err)
	}
	rec = doMeshReq(h, "POST", "/api/acme/txt", "100.64.0.11", `{"name":"blog.photos.bobo.hogman","value":"`+validVal+`"}`, jsonHdr)
	if rec.Code != http.StatusCreated {
		t.Fatalf("sub-name POST txt: got %d want 201 body=%s", rec.Code, rec.Body.String())
	}

	// Ordinary names starting with "ns" (e.g., nspire) must work while ^ns[0-9]*$ remain refused.
	if _, err := e.svc.ServerClaim(Actor{CLI: false, Member: aliceSrvMember(t, e, "alice")}, aliceSrv, "nspire", nil); err != nil {
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
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "alice", "member"); err != nil {
		t.Fatal(err)
	}
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")
	if _, err := e.svc.ServerClaim(Actor{CLI: false, Member: aliceSrvMember(t, e, "alice")}, aliceSrv, "photos", nil); err != nil {
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

	cdnsCli, err := NewChallengeDNSClient(cdns.URL, "hcd_test_token")
	if err != nil {
		t.Fatal(err)
	}
	e.svc.acme = cdnsCli

	h := MeshHandler(e.svc)
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

func aliceSrvMember(t *testing.T, e *testEnv, handle string) *Member {
	t.Helper()
	m, err := e.st.MemberByHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestShouldFailoverACME(t *testing.T) {
	if shouldFailoverACME(nil) {
		t.Fatal("nil error must not failover")
	}
	if shouldFailoverACME(context.Canceled) {
		t.Fatal("canceled context must not failover")
	}
	if shouldFailoverACME(dnsStepError{err: errors.New("propagation timeout")}) {
		t.Fatal("DNS solver/propagation error must not failover")
	}
	if shouldFailoverACME(acme.Problem{Type: "urn:ietf:params:acme:error:unauthorized", Status: http.StatusForbidden}) {
		t.Fatal("unauthorized must not failover")
	}
	if shouldFailoverACME(acme.Problem{Type: "urn:ietf:params:acme:error:dns", Status: http.StatusBadRequest}) {
		t.Fatal("dns problem must not failover")
	}
	if !shouldFailoverACME(acme.Problem{Type: "urn:ietf:params:acme:error:rateLimited", Status: http.StatusTooManyRequests}) {
		t.Fatal("rateLimited 429 must failover")
	}
	if !shouldFailoverACME(acme.Problem{Type: "urn:ietf:params:acme:error:serverInternal", Status: http.StatusServiceUnavailable}) {
		t.Fatal("503 server error must failover")
	}
	if !shouldFailoverACME(&net.OpError{Op: "dial", Err: errors.New("connection refused")}) {
		t.Fatal("network outage must failover")
	}
}

func makeSelfSignedPEM(t *testing.T, cn string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestHomeTLSAtomicAndCaddyUnixReload(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := makeSelfSignedPEM(t, "home.bobo.hogman", time.Now().Add(24*time.Hour))

	if err := writeHomeTLSAtomic(dir, certPEM, keyPEM); err != nil {
		t.Fatalf("writeHomeTLSAtomic: %v", err)
	}
	if err := VerifyHomeTLS(dir); err != nil {
		t.Fatalf("VerifyHomeTLS valid: %v", err)
	}

	expiredCert, expiredKey := makeSelfSignedPEM(t, "home.bobo.hogman", time.Now().Add(-time.Minute))
	if err := writeHomeTLSAtomic(dir, expiredCert, expiredKey); err != nil {
		t.Fatal(err)
	}
	if err := VerifyHomeTLS(dir); err == nil {
		t.Fatal("VerifyHomeTLS accepted expired cert")
	}

	// Missing socket skips gracefully without error.
	ctx := context.Background()
	missingSock := newShortSocketPath(t, "missing.sock")
	if err := reloadCaddy(ctx, missingSock); err != nil {
		t.Fatalf("missing socket should be skipped cleanly, got %v", err)
	}

	// Existing Unix socket receives GET /config/ then POST /load with Cache-Control: must-revalidate.
	sockPath := newShortSocketPath(t, "admin.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	var gotConfig, gotCacheCtl, gotContentType, gotLoadedBody string
	const fakeCfg = `{"apps":{"tls":{"certificates":{"load_files":[{"certificate":"/home-tls/home.crt","key":"/home-tls/home.key"}]}}}}`

	mux := http.NewServeMux()
	mux.HandleFunc("GET /config/", func(w http.ResponseWriter, r *http.Request) {
		gotConfig = "yes"
		_, _ = io.WriteString(w, fakeCfg)
	})
	mux.HandleFunc("POST /load", func(w http.ResponseWriter, r *http.Request) {
		gotCacheCtl = r.Header.Get("Cache-Control")
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotLoadedBody = string(b)
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	if err := reloadCaddy(ctx, sockPath); err != nil {
		t.Fatalf("reloadCaddy: %v", err)
	}
	if gotConfig != "yes" || gotCacheCtl != "must-revalidate" || gotContentType != "application/json" || gotLoadedBody != fakeCfg {
		t.Fatalf("unexpected Caddy reload call: config=%q cache=%q ct=%q body=%q", gotConfig, gotCacheCtl, gotContentType, gotLoadedBody)
	}
}

func newMockACMECA(t *testing.T, onOrder func(http.ResponseWriter, *http.Request)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var nonceSeq atomic.Int64
	var hits atomic.Int32
	nextNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonceSeq.Add(1)))
		w.Header().Set("Cache-Control", "no-store")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/acct",
			"newOrder":   base + "/order",
			"revokeCert": base + "/revoke",
			"keyChange":  base + "/key",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/acct", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		nextNonce(w)
		var jws struct {
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var acctPayload struct {
			Contact []string `json:"contact"`
		}
		if err := json.Unmarshal(raw, &acctPayload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(acctPayload.Contact) != 0 {
			http.Error(w, fmt.Sprintf("expected empty contact, got %v", acctPayload.Contact), http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "https://"+r.Host+"/acct/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "valid",
			"orders": "https://" + r.Host + "/acct/1/orders",
		})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		nextNonce(w)
		onOrder(w, r)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestHomeCertManagerEnsureOnceFastFailover429(t *testing.T) {
	var orderStatus atomic.Int32

	primary, _ := newMockACMECA(t, func(w http.ResponseWriter, r *http.Request) {
		st := int(orderStatus.Load())
		w.Header().Set("Content-Type", "application/problem+json")
		if st == http.StatusForbidden {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"type":"urn:ietf:params:acme:error:unauthorized","status":403,"detail":"blocked"}`)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"type":"urn:ietf:params:acme:error:rateLimited","status":429,"detail":"slow down"}`)
	})

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mock-fallback-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	var issuedCertMu sync.Mutex
	var issuedCertPEM []byte

	var nonceSeq atomic.Int64
	var fbAcctHits atomic.Int32
	fbMux := http.NewServeMux()
	nextNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("fb-nonce-%d", nonceSeq.Add(1)))
		w.Header().Set("Cache-Control", "no-store")
	}
	fbMux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/acct",
			"newOrder":   base + "/order",
		})
	})
	fbMux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.WriteHeader(http.StatusOK)
	})
	fbMux.HandleFunc("/acct", func(w http.ResponseWriter, r *http.Request) {
		fbAcctHits.Add(1)
		nextNonce(w)
		var jws struct {
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var acctPayload struct {
			Contact []string `json:"contact"`
		}
		if err := json.Unmarshal(raw, &acctPayload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Like Google: a fallback account needs the operator's contact.
		if len(acctPayload.Contact) != 1 || acctPayload.Contact[0] != "mailto:ops@example.com" {
			http.Error(w, fmt.Sprintf("Accounts must have at least one contact (want [mailto:ops@example.com], got %v)", acctPayload.Contact), http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "https://"+r.Host+"/acct/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	fbMux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.Header().Set("Location", "https://"+r.Host+"/order/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      "ready",
			"identifiers": []map[string]string{{"type": "dns", "value": "home.bobo.hogman"}},
			"finalize":    "https://" + r.Host + "/finalize",
		})
	})
	fbMux.HandleFunc("/finalize", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var jws struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(body, &jws); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rawPayload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var fin struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal(rawPayload, &fin); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		csrDER, err := base64.RawURLEncoding.DecodeString(fin.CSR)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(99),
			Subject:      csr.Subject,
			DNSNames:     csr.DNSNames,
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, csr.PublicKey, caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		issuedCertMu.Lock()
		issuedCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		issuedCertMu.Unlock()

		nextNonce(w)
		w.Header().Set("Location", "https://"+r.Host+"/order/1")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"identifiers": []map[string]string{{"type": "dns", "value": "home.bobo.hogman"}},
			"certificate": "https://" + r.Host + "/cert/1",
		})
	})
	fbMux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		issuedCertMu.Lock()
		defer issuedCertMu.Unlock()
		_, _ = w.Write(issuedCertPEM)
	})
	fallback := httptest.NewTLSServer(fbMux)
	t.Cleanup(fallback.Close)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	var caPEM []byte
	caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: primary.Certificate().Raw})...)
	caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fallback.Certificate().Raw})...)
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	newMgr := func(backend *stubACMEBackend) *HomeCertManager {
		mgr, err := NewHomeCertManager(HomeConfig{
			Zone:       "bobo.hogman",
			HomeTLSDir: filepath.Join(t.TempDir(), "tls"),
			StorageDir: filepath.Join(t.TempDir(), "acme"),
			PrimaryCA:  primary.URL + "/dir",
			FallbackCA: fallback.URL + "/dir",
			CARootFile: caFile,
			Backend:    backend,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(mgr.Close)
		return mgr
	}

	// Non-failover 403 must return fast without hitting fallback or MintEAB.
	orderStatus.Store(http.StatusForbidden)
	b403 := &stubACMEBackend{}
	mgr403 := newMgr(b403)
	start := time.Now()
	if err := mgr403.EnsureOnce(context.Background()); err == nil {
		t.Fatal("expected 403 error from primary CA")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("403 EnsureOnce stalled too long (%s)", elapsed)
	}
	if b403.eabHits != 0 || fbAcctHits.Load() != 0 {
		t.Fatalf("403 triggered fallback unexpectedly: eabHits=%d fbAcct=%d", b403.eabHits, fbAcctHits.Load())
	}

	// Primary 429 must fail over immediately, mint EAB once, and export fallback cert.
	orderStatus.Store(http.StatusTooManyRequests)
	b429 := &stubACMEBackend{}
	mgr429 := newMgr(b429)
	start = time.Now()
	if err := mgr429.EnsureOnce(context.Background()); err != nil {
		t.Fatalf("429 EnsureOnce failover failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("429 EnsureOnce stalled too long (%s)", elapsed)
	}
	if b429.eabHits != 1 || fbAcctHits.Load() != 1 {
		t.Fatalf("expected 1 fallback EAB/acct registration, got eabHits=%d fbAcct=%d", b429.eabHits, fbAcctHits.Load())
	}
	if err := VerifyHomeTLS(mgr429.cfg.HomeTLSDir); err != nil {
		t.Fatalf("VerifyHomeTLS after failover: %v", err)
	}
}

// 4b: the same manager keeps the front door's wildcard, under its own name
// and file names, with no pen zone at all.
func TestCertManagerHostAndFileBase(t *testing.T) {
	dir := t.TempDir()
	m, err := NewHomeCertManager(HomeConfig{
		Host:       "*.gate.example.test.",
		FileBase:   "gate",
		HomeTLSDir: filepath.Join(dir, "tls"),
		StorageDir: filepath.Join(dir, "acme"),
		Backend:    noopACMEBackend{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if m.host != "*.gate.example.test" {
		t.Fatalf("host = %q", m.host)
	}
	if m.cfg.Email != "" {
		t.Fatalf("email = %q, want empty", m.cfg.Email)
	}

	certPEM, keyPEM := selfSignedPair(t, "*.gate.example.test")
	if err := writeTLSFilesAtomic(m.cfg.HomeTLSDir, m.cfg.FileBase, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTLSFiles(m.cfg.HomeTLSDir, "gate"); err != nil {
		t.Fatalf("gate files: %v", err)
	}
	if VerifyHomeTLS(m.cfg.HomeTLSDir) == nil {
		t.Fatal("home files reported valid, but only gate files were written")
	}
	if fi, err := os.Stat(filepath.Join(m.cfg.HomeTLSDir, "gate.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("gate.key mode: %v %v", fi, err)
	}

	// Without Host it's still home.<zone>, as before.
	h, err := NewHomeCertManager(HomeConfig{Zone: "bobo.pens.example.test", HomeTLSDir: filepath.Join(dir, "h"),
		StorageDir: filepath.Join(dir, "ha"), Backend: noopACMEBackend{}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if h.host != "home.bobo.pens.example.test" || h.cfg.FileBase != "home" {
		t.Fatalf("default host/base = %q/%q", h.host, h.cfg.FileBase)
	}
}

type noopACMEBackend struct{}

func (noopACMEBackend) SetTXT(context.Context, string, string) error    { return nil }
func (noopACMEBackend) DeleteTXT(context.Context, string, string) error { return nil }
func (noopACMEBackend) MintEAB(context.Context) (*EABPair, error)       { return nil, nil }

func selfSignedPair(t *testing.T, name string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func TestPublicCertNetworkInfoAndLinks(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(filepath.Join(dir, "registrar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.db.Close() })
	hs := newFakeHeadscale(t)
	pubSvc, err := NewService(Config{
		Zone:       "bobo.pens.example.com",
		PublicHost: "bobo.gate.example.com",
		CoreIP:     "100.64.0.1",
	}, st, NewHeadscale(hs.srv.URL, "test-key"))
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
	PublicHandler(pubSvc).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /hogman/v1/network status = %d", rec.Code)
	}
	rawJSON := rec.Body.String()
	if !strings.Contains(rawJSON, `"cert_mode":"public"`) || strings.Contains(rawJSON, "root_fingerprint") || strings.Contains(rawJSON, "root_ca") || strings.Contains(rawJSON, `"pens_zone"`) {
		t.Fatalf("unexpected /hogman/v1/network payload: %s", rawJSON)
	}
}

func TestRegistrarACMEEmptyEmailNoPrompt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Keep a live open pipe on stdin to catch any unexpected interactive prompt.
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = wPipe.Close()
		_ = rPipe.Close()
	}()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegistrarACMENoPromptSubprocess$")
	cmd.Stdin = rPipe
	cmd.Env = append(os.Environ(), "HOGMAN_REGISTRAR_NO_PROMPT_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("empty-email ACME subprocess failed: %v\n%s", err, out)
	}
	text := string(out)
	if strings.Contains(text, "Email address") || strings.Contains(text, "Your sites will be served") {
		t.Fatalf("CertMagic prompted interactively on empty email:\n%s", text)
	}
}

func TestRegistrarACMENoPromptSubprocess(t *testing.T) {
	if os.Getenv("HOGMAN_REGISTRAR_NO_PROMPT_HELPER") != "1" {
		t.Skip("helper subprocess for TestRegistrarACMEEmptyEmailNoPrompt")
	}

	const host = "*.gate.example.test"
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "registrar-no-email-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	var issuedMu sync.Mutex
	var issuedPEM []byte
	var acctHits atomic.Int32
	var nonceSeq atomic.Int64
	nextNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("np-nonce-%d", nonceSeq.Add(1)))
		w.Header().Set("Cache-Control", "no-store")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/acct",
			"newOrder":   base + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/acct", func(w http.ResponseWriter, r *http.Request) {
		acctHits.Add(1)
		nextNonce(w)
		var jws struct {
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var acctPayload struct {
			Contact []string `json:"contact"`
		}
		if err := json.Unmarshal(raw, &acctPayload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(acctPayload.Contact) != 0 {
			t.Errorf("expected empty contact list, got %v", acctPayload.Contact)
			http.Error(w, "unexpected ACME contact", http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "https://"+r.Host+"/acct/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.Header().Set("Location", "https://"+r.Host+"/order/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      "ready",
			"identifiers": []map[string]string{{"type": "dns", "value": host}},
			"finalize":    "https://" + r.Host + "/finalize",
		})
	})
	mux.HandleFunc("/finalize", func(w http.ResponseWriter, r *http.Request) {
		var jws struct {
			Payload string `json:"payload"`
		}
		_ = json.NewDecoder(r.Body).Decode(&jws)
		raw, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
		var fin struct {
			CSR string `json:"csr"`
		}
		_ = json.Unmarshal(raw, &fin)
		csrDER, _ := base64.RawURLEncoding.DecodeString(fin.CSR)
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(101),
			Subject:      csr.Subject,
			DNSNames:     csr.DNSNames,
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(48 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, csr.PublicKey, caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		issuedMu.Lock()
		issuedPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		issuedMu.Unlock()
		nextNonce(w)
		w.Header().Set("Location", "https://"+r.Host+"/order/1")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"identifiers": []map[string]string{{"type": "dns", "value": host}},
			"certificate": "https://" + r.Host + "/cert/1",
		})
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		issuedMu.Lock()
		defer issuedMu.Unlock()
		_, _ = w.Write(issuedPEM)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	tmp := t.TempDir()
	caFile := filepath.Join(tmp, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tlsDir := filepath.Join(tmp, "tls")
	storeDir := filepath.Join(tmp, "acme")

	cfg := HomeConfig{
		Host:       host,
		FileBase:   "gate",
		HomeTLSDir: tlsDir,
		StorageDir: storeDir,
		PrimaryCA:  srv.URL + "/dir",
		CARootFile: caFile,
		Backend:    noopACMEBackend{},
	}
	mgr1, err := NewHomeCertManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if mgr1.cfg.Email != "" {
		mgr1.Close()
		t.Fatalf("expected empty email default, got %q", mgr1.cfg.Email)
	}
	if err := mgr1.EnsureOnce(context.Background()); err != nil {
		mgr1.Close()
		t.Fatalf("EnsureOnce with empty email failed: %v", err)
	}
	mgr1.Close()

	if err := VerifyTLSFiles(tlsDir, "gate"); err != nil {
		t.Fatalf("VerifyTLSFiles: %v", err)
	}
	if acctHits.Load() != 1 {
		t.Fatalf("expected 1 ACME /acct registration, got %d", acctHits.Load())
	}

	mgr2, err := NewHomeCertManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr2.Close()
	if err := mgr2.EnsureOnce(context.Background()); err != nil {
		t.Fatalf("restarted EnsureOnce failed: %v", err)
	}
	if acctHits.Load() != 1 {
		t.Fatalf("restart hit /acct unexpectedly: %d", acctHits.Load())
	}
}

// Run stops the cache when it returns and callers also defer Close; a second
// certmagic Cache.Stop panics ("close of closed channel"), which crashed the
// gate-cert service and pen registrars on every shutdown.
func TestHomeCertManagerCloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	m, err := NewHomeCertManager(HomeConfig{Zone: "bobo.pens.example.test", HomeTLSDir: filepath.Join(dir, "h"),
		StorageDir: filepath.Join(dir, "a"), Backend: noopACMEBackend{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Run returns at once, stopping the cache on the way out
	m.Run(ctx)
	m.Close()
	m.Close()
}

func TestVerifyTLSFilesUsesBaseInErrors(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := makeSelfSignedPEM(t, "*.gate.example.test", time.Now().Add(-time.Hour))
	if err := writeTLSFilesAtomic(dir, "gate", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	err := VerifyTLSFiles(dir, "gate")
	if err == nil || !strings.Contains(err.Error(), "gate certificate expired at") {
		t.Fatalf("VerifyTLSFiles(gate) = %v, want error naming gate certificate", err)
	}
}

func TestHomeCertManagerHandleFailoverRenewOnlyCap(t *testing.T) {
	dir := t.TempDir()
	tlsDir := filepath.Join(dir, "tls")
	billingPath := filepath.Join(dir, "billing-status.json")
	if err := os.WriteFile(billingPath, []byte(`{"state":"renew_only"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var fbHits atomic.Int32
	fbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fbHits.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer fbSrv.Close()

	m, err := NewHomeCertManager(HomeConfig{
		Zone:              "bobo.pens.example.test",
		HomeTLSDir:        tlsDir,
		StorageDir:        filepath.Join(dir, "acme"),
		PrimaryCA:         "http://127.0.0.1:1/dir",
		FallbackCA:        fbSrv.URL + "/dir",
		BillingStatusPath: billingPath,
		Backend:           &stubACMEBackend{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// Valid on-disk cert (>= 1h remaining) during renew-only wake: failover skips CA entirely.
	certPEM, keyPEM := makeSelfSignedPEM(t, "home.bobo.pens.example.test", time.Now().Add(24*time.Hour))
	if err := writeHomeTLSAtomic(tlsDir, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	m.handleFailover(context.Background())
	if fbHits.Load() != 0 {
		t.Fatalf("handleFailover touched fallback CA despite valid cert on disk: hits=%d", fbHits.Load())
	}

	// Seed an expired managed primary cert into storage AND m.cache (the real
	// production precondition when background renewal emits cert_failed).
	// Calling handleFailover must bypass ManageSync's shared-cache short-circuit
	// and actually contact the fallback CA once, then enforce the 1-per-wake cap.
	expCertPEM, expKeyPEM := makeSelfSignedPEM(t, "home.bobo.pens.example.test", time.Now().Add(-time.Hour))
	if err := writeHomeTLSAtomic(tlsDir, expCertPEM, expKeyPEM); err != nil {
		t.Fatal(err)
	}
	pCertKey := certmagic.StorageKeys.SiteCert(m.primaryIss.IssuerKey(), m.host)
	pPrivKey := certmagic.StorageKeys.SitePrivateKey(m.primaryIss.IssuerKey(), m.host)
	pMetaKey := certmagic.StorageKeys.SiteMeta(m.primaryIss.IssuerKey(), m.host)
	if err := m.storage.Store(context.Background(), pCertKey, expCertPEM); err != nil {
		t.Fatal(err)
	}
	if err := m.storage.Store(context.Background(), pPrivKey, expKeyPEM); err != nil {
		t.Fatal(err)
	}
	if err := m.storage.Store(context.Background(), pMetaKey, []byte(`{"sans":["home.bobo.pens.example.test"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.syncStoredCert(context.Background(), m.primaryCfg, m.primaryIss); err != nil {
		t.Fatalf("seed primary cert in cache: %v", err)
	}
	m.handleFailover(context.Background())
	afterFirst := fbHits.Load()
	if afterFirst == 0 {
		t.Fatal("expected first failover attempt with cached expired primary cert to reach fallback CA")
	}
	m.handleFailover(context.Background())
	if fbHits.Load() != afterFirst {
		t.Fatalf("second failover in same renew-only wake bypassed 1-per-wake cap: hits=%d -> %d", afterFirst, fbHits.Load())
	}

	// Synchronous ForceRenew failure on primary must NOT enqueue a stale token on failoverCh.
	_ = m.ForceRenew(context.Background())
	select {
	case <-m.failoverCh:
		t.Fatal("synchronous ForceRenew leaked a stale token into failoverCh")
	default:
	}
}
