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
	return &EABPair{KID: "test-kid", HMACB64URL: "dGVzdC1tYWM"}, nil
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

func aliceSrvMember(t *testing.T, e *testEnv, handle string) *Member {
	t.Helper()
	m, err := e.st.MemberByHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

type fakeCertmagicIssuer struct {
	key  string
	cert *certmagic.IssuedCertificate
	err  error
	hits atomic.Int32
}

func (f *fakeCertmagicIssuer) IssuerKey() string { return f.key }

func (f *fakeCertmagicIssuer) Issue(context.Context, *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	f.hits.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return f.cert, nil
}

func TestShouldFailoverAndFailoverIssuer(t *testing.T) {
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

	okCert := &certmagic.IssuedCertificate{Certificate: []byte("cert")}
	var fbInits atomic.Int32
	primary := &fakeCertmagicIssuer{key: "primary", cert: okCert}
	fb := &fakeCertmagicIssuer{key: "fallback", cert: okCert}
	iss := &FailoverIssuer{
		Primary: primary,
		FallbackFactory: func(context.Context) (certmagic.Issuer, error) {
			fbInits.Add(1)
			return fb, nil
		},
	}

	// Primary succeeds: fallback never touched.
	if got, err := iss.Issue(context.Background(), nil); err != nil || got != okCert || fbInits.Load() != 0 {
		t.Fatalf("primary success path failed: got=%v err=%v fbInits=%d", got, err, fbInits.Load())
	}

	// DNS error: fallback never touched.
	primary.err = acme.Problem{Type: "urn:ietf:params:acme:error:dns", Status: http.StatusBadRequest}
	if _, err := iss.Issue(context.Background(), nil); err == nil || fbInits.Load() != 0 || fb.hits.Load() != 0 {
		t.Fatalf("DNS failure wrongly triggered fallback: err=%v fbInits=%d hits=%d", err, fbInits.Load(), fb.hits.Load())
	}

	// 429 rateLimited: lazy fallback initializes once and succeeds cleanly.
	primary.err = acme.Problem{Type: "urn:ietf:params:acme:error:rateLimited", Status: http.StatusTooManyRequests}
	if got, err := iss.Issue(context.Background(), nil); err != nil || got != okCert || fbInits.Load() != 1 || fb.hits.Load() != 1 {
		t.Fatalf("429 failover failed: got=%v err=%v fbInits=%d hits=%d", got, err, fbInits.Load(), fb.hits.Load())
	}
	if _, err := iss.Issue(context.Background(), nil); err != nil || fbInits.Load() != 1 || fb.hits.Load() != 2 {
		t.Fatalf("second 429 reused factory unexpectedly: err=%v fbInits=%d hits=%d", err, fbInits.Load(), fb.hits.Load())
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
