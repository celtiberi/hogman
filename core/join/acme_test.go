package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/mholt/acmez/v3/acme"

	"hogman/join/internal/penapi"
)

func newTLSServerForHost(t *testing.T, host string, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func homeMeshTestClient(srv *httptest.Server, penZone string) *http.Client {
	leaf, err := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	addr := srv.Listener.Addr().String()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, network, reqAddr string) (net.Conn, error) {
				if reqAddr == "home."+penZone+":443" {
					return dialer.DialContext(ctx, network, addr)
				}
				return dialer.DialContext(ctx, network, reqAddr)
			},
		},
	}
}

func TestMeshTXTProviderStripsPrefixAndZone(t *testing.T) {
	const penZone = "bobo.pens.example.com"

	type txtCall struct {
		Method string
		Name   string
		Value  string
	}
	var mu sync.Mutex
	var calls []txtCall
	var failOnBlog atomic.Bool
	var hits int

	srv := newTLSServerForHost(t, "home."+penZone, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/acme/txt" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		hits++
		calls = append(calls, txtCall{Method: r.Method, Name: body.Name, Value: body.Value})
		mu.Unlock()

		if r.Method == http.MethodPost && failOnBlog.Load() && body.Name == "blog" {
			http.Error(w, `{"error":"rate limit"}`, http.StatusTooManyRequests)
			return
		}
		if r.Method == http.MethodDelete && body.Name == "missing" {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	p := &meshTXTProvider{
		hc:      homeMeshTestClient(srv, penZone),
		penZone: penZone,
	}
	ctx := context.Background()

	// Zone matching pen zone directly: strips "_acme-challenge." and "."+penZone.
	recs, err := p.AppendRecords(ctx, penZone+".", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.photos", Text: "token_photos_012345"},
	})
	if err != nil || len(recs) != 1 {
		t.Fatalf("AppendRecords photos failed: recs=%v err=%v", recs, err)
	}

	// Sub-name when CertMagic passes parent zone.
	if _, err := p.AppendRecords(ctx, "pens.example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.blog.photos.bobo", Text: "token_sub_012345"},
	}); err != nil {
		t.Fatalf("AppendRecords sub-name failed: %v", err)
	}

	// Delete strips prefix/zone cleanly and ignores 404.
	if _, err := p.DeleteRecords(ctx, penZone+".", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.photos", Text: "token_photos_012345"},
		libdns.TXT{Name: "_acme-challenge.missing", Text: "token_missing_0123"},
	}); err != nil {
		t.Fatalf("DeleteRecords failed: %v", err)
	}

	mu.Lock()
	got := append([]txtCall(nil), calls...)
	mu.Unlock()
	if len(got) != 4 {
		t.Fatalf("expected 4 HTTP calls, got %+v", got)
	}
	if got[0] != (txtCall{http.MethodPost, "photos", "token_photos_012345"}) ||
		got[1] != (txtCall{http.MethodPost, "blog.photos", "token_sub_012345"}) ||
		got[2] != (txtCall{http.MethodDelete, "photos", "token_photos_012345"}) ||
		got[3] != (txtCall{http.MethodDelete, "missing", "token_missing_0123"}) {
		t.Fatalf("unexpected TXT call sequence: %+v", got)
	}

	// Client-side guards reject out-of-zone or non-_acme-challenge names before any HTTP call.
	beforeHits := hits
	if _, err := p.AppendRecords(ctx, "pens.example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.photos.other", Text: "token"},
	}); err == nil {
		t.Fatal("expected out-of-zone record to fail")
	}
	if _, err := p.AppendRecords(ctx, penZone+".", []libdns.Record{
		libdns.TXT{Name: "photos", Text: "token"},
	}); err == nil {
		t.Fatal("expected missing _acme-challenge prefix to fail")
	}
	if hits != beforeHits {
		t.Fatalf("expected zero HTTP hits on rejected names, got %d extra", hits-beforeHits)
	}

	// Partial batch failure rolls back previously created records.
	failOnBlog.Store(true)
	if _, err := p.AppendRecords(ctx, penZone+".", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.alpha", Text: "val-a"},
		libdns.TXT{Name: "_acme-challenge.blog", Text: "val-b"},
	}); err == nil {
		t.Fatal("expected batch error when second record returns 429")
	}
	mu.Lock()
	last := calls[len(calls)-1]
	mu.Unlock()
	if last != (txtCall{http.MethodDelete, "alpha", "val-a"}) {
		t.Fatalf("expected rollback DELETE for alpha, got last call %+v", last)
	}
}

func TestShouldFailoverACME(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"canceled", context.Canceled, false},
		{"dns step wrapping registrar 429 cap", dnsStepError{err: &penapi.HomeAPIError{Status: http.StatusTooManyRequests, Msg: "weekly cap"}}, false},
		{"dns step wrapping acme 429", dnsStepError{err: acme.Problem{Status: http.StatusTooManyRequests}}, false},
		{"acme 429", acme.Problem{Status: http.StatusTooManyRequests}, true},
		{"acme rateLimited urn", acme.Problem{Status: http.StatusBadRequest, Type: "urn:ietf:params:acme:error:rateLimited"}, true},
		{"acme 503", acme.Problem{Status: http.StatusServiceUnavailable}, true},
		{"acme subproblem 500", acme.Problem{Status: http.StatusBadRequest, Subproblems: []acme.Subproblem{{Problem: acme.Problem{Status: http.StatusInternalServerError}}}}, true},
		{"acme 403 unauthorized", acme.Problem{Status: http.StatusForbidden, Type: "urn:ietf:params:acme:error:unauthorized"}, false},
		{"acme 400 malformed", acme.Problem{Status: http.StatusBadRequest, Type: "urn:ietf:params:acme:error:malformed"}, false},
		{"net error", &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, true},
		{"url transport error", &url.Error{Op: "Get", URL: "https://ca.example", Err: errors.New("eof")}, true},
		{"url canceled error", &url.Error{Op: "Get", URL: "https://ca.example", Err: context.Canceled}, false},
	}
	for _, tc := range cases {
		if got := shouldFailoverACME(tc.err); got != tc.want {
			t.Errorf("%s: shouldFailoverACME = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func verifyCertManagerHandshake(t *testing.T, cm *shareCertManager, serverName string, rootPool *x509.CertPool) *big.Int {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("share ok"))
	}))
	srv.TLS = cm.TLSConfig()
	srv.StartTLS()
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	c := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: serverName, RootCAs: rootPool},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
	resp, err := c.Get("https://" + serverName + "/")
	if err != nil {
		t.Fatalf("TLS request to %s failed: %v", serverName, err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatalf("missing peer certificate for %s", serverName)
	}
	return new(big.Int).Set(resp.TLS.PeerCertificates[0].SerialNumber)
}

func decodeACMEContacts(r *http.Request) ([]string, error) {
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return nil, err
	}
	var acctPayload struct {
		Contact []string `json:"contact"`
	}
	if err := json.Unmarshal(raw, &acctPayload); err != nil {
		return nil, err
	}
	return acctPayload.Contact, nil
}

func TestShareCertManagerMockACME(t *testing.T) {
	const (
		penZone   = "bobo.pens.example.com"
		shareHost = "photos.bobo.pens.example.com"
	)

	var (
		orderStatus  atomic.Int32
		primaryHits  atomic.Int32
		fallbackHits atomic.Int32
		txtCap429    atomic.Bool
		txtHits      atomic.Int32
		eabHits      atomic.Int32
	)
	orderStatus.Store(http.StatusTooManyRequests)

	nextNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", "nonce-1")
	}

	// Mock primary ACME CA: returns valid directory/new-account and configurable /order status
	// (either HTTP 403/429 failure, or "pending" order to exercise DNS TXT cap before Wait).
	priMux := http.NewServeMux()
	priMux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/acct",
			"newOrder":   base + "/order",
		})
	})
	priMux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.WriteHeader(http.StatusNoContent)
	})
	priMux.HandleFunc("/acct", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		contacts, err := decodeACMEContacts(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(contacts) != 0 {
			t.Errorf("primary /acct expected empty contact list, got %v", contacts)
			http.Error(w, "unexpected ACME contact", http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "https://"+r.Host+"/acct/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	priMux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		primaryHits.Add(1)
		st := int(orderStatus.Load())
		if st == http.StatusOK {
			w.Header().Set("Location", "https://"+r.Host+"/order/1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "pending",
				"identifiers":    []map[string]string{{"type": "dns", "value": shareHost}},
				"authorizations": []string{"https://" + r.Host + "/authz/1"},
				"finalize":       "https://" + r.Host + "/finalize/1",
			})
			return
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(st)
		errType := "urn:ietf:params:acme:error:unauthorized"
		if st == http.StatusTooManyRequests {
			errType = "urn:ietf:params:acme:error:rateLimited"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": errType, "detail": "primary status", "status": st})
	})
	priMux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "pending",
			"identifier": map[string]string{"type": "dns", "value": shareHost},
			"challenges": []map[string]any{{
				"type":   "dns-01",
				"url":    "https://" + r.Host + "/chall/1",
				"status": "pending",
				"token":  "chall_token_0123456789abcdef",
			}},
		})
	})
	primary := httptest.NewTLSServer(priMux)
	defer primary.Close()

	// Mock fallback ACME CA requiring EAB and issuing a real ECDSA leaf signed by caKey.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9001),
		Subject:               pkix.Name{CommonName: "Fallback Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	fbCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	var issuedMu sync.Mutex
	var issuedPEM []byte
	fbMux := http.NewServeMux()
	fbMux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/acct",
			"newOrder":   base + "/order",
			"meta":       map[string]any{"externalAccountRequired": true},
		})
	})
	fbMux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.WriteHeader(http.StatusNoContent)
	})
	fbMux.HandleFunc("/acct", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		fallbackHits.Add(1)
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
			Contact                []string        `json:"contact"`
			ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
		}
		if err := json.Unmarshal(raw, &acctPayload); err != nil || len(acctPayload.ExternalAccountBinding) == 0 {
			http.Error(w, "missing EAB", http.StatusForbidden)
			return
		}
		// Like Google: an account needs a contact. It must be the operator's
		// address handed out with the EAB, nothing else.
		if len(acctPayload.Contact) != 1 || acctPayload.Contact[0] != "mailto:ops@example.com" {
			t.Errorf("fallback /acct contact = %v, want [mailto:ops@example.com]", acctPayload.Contact)
			http.Error(w, `{"type":"urn:ietf:params:acme:error:malformed","detail":"Accounts must have at least one contact."}`, http.StatusBadRequest)
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
			"identifiers": []map[string]string{{"type": "dns", "value": shareHost}},
			"finalize":    "https://" + r.Host + "/finalize/1",
		})
	})
	fbMux.HandleFunc("/finalize/1", func(w http.ResponseWriter, r *http.Request) {
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
			SerialNumber: big.NewInt(777),
			Subject:      pkix.Name{CommonName: shareHost},
			DNSNames:     []string{shareHost},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(72 * time.Hour),
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
			"identifiers": []map[string]string{{"type": "dns", "value": shareHost}},
			"certificate": "https://" + r.Host + "/cert/1",
		})
	})
	fbMux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		issuedMu.Lock()
		defer issuedMu.Unlock()
		_, _ = w.Write(issuedPEM)
	})
	fallback := httptest.NewTLSServer(fbMux)
	defer fallback.Close()

	// Mock home.<penZone> mesh server serving /api/acme/txt and /api/acme/eab.
	meshSrv := newTLSServerForHost(t, "home."+penZone, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/acme/txt":
			txtHits.Add(1)
			if txtCap429.Load() {
				http.Error(w, `{"error":"weekly certificate name limit reached"}`, http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusCreated)
		case "/api/acme/eab":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
			if !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
				http.Error(w, `{"error":"Content-Type must be application/json"}`, http.StatusUnsupportedMediaType)
				return
			}
			eabHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"kid":         "share-eab-kid",
				"hmac_b64url": base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
				"contact":     "ops@example.com",
			})
		default:
			http.NotFound(w, r)
		}
	}))

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	var caPEM []byte
	caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: primary.Certificate().Raw})...)
	caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fallback.Certificate().Raw})...)
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	newMgr := func(storageDir string) *shareCertManager {
		cm, err := newShareCertManager(shareACMEConfig{
			Zone:       penZone,
			Host:       shareHost,
			StorageDir: storageDir,
			PrimaryCA:  primary.URL + "/dir",
			FallbackCA: fallback.URL + "/dir",
			CARootFile: caFile,
			HTTPClient: homeMeshTestClient(meshSrv, penZone),
		})
		if err != nil {
			t.Fatal(err)
		}
		cm.backoff = []time.Duration{5 * time.Millisecond}
		return cm
	}

	// 1. Primary 403 must NOT fail over or call /api/acme/eab, and EnsureWithBackoff stops quickly.
	orderStatus.Store(http.StatusForbidden)
	cm403 := newMgr(t.TempDir())
	if err := cm403.EnsureWithBackoff(context.Background()); err == nil {
		cm403.Close()
		t.Fatal("expected 403 error from primary CA")
	}
	cm403.Close()
	if eabHits.Load() != 0 || fallbackHits.Load() != 0 {
		t.Fatalf("403 triggered fallback: eabHits=%d fbHits=%d", eabHits.Load(), fallbackHits.Load())
	}

	// 2. Registrar /api/acme/txt 429 cap (dnsStepError) must NOT fail over or mint EAB,
	//    and must persist backoff state without in-process retry bursts.
	orderStatus.Store(http.StatusOK)
	txtCap429.Store(true)
	txtBeforeCap := txtHits.Load()
	cmCap := newMgr(t.TempDir())
	if err := cmCap.EnsureWithBackoff(context.Background()); err == nil {
		cmCap.Close()
		t.Fatal("expected TXT 429 error")
	}
	if txtHits.Load()-txtBeforeCap != 1 {
		cmCap.Close()
		t.Fatalf("registrar TXT 429 cap made %d attempts, want 1", txtHits.Load()-txtBeforeCap)
	}
	if st := cmCap.loadRetryState(); st.Failures != 1 || st.NextAttempt.IsZero() {
		cmCap.Close()
		t.Fatalf("registrar TXT 429 cap did not record backoff state: %+v", st)
	}
	cmCap.Close()
	if eabHits.Load() != 0 || fallbackHits.Load() != 0 {
		t.Fatalf("registrar TXT 429 cap triggered fallback unexpectedly: eabHits=%d fbHits=%d", eabHits.Load(), fallbackHits.Load())
	}

	// 3. Primary ACME 429 fails over immediately, mints EAB once, and serves valid fallback cert.
	txtCap429.Store(false)
	orderStatus.Store(http.StatusTooManyRequests)
	persistDir := filepath.Join(t.TempDir(), "acme")
	cm429 := newMgr(persistDir)
	if err := cm429.Ensure(context.Background()); err != nil {
		cm429.Close()
		t.Fatalf("429 failover failed: %v", err)
	}
	if eabHits.Load() != 1 || fallbackHits.Load() != 1 {
		cm429.Close()
		t.Fatalf("expected 1 EAB/fallback registration, got eab=%d fb=%d", eabHits.Load(), fallbackHits.Load())
	}
	fbPool := x509.NewCertPool()
	fbPool.AddCert(fbCA)
	serial1 := verifyCertManagerHandshake(t, cm429, shareHost, fbPool)
	cm429.Close()

	// 4. Restarting with the same <dir>/acme cache reuses the cert with zero CA/EAB/TXT calls.
	priBefore := primaryHits.Load()
	fbBefore := fallbackHits.Load()
	eabBefore := eabHits.Load()
	txtBefore := txtHits.Load()
	cmRestart := newMgr(persistDir)
	defer cmRestart.Close()
	if err := cmRestart.Ensure(context.Background()); err != nil {
		t.Fatalf("restarted Ensure failed: %v", err)
	}
	serial2 := verifyCertManagerHandshake(t, cmRestart, shareHost, fbPool)
	if serial1.Cmp(serial2) != 0 {
		t.Fatalf("restart obtained new cert serial %v instead of cached %v", serial2, serial1)
	}
	if primaryHits.Load() != priBefore || fallbackHits.Load() != fbBefore ||
		eabHits.Load() != eabBefore || txtHits.Load() != txtBefore {
		t.Fatalf("restart hit CA/mesh unexpectedly: pri=%d->%d fb=%d->%d eab=%d->%d txt=%d->%d",
			priBefore, primaryHits.Load(), fbBefore, fallbackHits.Load(),
			eabBefore, eabHits.Load(), txtBefore, txtHits.Load())
	}
}

func TestSharePublicCertPebbleE2E(t *testing.T) {
	if os.Getenv("HOGMAN_PEBBLE_E2E") != "1" {
		t.Skip("set HOGMAN_PEBBLE_E2E=1 inside the ACME Pebble Compose network to run")
	}

	mustEnv := func(k string) string {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			t.Fatalf("missing required env %s", k)
		}
		return v
	}
	readPool := func(path string) *x509.CertPool {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM(b) {
			t.Fatalf("invalid PEM in %s", path)
		}
		return p
	}

	zone := mustEnv("ACME_ZONE")
	meshSock := mustEnv("ACME_MESH_SOCK")
	serverIP := mustEnv("ACME_SERVER_IP")
	pebble1URL := mustEnv("ACME_PEBBLE1_CA_URL")
	pebble2URL := mustEnv("ACME_PEBBLE2_CA_URL")
	mock429URL := mustEnv("ACME_MOCK429_CA_URL")
	caRoot := mustEnv("ACME_CA_ROOT")
	pebble1Pool := readPool(mustEnv("ACME_PEBBLE1_ROOT"))
	pebble2Pool := readPool(mustEnv("ACME_PEBBLE2_ROOT"))
	resolver := mustEnv("ACME_RESOLVER")
	statsURL := mustEnv("ACME_STATS_URL")

	type stats struct {
		TXTWrites     int                 `json:"txt_writes"`
		EABCount      int                 `json:"eab_count"`
		DistinctFQDNs int                 `json:"distinct_fqdns"`
		Live          map[string][]string `json:"live"`
	}
	getStats := func() stats {
		resp, err := http.Get(statsURL)
		if err != nil {
			t.Fatalf("GET %s: %v", statsURL, err)
		}
		defer resp.Body.Close()
		var st stats
		if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
			t.Fatalf("decode stats: %v", err)
		}
		return st
	}

	// Simulate the share's mesh http.Client routing https://home.<zone>/api/...
	// to the live registrar mesh Unix socket with the share server's mesh IP.
	meshClient := func(xff string) *http.Client {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		unixTr := &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", meshSock)
			},
		}
		return &http.Client{
			Timeout: 20 * time.Second,
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				cloned := req.Clone(req.Context())
				cloned.URL.Scheme = "http"
				cloned.URL.Host = "localhost"
				cloned.Host = "localhost"
				cloned.Header.Set("X-Forwarded-For", xff)
				return unixTr.RoundTrip(cloned)
			}),
		}
	}

	ctx := context.Background()

	// 1. Obtain photos.<zone> via Pebble1 through live registrar /api/acme/txt + fake-challengedns.
	photosHost := "photos." + zone
	photosDir := filepath.Join(t.TempDir(), "acme-photos")
	before := getStats()
	cm1, err := newShareCertManager(shareACMEConfig{
		Zone:               zone,
		Host:               photosHost,
		StorageDir:         photosDir,
		PrimaryCA:          pebble1URL,
		CARootFile:         caRoot,
		Resolvers:          []string{resolver},
		PropagationDelay:   100 * time.Millisecond,
		PropagationTimeout: 15 * time.Second,
		HTTPClient:         meshClient(serverIP),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cm1.Ensure(ctx); err != nil {
		cm1.Close()
		t.Fatalf("pebble1 share Ensure failed: %v", err)
	}
	serial1 := verifyCertManagerHandshake(t, cm1, photosHost, pebble1Pool)
	cm1.Close()

	afterPhotos := getStats()
	if afterPhotos.EABCount != before.EABCount {
		t.Fatalf("happy path minted fallback EAB: before=%+v after=%+v", before, afterPhotos)
	}
	if afterPhotos.TXTWrites <= before.TXTWrites || len(afterPhotos.Live) != 0 {
		t.Fatalf("unexpected DNS TXT stats after issuance: before=%+v after=%+v", before, afterPhotos)
	}

	// 2. Restarting on the same storage dir reuses cached cert without new TXT writes or orders.
	cm2, err := newShareCertManager(shareACMEConfig{
		Zone:               zone,
		Host:               photosHost,
		StorageDir:         photosDir,
		PrimaryCA:          pebble1URL,
		CARootFile:         caRoot,
		Resolvers:          []string{resolver},
		PropagationDelay:   100 * time.Millisecond,
		PropagationTimeout: 15 * time.Second,
		HTTPClient:         meshClient(serverIP),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cm2.Ensure(ctx); err != nil {
		cm2.Close()
		t.Fatalf("restarted Ensure failed: %v", err)
	}
	serial2 := verifyCertManagerHandshake(t, cm2, photosHost, pebble1Pool)
	cm2.Close()
	if serial1.Cmp(serial2) != 0 {
		t.Fatalf("restart changed cert serial: %v -> %v", serial1, serial2)
	}
	afterRestart := getStats()
	if afterRestart.TXTWrites != afterPhotos.TXTWrites {
		t.Fatalf("restart performed unexpected TXT writes: %d -> %d", afterPhotos.TXTWrites, afterRestart.TXTWrites)
	}

	// 3. Unowned name fails on registrar /api/acme/txt (403) without failing over or minting EAB.
	cmDenied, err := newShareCertManager(shareACMEConfig{
		Zone:               zone,
		Host:               "other." + zone,
		StorageDir:         filepath.Join(t.TempDir(), "acme-denied"),
		PrimaryCA:          pebble1URL,
		FallbackCA:         pebble2URL,
		CARootFile:         caRoot,
		Resolvers:          []string{resolver},
		PropagationDelay:   100 * time.Millisecond,
		PropagationTimeout: 10 * time.Second,
		HTTPClient:         meshClient(serverIP),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmDenied.Ensure(ctx); err == nil {
		cmDenied.Close()
		t.Fatal("expected unowned share name to fail")
	}
	cmDenied.Close()
	if stDenied := getStats(); stDenied.EABCount != before.EABCount {
		t.Fatalf("unowned name 403 triggered EAB mint: %+v", stDenied)
	}

	// 4. Primary HTTP 429 fails over to Pebble2 via lazy POST /api/acme/eab, and restart reuses cert.
	fbHost := "sharefb." + zone
	fbDir := filepath.Join(t.TempDir(), "acme-fb")
	cmFB, err := newShareCertManager(shareACMEConfig{
		Zone:               zone,
		Host:               fbHost,
		StorageDir:         fbDir,
		PrimaryCA:          mock429URL,
		FallbackCA:         pebble2URL,
		CARootFile:         caRoot,
		Resolvers:          []string{resolver},
		PropagationDelay:   100 * time.Millisecond,
		PropagationTimeout: 15 * time.Second,
		HTTPClient:         meshClient(serverIP),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmFB.Ensure(ctx); err != nil {
		cmFB.Close()
		t.Fatalf("mock429 -> pebble2 share failover failed: %v", err)
	}
	fbSerial1 := verifyCertManagerHandshake(t, cmFB, fbHost, pebble2Pool)
	// Verify cert fails against Pebble1 root before testing restart cache reuse.
	badSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	badSrv.TLS = cmFB.TLSConfig()
	badSrv.StartTLS()
	badAddr := badSrv.Listener.Addr().String()
	badClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: fbHost, RootCAs: pebble1Pool},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, badAddr)
			},
		},
	}
	if _, err := badClient.Get("https://" + fbHost + "/"); err == nil {
		badSrv.Close()
		t.Fatal("expected pebble2 fallback cert to fail verification against pebble1 root")
	}
	badSrv.Close()

	cmFB.Close()

	afterFB := getStats()
	if afterFB.EABCount != before.EABCount+1 {
		t.Fatalf("expected 1 fallback EAB mint, got before=%+v after=%+v", before, afterFB)
	}
	cmFBRestart, err := newShareCertManager(shareACMEConfig{
		Zone:               zone,
		Host:               fbHost,
		StorageDir:         fbDir,
		PrimaryCA:          mock429URL,
		FallbackCA:         pebble2URL,
		CARootFile:         caRoot,
		Resolvers:          []string{resolver},
		PropagationDelay:   100 * time.Millisecond,
		PropagationTimeout: 15 * time.Second,
		HTTPClient:         meshClient(serverIP),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cmFBRestart.Close()
	if err := cmFBRestart.Ensure(ctx); err != nil {
		t.Fatalf("fallback restart Ensure failed: %v", err)
	}
	fbSerial2 := verifyCertManagerHandshake(t, cmFBRestart, fbHost, pebble2Pool)
	if fbSerial1.Cmp(fbSerial2) != 0 {
		t.Fatalf("fallback restart changed serial: %v -> %v", fbSerial1, fbSerial2)
	}
	afterFBRestart := getStats()
	if afterFBRestart.EABCount != afterFB.EABCount || afterFBRestart.TXTWrites != afterFB.TXTWrites {
		t.Fatalf("fallback restart hit EAB or TXT unexpectedly: before=%+v after=%+v", afterFB, afterFBRestart)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type mockLeafACMEServer struct {
	srv       *httptest.Server
	caPool    *x509.CertPool
	caFile    string
	acctHits  atomic.Int32
	orderHits atomic.Int32
	failOrder atomic.Bool
}

func newMockLeafACMEServer(t *testing.T, host string) *mockLeafACMEServer {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(5001),
		Subject:               pkix.Name{CommonName: "Share Mock CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	m := &mockLeafACMEServer{caPool: caPool}
	var issuedMu sync.Mutex
	var issuedPEM []byte
	nextNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", "mock-nonce")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/acct",
			"newOrder":   base + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/acct", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		m.acctHits.Add(1)
		contacts, err := decodeACMEContacts(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(contacts) != 0 {
			t.Errorf("expected empty contact list, got %v", contacts)
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
		m.orderHits.Add(1)
		if m.failOrder.Load() {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":   "urn:ietf:params:acme:error:rateLimited",
				"detail": "temporary CA rate limit",
				"status": http.StatusTooManyRequests,
			})
			return
		}
		w.Header().Set("Location", "https://"+r.Host+"/order/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      "ready",
			"identifiers": []map[string]string{{"type": "dns", "value": host}},
			"finalize":    "https://" + r.Host + "/finalize/1",
		})
	})
	mux.HandleFunc("/finalize/1", func(w http.ResponseWriter, r *http.Request) {
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
			SerialNumber: big.NewInt(888),
			Subject:      pkix.Name{CommonName: host},
			DNSNames:     []string{host},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(72 * time.Hour),
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

	m.srv = httptest.NewTLSServer(mux)
	t.Cleanup(m.srv.Close)
	m.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(m.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestShareACMEEmptyEmailNoPrompt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Keep a live open pipe on stdin so any interactive CertMagic prompt blocks or prints.
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = wPipe.Close()
		_ = rPipe.Close()
	}()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestShareACMENoPromptSubprocess$")
	cmd.Stdin = rPipe
	cmd.Env = append(os.Environ(), "HOGMAN_ACME_NO_PROMPT_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("empty-email share ACME subprocess failed: %v\n%s", err, out)
	}
	text := string(out)
	if strings.Contains(text, "Email address") || strings.Contains(text, "Your sites will be served") {
		t.Fatalf("CertMagic prompted interactively on empty email:\n%s", text)
	}
}

func TestShareACMENoPromptSubprocess(t *testing.T) {
	if os.Getenv("HOGMAN_ACME_NO_PROMPT_HELPER") != "1" {
		t.Skip("helper subprocess for TestShareACMEEmptyEmailNoPrompt")
	}

	const (
		penZone   = "bobo.pens.example.com"
		shareHost = "photos.bobo.pens.example.com"
	)
	t.Setenv("HOGMAN_ACME_EMAIL", "")
	storageDir := filepath.Join(t.TempDir(), "acme")
	ca := newMockLeafACMEServer(t, shareHost)

	cfg := shareACMEConfigFromEnv(penZone, shareHost, storageDir, &http.Client{Timeout: 5 * time.Second})
	if cfg.Email != "" {
		t.Fatalf("shareACMEConfigFromEnv Email = %q, want empty", cfg.Email)
	}
	cfg.PrimaryCA = ca.srv.URL + "/dir"
	cfg.FallbackCA = ""
	cfg.CARootFile = ca.caFile

	cm1, err := newShareCertManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cm1.Ensure(context.Background()); err != nil {
		cm1.Close()
		t.Fatalf("Ensure with empty email failed: %v", err)
	}
	serial1 := verifyCertManagerHandshake(t, cm1, shareHost, ca.caPool)
	cm1.Close()
	if ca.acctHits.Load() != 1 || ca.orderHits.Load() != 1 {
		t.Fatalf("expected 1 acct and 1 order call, got acct=%d order=%d", ca.acctHits.Load(), ca.orderHits.Load())
	}

	cm2, err := newShareCertManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cm2.Close()
	if err := cm2.Ensure(context.Background()); err != nil {
		t.Fatalf("restarted Ensure failed: %v", err)
	}
	serial2 := verifyCertManagerHandshake(t, cm2, shareHost, ca.caPool)
	if serial1.Cmp(serial2) != 0 {
		t.Fatalf("restart changed cert serial: %v -> %v", serial1, serial2)
	}
	if ca.acctHits.Load() != 1 || ca.orderHits.Load() != 1 {
		t.Fatalf("restart hit CA unexpectedly: acct=%d order=%d", ca.acctHits.Load(), ca.orderHits.Load())
	}
}

func TestShareACMEPersistentBackoffAcrossRestarts(t *testing.T) {
	const (
		penZone   = "bobo.pens.example.com"
		shareHost = "photos.bobo.pens.example.com"
	)
	ca := newMockLeafACMEServer(t, shareHost)
	ca.failOrder.Store(true)

	storageDir := filepath.Join(t.TempDir(), "acme")
	fakeNow := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	var waits []time.Duration

	newMgr := func(withFakeWait bool) *shareCertManager {
		cm, err := newShareCertManager(shareACMEConfig{
			Zone:       penZone,
			Host:       shareHost,
			StorageDir: storageDir,
			PrimaryCA:  ca.srv.URL + "/dir",
			FallbackCA: "",
			CARootFile: ca.caFile,
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
		})
		if err != nil {
			t.Fatal(err)
		}
		cm.now = func() time.Time { return fakeNow }
		if withFakeWait {
			cm.waitFn = func(ctx context.Context, d time.Duration) error {
				waits = append(waits, d)
				fakeNow = fakeNow.Add(d)
				return nil
			}
		}
		return cm
	}

	// 1. Fresh failure: runs 3 startup attempts with 5s and 15s waits, then persists 45s next_attempt.
	cm1 := newMgr(true)
	err := cm1.EnsureWithBackoff(context.Background())
	cm1.Close()
	if err == nil {
		t.Fatal("expected initial 503 failure")
	}
	if got := ca.orderHits.Load(); got != 3 {
		t.Fatalf("initial startup made %d order hits, want 3", got)
	}
	wantInitialWaits := []time.Duration{5 * time.Second, 15 * time.Second}
	if len(waits) != len(wantInitialWaits) || waits[0] != wantInitialWaits[0] || waits[1] != wantInitialWaits[1] {
		t.Fatalf("initial waits = %v, want %v", waits, wantInitialWaits)
	}
	retryPath := filepath.Join(storageDir, acmeRetryStateFile)
	fi, err := os.Stat(retryPath)
	if err != nil {
		t.Fatalf("stat %s: %v", retryPath, err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode = %o, want 0600", retryPath, fi.Mode().Perm())
	}
	st := cm1.loadRetryState()
	if st.Failures != 3 || !st.NextAttempt.Equal(fakeNow.Add(45*time.Second)) {
		t.Fatalf("persisted retry state = %+v (now=%s)", st, fakeNow)
	}

	// 2. Restart 30s later with real timer wait: blocks before next_attempt with 0 CA hits.
	fakeNow = fakeNow.Add(30 * time.Second)
	cmEarly := newMgr(false)
	earlyCtx, earlyCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	earlyErr := cmEarly.EnsureWithBackoff(earlyCtx)
	earlyCancel()
	cmEarly.Close()
	if !errors.Is(earlyErr, context.DeadlineExceeded) {
		t.Fatalf("early restart err = %v, want DeadlineExceeded", earlyErr)
	}
	if got := ca.orderHits.Load(); got != 3 {
		t.Fatalf("early restart hit CA before next_attempt: orderHits=%d", got)
	}

	// 3. Simulated 30s service restarts advance through 45s -> 2m -> 5m -> 15m -> 30m -> 1h -> 1h cap.
	wantRestartWaits := []time.Duration{
		15 * time.Second, // remaining of 45s after the 30s gap above
		90 * time.Second, // 2m - 30s
		4*time.Minute + 30*time.Second,
		14*time.Minute + 30*time.Second,
		29*time.Minute + 30*time.Second,
		59*time.Minute + 30*time.Second,
		59*time.Minute + 30*time.Second,
	}
	for i, wantWait := range wantRestartWaits {
		waits = nil
		cm := newMgr(true)
		hitsBefore := ca.orderHits.Load()
		if err := cm.EnsureWithBackoff(context.Background()); err == nil {
			cm.Close()
			t.Fatalf("restart %d unexpectedly succeeded", i)
		}
		cm.Close()
		if ca.orderHits.Load() != hitsBefore+1 {
			t.Fatalf("restart %d made %d orders, want 1", i, ca.orderHits.Load()-hitsBefore)
		}
		if len(waits) != 1 || waits[0] != wantWait {
			t.Fatalf("restart %d waits = %v, want [%s]", i, waits, wantWait)
		}
		fakeNow = fakeNow.Add(30 * time.Second)
	}
	if st := cm1.loadRetryState(); st.Failures != 10 {
		t.Fatalf("final failure count = %d, want 10", st.Failures)
	}

	// 4. Backward clock jump clamps wait to 1h cap rather than sleeping days.
	savedNow := fakeNow
	fakeNow = fakeNow.Add(-24 * time.Hour)
	cmClock := newMgr(false)
	var observedWait time.Duration
	sentinel := errors.New("stop after clamp check")
	cmClock.waitFn = func(_ context.Context, d time.Duration) error {
		observedWait = d
		return sentinel
	}
	if err := cmClock.EnsureWithBackoff(context.Background()); !errors.Is(err, sentinel) {
		cmClock.Close()
		t.Fatalf("clock jump err = %v, want sentinel", err)
	}
	cmClock.Close()
	if observedWait != time.Hour {
		t.Fatalf("backward clock jump wait = %s, want 1h cap", observedWait)
	}
	fakeNow = savedNow

	// 5. Corrupt retry.json fails open to zero state.
	corruptDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(corruptDir, acmeRetryStateFile), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmCorrupt, err := newShareCertManager(shareACMEConfig{
		Zone: penZone, Host: shareHost, StorageDir: corruptDir,
		PrimaryCA: ca.srv.URL + "/dir", CARootFile: ca.caFile, HTTPClient: &http.Client{Timeout: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := cmCorrupt.loadRetryState(); got != (acmeRetryState{}) {
		cmCorrupt.Close()
		t.Fatalf("corrupt retry.json yielded %+v, want zero", got)
	}
	cmCorrupt.Close()

	// 6. Recovery obtains cert, serves valid TLS, and removes retry.json.
	waits = nil
	ca.failOrder.Store(false)
	cmRecover := newMgr(true)
	if err := cmRecover.EnsureWithBackoff(context.Background()); err != nil {
		cmRecover.Close()
		t.Fatalf("recovery EnsureWithBackoff failed: %v", err)
	}
	_ = verifyCertManagerHandshake(t, cmRecover, shareHost, ca.caPool)
	cmRecover.Close()
	if _, err := os.Stat(retryPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected %s to be deleted on success, got %v", retryPath, err)
	}

	// 7. Valid cached cert short-circuits immediately and clears stale retry.json with 0 CA hits.
	staleBytes, err := json.Marshal(acmeRetryState{Failures: 8, NextAttempt: fakeNow.Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(retryPath, staleBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	waits = nil
	hitsBefore := ca.orderHits.Load()
	cmCached := newMgr(true)
	defer cmCached.Close()
	if err := cmCached.EnsureWithBackoff(context.Background()); err != nil {
		t.Fatalf("cached EnsureWithBackoff failed: %v", err)
	}
	if len(waits) != 0 || ca.orderHits.Load() != hitsBefore {
		t.Fatalf("cached cert waited or hit CA: waits=%v hits=%d->%d", waits, hitsBefore, ca.orderHits.Load())
	}
	if _, err := os.Stat(retryPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected stale %s to be removed on cached hit, got %v", retryPath, err)
	}
}

func TestShareACMERegistrarCapLongBackoff(t *testing.T) {
	const (
		penZone   = "bobo.pens.example.com"
		shareHost = "photos.bobo.pens.example.com"
	)

	var nonces atomic.Int64
	nextNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", "cap-nonce-"+big.NewInt(nonces.Add(1)).String())
	}
	var txtHits atomic.Int32

	priMux := http.NewServeMux()
	priMux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/acct",
			"newOrder":   base + "/order",
		})
	})
	priMux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.WriteHeader(http.StatusNoContent)
	})
	priMux.HandleFunc("/acct", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.Header().Set("Location", "https://"+r.Host+"/acct/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	priMux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.Header().Set("Location", "https://"+r.Host+"/order/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"identifiers":    []map[string]string{{"type": "dns", "value": shareHost}},
			"authorizations": []string{"https://" + r.Host + "/authz/1"},
			"finalize":       "https://" + r.Host + "/finalize/1",
		})
	})
	priMux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "pending",
			"identifier": map[string]string{"type": "dns", "value": shareHost},
			"challenges": []map[string]any{{
				"type":   "dns-01",
				"url":    "https://" + r.Host + "/chall/1",
				"status": "pending",
				"token":  "chall_token_0123456789abcdef",
			}},
		})
	})
	primary := httptest.NewTLSServer(priMux)
	defer primary.Close()

	meshSrv := newTLSServerForHost(t, "home."+penZone, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/acme/txt" {
			txtHits.Add(1)
			http.Error(w, `{"error":"weekly certificate name limit reached"}`, http.StatusTooManyRequests)
			return
		}
		http.NotFound(w, r)
	}))

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: primary.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	storageDir := filepath.Join(t.TempDir(), "acme")
	fakeNow := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	var waits []time.Duration

	newMgr := func() *shareCertManager {
		cm, err := newShareCertManager(shareACMEConfig{
			Zone:       penZone,
			Host:       shareHost,
			StorageDir: storageDir,
			PrimaryCA:  primary.URL + "/dir",
			CARootFile: caFile,
			HTTPClient: homeMeshTestClient(meshSrv, penZone),
		})
		if err != nil {
			t.Fatal(err)
		}
		cm.now = func() time.Time { return fakeNow }
		cm.waitFn = func(_ context.Context, d time.Duration) error {
			waits = append(waits, d)
			fakeNow = fakeNow.Add(d)
			return nil
		}
		return cm
	}

	// 1. First registrar 429 returns after 1 attempt and schedules 1h maxBackoff immediately.
	cm1 := newMgr()
	if err := cm1.EnsureWithBackoff(context.Background()); err == nil {
		cm1.Close()
		t.Fatal("expected TXT 429 error on first attempt")
	}
	st1 := cm1.loadRetryState()
	cm1.Close()
	if txtHits.Load() != 1 {
		t.Fatalf("expected 1 TXT attempt on registrar 429, got %d", txtHits.Load())
	}
	if len(waits) != 0 {
		t.Fatalf("unexpected in-process wait after registrar 429: %v", waits)
	}
	wantNext1 := fakeNow.Add(time.Hour)
	if st1.Failures != 1 || !st1.NextAttempt.Equal(wantNext1) {
		t.Fatalf("retry state = %+v, want Failures=1 NextAttempt=%s", st1, wantNext1)
	}

	// 2. Restart 15m later waits remaining 45m, tries once, and sets another 1h backoff.
	fakeNow = fakeNow.Add(15 * time.Minute)
	cm2 := newMgr()
	if err := cm2.EnsureWithBackoff(context.Background()); err == nil {
		cm2.Close()
		t.Fatal("expected TXT 429 error on second attempt")
	}
	st2 := cm2.loadRetryState()
	cm2.Close()
	if len(waits) != 1 || waits[0] != 45*time.Minute {
		t.Fatalf("restart waits = %v, want [45m]", waits)
	}
	if txtHits.Load() != 2 {
		t.Fatalf("expected 2 total TXT hits after restart, got %d", txtHits.Load())
	}
	wantNext2 := fakeNow.Add(time.Hour)
	if st2.Failures != 2 || !st2.NextAttempt.Equal(wantNext2) {
		t.Fatalf("retry state after second 429 = %+v, want Failures=2 NextAttempt=%s", st2, wantNext2)
	}

	// 3. Immediate restart waits full 1h cap before hitting /api/acme/txt again.
	waits = nil
	cm3 := newMgr()
	if err := cm3.EnsureWithBackoff(context.Background()); err == nil {
		cm3.Close()
		t.Fatal("expected TXT 429 error on third attempt")
	}
	cm3.Close()
	if len(waits) != 1 || waits[0] != time.Hour {
		t.Fatalf("third restart waits = %v, want [1h]", waits)
	}
	if txtHits.Load() != 3 {
		t.Fatalf("expected 3 total TXT hits, got %d", txtHits.Load())
	}
}

func TestFallbackContact(t *testing.T) {
	if got := fallbackContact(" ops@example.com "); len(got) != 1 || got[0] != "mailto:ops@example.com" {
		t.Fatalf("fallbackContact = %v", got)
	}
	for _, bad := range []string{"", "nope", "Ops <ops@example.com>", "a@b.com,c@d.com", "ops@example.com?cc=x@y.z"} {
		if got := fallbackContact(bad); got != nil {
			t.Fatalf("fallbackContact(%q) = %v, want nil", bad, got)
		}
	}
}

func TestShareCertManagerCloseIdempotent(t *testing.T) {
	cm, err := newShareCertManager(shareACMEConfig{
		Zone:       "bobo.pens.example.com",
		Host:       "photos.bobo.pens.example.com",
		StorageDir: filepath.Join(t.TempDir(), "acme"),
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Fresh share failure calls cm.Close() before undoFreshShare while defer
	// cm.Close() also runs on return; Close must be idempotent.
	cm.Close()
	cm.Close()
}

func TestMeshJSONParsesRetryAfter(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2700")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"too many new certificate names for this pen in the last hour"}`))
	}))
	defer srv.Close()

	hc := srv.Client()
	origTr := hc.Transport.(*http.Transport)
	hc.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		u, _ := url.Parse(srv.URL)
		req2 := req.Clone(req.Context())
		req2.URL.Scheme = u.Scheme
		req2.URL.Host = u.Host
		return origTr.RoundTrip(req2)
	})

	_, err := penapi.HomeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodPost, "/acme/txt", map[string]string{"name": "photos", "value": "x"}, nil)
	var me *penapi.HomeAPIError
	if !errors.As(err, &me) {
		t.Fatalf("expected *penapi.HomeAPIError, got %T: %v", err, err)
	}
	if me.Status != http.StatusTooManyRequests || me.RetryAfter != 45*time.Minute {
		t.Fatalf("HomeAPIError = %+v, want status=429 retryAfter=45m", me)
	}
	if me.Msg != "too many new certificate names for this pen in the last hour" {
		t.Fatalf("HomeAPIError.Msg = %q", me.Msg)
	}
}
