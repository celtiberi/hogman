package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hogman/join/internal/share"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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

func verifyCertManagerHandshake(t *testing.T, cm *share.CertManager, serverName string, rootPool *x509.CertPool) *big.Int {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = cm.TLSConfig()
	srv.StartTLS()
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: serverName,
				RootCAs:    rootPool,
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
			},
		},
	}
	resp, err := client.Get("https://" + serverName + "/")
	if err != nil {
		t.Fatalf("TLS request to %s failed: %v", serverName, err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatalf("missing peer certificate for %s", serverName)
	}
	return resp.TLS.PeerCertificates[0].SerialNumber
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
	homeCAPool := readPool(mustEnv("ACME_HOME_CA_ROOT"))
	pebble1URL := mustEnv("ACME_PEBBLE1_CA_URL")
	pebble2URL := mustEnv("ACME_PEBBLE2_CA_URL")
	mock429URL := mustEnv("ACME_MOCK429_CA_URL")
	caRoot := mustEnv("ACME_CA_ROOT")
	pebble1Pool := readPool(mustEnv("ACME_PEBBLE1_ROOT"))
	pebble2Pool := readPool(mustEnv("ACME_PEBBLE2_ROOT"))
	resolverAddr := mustEnv("ACME_RESOLVER")
	stateJSONPath := mustEnv("ACME_STATE_JSON")

	type cdnsState struct {
		Seen map[string]map[string]time.Time `json:"seen"`
		EAB  map[string][]time.Time          `json:"eab"`
	}
	readCDNSStats := func() (eabCount int, seen map[string]bool) {
		b, err := os.ReadFile(stateJSONPath)
		if err != nil {
			t.Fatalf("read %s: %v", stateJSONPath, err)
		}
		var st cdnsState
		if err := json.Unmarshal(b, &st); err != nil {
			t.Fatalf("decode %s: %v", stateJSONPath, err)
		}
		seen = map[string]bool{}
		for _, m := range st.Seen {
			for fqdn := range m {
				seen[fqdn] = true
			}
		}
		for _, ts := range st.EAB {
			eabCount += len(ts)
		}
		return eabCount, seen
	}

	lookupTXT := func(fqdn string) []string {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, resolverAddr)
			},
		}
		vals, err := r.LookupTXT(context.Background(), fqdn)
		if err != nil {
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				return nil
			}
			if strings.Contains(err.Error(), "no such host") || strings.Contains(strings.ToLower(err.Error()), "no answer") {
				return nil
			}
			t.Fatalf("LookupTXT(%s): %v", fqdn, err)
		}
		return vals
	}

	type callCounts struct {
		txtPosts   atomic.Int32
		txtDeletes atomic.Int32
		eabPosts   atomic.Int32
	}
	newMeshClient := func() (*http.Client, *callCounts) {
		counts := &callCounts{}
		baseTr := &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{RootCAs: homeCAPool},
		}
		return &http.Client{
			Timeout: 20 * time.Second,
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case req.URL.Path == "/api/acme/txt" && req.Method == http.MethodPost:
					counts.txtPosts.Add(1)
				case req.URL.Path == "/api/acme/txt" && req.Method == http.MethodDelete:
					counts.txtDeletes.Add(1)
				case req.URL.Path == "/api/acme/eab" && req.Method == http.MethodPost:
					counts.eabPosts.Add(1)
				}
				return baseTr.RoundTrip(req)
			}),
		}, counts
	}

	ctx := context.Background()

	// 1. Obtain photos.<zone> via Pebble1 over real WireGuard -> embedded registrar -> real challenge-dns.
	photosHost := "photos." + zone
	photosDir := filepath.Join(t.TempDir(), "acme-photos")
	beforeEAB, _ := readCDNSStats()
	cli1, counts1 := newMeshClient()
	cm1, err := share.NewCertManager(share.ACMEConfig{
		Zone:               zone,
		Host:               photosHost,
		StorageDir:         photosDir,
		PrimaryCA:          pebble1URL,
		CARootFile:         caRoot,
		Resolvers:          []string{resolverAddr},
		PropagationDelay:   100 * time.Millisecond,
		PropagationTimeout: 15 * time.Second,
		HTTPClient:         cli1,
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

	afterPhotosEAB, afterPhotosSeen := readCDNSStats()
	if afterPhotosEAB != beforeEAB || counts1.eabPosts.Load() != 0 {
		t.Fatalf("happy path minted fallback EAB: before=%d after=%d calls=%d", beforeEAB, afterPhotosEAB, counts1.eabPosts.Load())
	}
	wantChallengeFQDN := "_acme-challenge." + photosHost
	if !afterPhotosSeen[wantChallengeFQDN] || counts1.txtPosts.Load() == 0 {
		t.Fatalf("expected TXT write for %s: seen=%v txtPosts=%d", wantChallengeFQDN, afterPhotosSeen, counts1.txtPosts.Load())
	}
	if live := lookupTXT(wantChallengeFQDN); len(live) != 0 {
		t.Fatalf("expected challenge TXT cleanup after issuance, live=%v", live)
	}

	// 2. Restarting on the same storage dir reuses cached cert without new TXT writes or orders.
	cli2, counts2 := newMeshClient()
	cm2, err := share.NewCertManager(share.ACMEConfig{
		Zone:               zone,
		Host:               photosHost,
		StorageDir:         photosDir,
		PrimaryCA:          pebble1URL,
		CARootFile:         caRoot,
		Resolvers:          []string{resolverAddr},
		PropagationDelay:   100 * time.Millisecond,
		PropagationTimeout: 15 * time.Second,
		HTTPClient:         cli2,
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
	if counts2.txtPosts.Load() != 0 || counts2.eabPosts.Load() != 0 {
		t.Fatalf("restart hit ACME proxy unexpectedly: txtPosts=%d eabPosts=%d", counts2.txtPosts.Load(), counts2.eabPosts.Load())
	}

	// 3. Unowned name fails on registrar /api/acme/txt (403) without failing over or minting EAB.
	cliDenied, countsDenied := newMeshClient()
	cmDenied, err := share.NewCertManager(share.ACMEConfig{
		Zone:               zone,
		Host:               "other." + zone,
		StorageDir:         filepath.Join(t.TempDir(), "acme-denied"),
		PrimaryCA:          pebble1URL,
		FallbackCA:         pebble2URL,
		CARootFile:         caRoot,
		Resolvers:          []string{resolverAddr},
		PropagationDelay:   100 * time.Millisecond,
		PropagationTimeout: 10 * time.Second,
		HTTPClient:         cliDenied,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmDenied.Ensure(ctx); err == nil {
		cmDenied.Close()
		t.Fatal("expected unowned share name to fail")
	}
	cmDenied.Close()
	if eabAfterDenied, _ := readCDNSStats(); eabAfterDenied != beforeEAB || countsDenied.eabPosts.Load() != 0 {
		t.Fatalf("unowned name 403 triggered EAB mint: before=%d after=%d calls=%d", beforeEAB, eabAfterDenied, countsDenied.eabPosts.Load())
	}

	// 4. Primary HTTP 429 fails over to Pebble2 via lazy POST /api/acme/eab, and restart reuses cert.
	fbHost := "sharefb." + zone
	fbDir := filepath.Join(t.TempDir(), "acme-fb")
	cliFB, countsFB := newMeshClient()
	cmFB, err := share.NewCertManager(share.ACMEConfig{
		Zone:               zone,
		Host:               fbHost,
		StorageDir:         fbDir,
		PrimaryCA:          mock429URL,
		FallbackCA:         pebble2URL,
		CARootFile:         caRoot,
		Resolvers:          []string{resolverAddr},
		PropagationDelay:   100 * time.Millisecond,
		PropagationTimeout: 15 * time.Second,
		HTTPClient:         cliFB,
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

	afterFBEAB, _ := readCDNSStats()
	if afterFBEAB != beforeEAB+1 || countsFB.eabPosts.Load() != 1 {
		t.Fatalf("expected 1 fallback EAB mint, got before=%d after=%d calls=%d", beforeEAB, afterFBEAB, countsFB.eabPosts.Load())
	}

	cliFBRestart, countsFBRestart := newMeshClient()
	cmFBRestart, err := share.NewCertManager(share.ACMEConfig{
		Zone:               zone,
		Host:               fbHost,
		StorageDir:         fbDir,
		PrimaryCA:          mock429URL,
		FallbackCA:         pebble2URL,
		CARootFile:         caRoot,
		Resolvers:          []string{resolverAddr},
		PropagationDelay:   100 * time.Millisecond,
		PropagationTimeout: 15 * time.Second,
		HTTPClient:         cliFBRestart,
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
	if eabAfterRestart, _ := readCDNSStats(); eabAfterRestart != afterFBEAB || countsFBRestart.txtPosts.Load() != 0 || countsFBRestart.eabPosts.Load() != 0 {
		t.Fatalf("fallback restart hit EAB or TXT unexpectedly: eab=%d->%d txtPosts=%d eabPosts=%d",
			afterFBEAB, eabAfterRestart, countsFBRestart.txtPosts.Load(), countsFBRestart.eabPosts.Load())
	}
}
