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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	cm1, err := share.NewCertManager(share.ACMEConfig{
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
	cm2, err := share.NewCertManager(share.ACMEConfig{
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
	cmDenied, err := share.NewCertManager(share.ACMEConfig{
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
	cmFB, err := share.NewCertManager(share.ACMEConfig{
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
	cmFBRestart, err := share.NewCertManager(share.ACMEConfig{
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
