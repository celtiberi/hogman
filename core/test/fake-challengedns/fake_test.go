package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
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
	"testing"
	"time"
)

func doJSONReq(t *testing.T, url, method, tok string, body any) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func TestChallengeServerScopeLimitsAndDeleteRepost(t *testing.T) {
	var mu sync.Mutex
	records := map[string][]string{}
	mgmt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Host  string `json:"host"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/clear-txt":
			delete(records, in.Host)
		case "/set-txt":
			records[in.Host] = append(records[in.Host], in.Value)
		default:
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mgmt.Close()

	cs := newChallengeServer("bobo", "pens.hogman.network", "tok-1", mgmt.URL, "kid-1", "mac-1")
	api := httptest.NewServer(cs.handler())
	defer api.Close()

	val1 := "validchallengevalue_01"
	val2 := "validchallengevalue_02"
	val3 := "validchallengevalue_03"
	fqdn := "_acme-challenge.photos.bobo.pens.hogman.network"

	// Unauthorized.
	resp, _ := doJSONReq(t, api.URL+"/v1/txt", "POST", "wrong", map[string]string{"fqdn": fqdn, "value": val1})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: got %d want 401", resp.StatusCode)
	}

	// Out-of-scope pen and missing _acme-challenge prefix refused.
	for _, badFQDN := range []string{
		"_acme-challenge.photos.other.pens.hogman.network",
		"photos.bobo.pens.hogman.network",
		"_acme-challenge.bobo.pens.hogman.network",
		"_acme-challenge.a.b.c.d.e.bobo.pens.hogman.network",
	} {
		resp, _ := doJSONReq(t, api.URL+"/v1/txt", "POST", "tok-1", map[string]string{"fqdn": badFQDN, "value": val1})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("bad scope %s: got %d want 403", badFQDN, resp.StatusCode)
		}
	}

	// Bad value -> 400.
	resp, _ = doJSONReq(t, api.URL+"/v1/txt", "POST", "tok-1", map[string]string{"fqdn": fqdn, "value": "bad!val"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad value: got %d want 400", resp.StatusCode)
	}

	// Two live TXT values succeed; repeat is idempotent; 3rd returns 409.
	resp, _ = doJSONReq(t, api.URL+"/v1/txt", "POST", "tok-1", map[string]string{"fqdn": fqdn, "value": val1})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first POST txt: got %d", resp.StatusCode)
	}
	resp, _ = doJSONReq(t, api.URL+"/v1/txt", "POST", "tok-1", map[string]string{"fqdn": fqdn, "value": val1})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("idempotent POST txt: got %d", resp.StatusCode)
	}
	resp, _ = doJSONReq(t, api.URL+"/v1/txt", "POST", "tok-1", map[string]string{"fqdn": fqdn, "value": val2})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("second POST txt: got %d", resp.StatusCode)
	}
	resp, _ = doJSONReq(t, api.URL+"/v1/txt", "POST", "tok-1", map[string]string{"fqdn": fqdn, "value": val3})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("third live txt: got %d want 409", resp.StatusCode)
	}

	// DELETE val1 clears challtestsrv host and re-posts remaining val2 cleanly.
	resp, _ = doJSONReq(t, api.URL+"/v1/txt", "DELETE", "tok-1", map[string]string{"fqdn": fqdn, "value": val1})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE txt: got %d want 204", resp.StatusCode)
	}
	mu.Lock()
	gotRecs := append([]string(nil), records[fqdn+"."]...)
	mu.Unlock()
	if len(gotRecs) != 1 || gotRecs[0] != val2 {
		t.Fatalf("challtestsrv records after partial delete = %v, want [%s]", gotRecs, val2)
	}

	// Weekly cap: 9 more distinct FQDNs succeed (total 10), 11th returns 429.
	for i := 2; i <= 10; i++ {
		f := fmt.Sprintf("_acme-challenge.app%d.bobo.pens.hogman.network", i)
		resp, _ = doJSONReq(t, api.URL+"/v1/txt", "POST", "tok-1", map[string]string{"fqdn": f, "value": val1})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("distinct fqdn #%d (%s): got %d", i, f, resp.StatusCode)
		}
	}
	resp, _ = doJSONReq(t, api.URL+"/v1/txt", "POST", "tok-1", map[string]string{
		"fqdn":  "_acme-challenge.app11.bobo.pens.hogman.network",
		"value": val1,
	})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("11th distinct fqdn: got %d want 429", resp.StatusCode)
	}

	// EAB cap: 5 succeed, 6th returns 429.
	for i := 1; i <= 5; i++ {
		resp, body := doJSONReq(t, api.URL+"/v1/eab", "POST", "tok-1", nil)
		if resp.StatusCode != http.StatusCreated || !strings.Contains(string(body), `"kid":"kid-1"`) {
			t.Fatalf("EAB #%d: got %d body=%s", i, resp.StatusCode, string(body))
		}
	}
	resp, _ = doJSONReq(t, api.URL+"/v1/eab", "POST", "tok-1", nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("6th EAB: got %d want 429", resp.StatusCode)
	}

	// Reset clears everything.
	resp, _ = doJSONReq(t, api.URL+"/test/reset", "POST", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset: got %d", resp.StatusCode)
	}
	resp, _ = doJSONReq(t, api.URL+"/v1/txt", "POST", "tok-1", map[string]string{
		"fqdn":  "_acme-challenge.app11.bobo.pens.hogman.network",
		"value": val1,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("after reset: got %d want 201", resp.StatusCode)
	}
}

func buildDNSQuery(name string, qtype uint16) []byte {
	var b bytes.Buffer
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	b.Write(hdr[:])
	encodeDNSName(&b, name)
	var qt [4]byte
	binary.BigEndian.PutUint16(qt[0:2], qtype)
	binary.BigEndian.PutUint16(qt[2:4], 1)
	b.Write(qt[:])
	return b.Bytes()
}

func TestDNSProxySOAAndForwarding(t *testing.T) {
	upPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upPC.Close()

	forwarded := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 512)
		n, addr, err := upPC.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		forwarded <- pkt
		resp := append([]byte(nil), pkt...)
		if len(resp) >= 4 {
			binary.BigEndian.PutUint16(resp[2:4], 0x8180)
		}
		_, _ = upPC.WriteTo(resp, addr)
	}()

	proxy := &dnsProxy{pensZone: "pens.hogman.network", upstream: upPC.LocalAddr().String()}

	// SOA query for zone apex -> local Answer SOA.
	apexQ := buildDNSQuery("pens.hogman.network", 6)
	apexResp, err := proxy.handlePacket(apexQ)
	if err != nil {
		t.Fatalf("zone apex SOA failed: %v", err)
	}
	if got := binary.BigEndian.Uint16(apexResp[6:8]); got != 1 {
		t.Fatalf("zone apex SOA ANCOUNT = %d, want 1", got)
	}

	// SOA query for subdomain -> local Authority SOA.
	subQ := buildDNSQuery("_acme-challenge.home.bobo.pens.hogman.network", 6)
	subResp, err := proxy.handlePacket(subQ)
	if err != nil {
		t.Fatalf("sub SOA failed: %v", err)
	}
	if got := binary.BigEndian.Uint16(subResp[8:10]); got != 1 {
		t.Fatalf("sub SOA NSCOUNT = %d, want 1", got)
	}

	// Serve UDP/TCP and check TXT forwarding end-to-end.
	proxyPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := proxyPC.LocalAddr().String()
	_ = proxyPC.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := proxy.serve(ctx, proxyAddr); err != nil {
		t.Fatal(err)
	}

	txtQ := buildDNSQuery("_acme-challenge.home.bobo.pens.hogman.network", 16)
	c, err := net.Dial("udp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(txtQ); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil || n != len(txtQ) {
		t.Fatalf("forwarded TXT UDP read failed: n=%d err=%v", n, err)
	}
	select {
	case got := <-forwarded:
		if !bytes.Equal(got, txtQ) {
			t.Fatal("upstream received altered TXT packet")
		}
	case <-time.After(time.Second):
		t.Fatal("TXT query not forwarded to upstream")
	}
}

func TestFakeHeadscaleAndMock429(t *testing.T) {
	hs := newFakeHeadscale()
	hsSrv := httptest.NewServer(hs.handler())
	defer hsSrv.Close()

	resp, body := doJSONReq(t, hsSrv.URL+"/api/v1/user", "POST", "", map[string]string{"name": "alice"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"name":"alice"`) {
		t.Fatalf("create user: %d %s", resp.StatusCode, string(body))
	}
	resp, body = doJSONReq(t, hsSrv.URL+"/api/v1/preauthkey", "POST", "", map[string]any{
		"user":    "1",
		"aclTags": []string{"tag:server"},
	})
	var keyResp struct {
		PreAuthKey hsPreAuthKey `json:"preAuthKey"`
	}
	_ = json.Unmarshal(body, &keyResp)
	if resp.StatusCode != http.StatusOK || keyResp.PreAuthKey.Key == "" {
		t.Fatalf("create preauthkey: %d %s", resp.StatusCode, string(body))
	}

	resp, body = doJSONReq(t, hsSrv.URL+"/test/hs-node", "POST", "", map[string]string{
		"key":  keyResp.PreAuthKey.Key,
		"ip":   "100.64.0.11",
		"name": "alice-srv",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("hs-node: %d %s", resp.StatusCode, string(body))
	}
	var created hsNode
	if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
		t.Fatalf("decode hs-node: err=%v body=%s", err, string(body))
	}
	resp, body = doJSONReq(t, hsSrv.URL+"/api/v1/node", "GET", "", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"100.64.0.11"`) || !strings.Contains(string(body), `"tag:server"`) {
		t.Fatalf("GET nodes: %d %s", resp.StatusCode, string(body))
	}
	resp, body = doJSONReq(t, hsSrv.URL+"/api/v1/node/"+created.ID, "GET", "", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"id":"`+created.ID+`"`) || !strings.Contains(string(body), `"100.64.0.11"`) {
		t.Fatalf("GET node/%s: %d %s", created.ID, resp.StatusCode, string(body))
	}
	resp, _ = doJSONReq(t, hsSrv.URL+"/api/v1/node/999", "GET", "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET node/999: got %d want 404", resp.StatusCode)
	}

	// Verify mock429 TLS server dir/nonce/acct/order behavior.
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock429"},
		DNSNames:     []string{"mock429", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kDER, _ := x509.MarshalECPrivateKey(k)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kDER}), 0o600)

	m429 := httptest.NewUnstartedServer(mock429Handler())
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	m429.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	m429.StartTLS()
	defer m429.Close()

	pool := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(der)
	pool.AddCert(leaf)
	cli := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	rDir, err := cli.Get(m429.URL + "/dir")
	if err != nil || rDir.StatusCode != http.StatusOK {
		t.Fatalf("mock429 /dir: err=%v resp=%v", err, rDir)
	}
	_ = rDir.Body.Close()

	rOrd, err := cli.Post(m429.URL+"/order", "application/jose+json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	bOrd, _ := io.ReadAll(rOrd.Body)
	_ = rOrd.Body.Close()
	if rOrd.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(bOrd), ":rateLimited") {
		t.Fatalf("mock429 /order: got %d %s", rOrd.StatusCode, string(bOrd))
	}
}
