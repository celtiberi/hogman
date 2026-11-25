// Command bench-driver is a repeatable load driver for I-30 pen capacity testing.
// It runs on the benchmark pen's Docker network, connects real tsnet.Server nodes
// against Headscale, and serves a small Unix-socket control API so bench.sh can
// ramp enrolled/online devices, measure policy propagation latency, and run
// concurrent HTTPS traffic over the mesh.
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
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/tsnet"
)

type enrollItem struct {
	Hostname string `json:"hostname"`
	AuthKey  string `json:"auth_key"`
	Kind     string `json:"kind"` // "personal" or "server"
	KeepLive bool   `json:"keep_live"`
}

type liveNode struct {
	hostname string
	kind     string
	srv      *tsnet.Server
	ip       string
	dir      string
}

type driver struct {
	controlURL string
	zone       string
	stateRoot  string
	homeCA     *x509.CertPool

	mu          sync.Mutex
	owner       *liveNode
	kickProbe   *liveNode
	echoServer  *liveNode
	liveNodes   []*liveNode
	totalJoined int
}

func main() {
	var (
		sockPath   = flag.String("sock", "/work/driver.sock", "Unix socket path for control API")
		controlURL = flag.String("control-url", "http://headscale:8080", "Headscale control URL")
		zone       = flag.String("zone", "bench.hogman.test", "Pen DNS zone")
		stateRoot  = flag.String("state", "/tmp/bench-tsnet", "Directory for temporary tsnet state")
		homeCAFile = flag.String("home-ca", "/work/home.crt", "Self-signed home cert/CA PEM to trust")
		callMethod = flag.String("call", "", "Client mode: send HTTP method to -sock path (body from stdin) and exit")
	)
	flag.Parse()

	if *callMethod != "" {
		path := flag.Arg(0)
		if path == "" {
			log.Fatal("-call requires a path argument")
		}
		var body io.Reader
		if *callMethod != http.MethodGet && *callMethod != http.MethodHead {
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				log.Fatalf("read stdin: %v", err)
			}
			if len(raw) > 0 {
				body = strings.NewReader(string(raw))
			}
		}
		hc := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", *sockPath)
				},
			},
		}
		req, err := http.NewRequest(*callMethod, "http://driver"+path, body)
		if err != nil {
			log.Fatalf("new request: %v", err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := hc.Do(req)
		if err != nil {
			log.Fatalf("call %s %s: %v", *callMethod, path, err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		_, _ = os.Stdout.Write(out)
		if resp.StatusCode/100 != 2 {
			os.Exit(1)
		}
		return
	}

	caPEM, err := os.ReadFile(*homeCAFile)
	if err != nil {
		log.Fatalf("read home CA %s: %v", *homeCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("invalid PEM in %s", *homeCAFile)
	}
	if err := os.MkdirAll(*stateRoot, 0o700); err != nil {
		log.Fatalf("mkdir %s: %v", *stateRoot, err)
	}

	d := &driver{
		controlURL: *controlURL,
		zone:       *zone,
		stateRoot:  *stateRoot,
		homeCA:     pool,
	}

	_ = os.Remove(*sockPath)
	ln, err := net.Listen("unix", *sockPath)
	if err != nil {
		log.Fatalf("listen unix %s: %v", *sockPath, err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /init", d.handleInit)
	mux.HandleFunc("POST /enroll", d.handleEnroll)
	mux.HandleFunc("POST /propagation", d.handlePropagation)
	mux.HandleFunc("POST /traffic", d.handleTraffic)
	mux.HandleFunc("GET /stats", d.handleStats)

	log.Printf("bench-driver listening on %s (control=%s zone=%s)", *sockPath, *controlURL, *zone)
	if err := http.Serve(ln, mux); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *driver) startNode(ctx context.Context, hostname, authKey, kind string) (*liveNode, error) {
	dir := filepath.Join(d.stateRoot, hostname)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	srv := &tsnet.Server{
		Hostname:   hostname,
		Dir:        dir,
		ControlURL: d.controlURL,
		AuthKey:    authKey,
		Logf:       func(string, ...any) {},
		UserLogf:   func(string, ...any) {},
	}
	upCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	st, err := srv.Up(upCtx)
	if err != nil {
		_ = srv.Close()
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("up %s: %w", hostname, err)
	}
	ip := ""
	for _, a := range st.TailscaleIPs {
		if a.Is4() {
			ip = a.String()
			break
		}
	}
	return &liveNode{hostname: hostname, kind: kind, srv: srv, ip: ip, dir: dir}, nil
}

func (d *driver) meshHTTPClient(n *liveNode, insecure bool, timeout time.Duration) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            d.homeCA,
		InsecureSkipVerify: insecure,
	}
	tr := &http.Transport{
		DialContext:         n.srv.Dial,
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     30 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func makeSelfSignedCert(host string) (tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}

func (d *driver) handleInit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OwnerKey      string `json:"owner_key"`
		KickProbeKey  string `json:"kick_probe_key"`
		EchoServerKey string `json:"echo_server_key"`
		CoreIP        string `json:"core_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	ctx := r.Context()
	owner, err := d.startNode(ctx, "probe-owner", in.OwnerKey, "personal")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	kick, err := d.startNode(ctx, "probe-kick", in.KickProbeKey, "personal")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	echoSrv, err := d.startNode(ctx, "probe-server", in.EchoServerKey, "server")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	cert, err := makeSelfSignedCert("probe-server." + d.zone)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	ln, err := echoSrv.srv.Listen("tcp", ":443")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": fmt.Sprintf("echo listen: %v", err)})
		return
	}
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = 'H'
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, _ = w.Write(payload)
		})
		_ = http.Serve(tlsLn, mux)
	}()

	d.mu.Lock()
	d.owner = owner
	d.kickProbe = kick
	d.echoServer = echoSrv
	d.totalJoined += 3
	d.mu.Unlock()

	writeJSON(w, 200, map[string]any{
		"owner_ip":       owner.ip,
		"kick_probe_ip":  kick.ip,
		"echo_server_ip": echoSrv.ip,
	})
}

func (d *driver) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Items       []enrollItem `json:"items"`
		Concurrency int          `json:"concurrency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if in.Concurrency <= 0 {
		in.Concurrency = 8
	}

	t0 := time.Now()
	jobs := make(chan enrollItem, len(in.Items))
	for _, it := range in.Items {
		jobs <- it
	}
	close(jobs)

	var okCount, errCount atomic.Int64
	var firstErrMu sync.Mutex
	var firstErr string
	var wg sync.WaitGroup
	for i := 0; i < in.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range jobs {
				n, err := d.startNode(context.Background(), it.Hostname, it.AuthKey, it.Kind)
				if err != nil {
					errCount.Add(1)
					firstErrMu.Lock()
					if firstErr == "" {
						firstErr = err.Error()
					}
					firstErrMu.Unlock()
					continue
				}
				okCount.Add(1)
				if it.KeepLive {
					d.mu.Lock()
					d.liveNodes = append(d.liveNodes, n)
					d.totalJoined++
					d.mu.Unlock()
				} else {
					_ = n.srv.Close()
					_ = os.RemoveAll(n.dir)
					d.mu.Lock()
					d.totalJoined++
					d.mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	d.mu.Lock()
	liveCount := len(d.liveNodes) + 3
	total := d.totalJoined
	d.mu.Unlock()

	writeJSON(w, 200, map[string]any{
		"enrolled":     okCount.Load(),
		"errors":       errCount.Load(),
		"first_error":  firstErr,
		"elapsed_ms":   time.Since(t0).Milliseconds(),
		"live_online":  liveCount,
		"total_joined": total,
	})
}

func (d *driver) probeCore(c *http.Client, coreIP string) bool {
	ok, _ := d.probeCoreDetail(c, coreIP)
	return ok
}

func (d *driver) probeCoreDetail(c *http.Client, coreIP string) (bool, string) {
	req, err := http.NewRequest(http.MethodGet, "https://"+coreIP+"/api/me", nil)
	if err != nil {
		return false, err.Error()
	}
	req.Host = "home." + d.zone
	resp, err := c.Do(req)
	if err != nil {
		return false, err.Error()
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == 200 {
		return true, "200"
	}
	return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
}

func (d *driver) adminAction(coreIP, handle, action string) error {
	c := d.meshHTTPClient(d.owner, true, 15*time.Second)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/api/admin/members/%s/%s", coreIP, handle, action), strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Host = "home." + d.zone
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d: %s", action, handle, resp.StatusCode, string(body))
	}
	return nil
}

func (d *driver) handlePropagation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CoreIP string `json:"core_ip"`
		Handle string `json:"handle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if in.Handle == "" {
		in.Handle = "probe-kick"
	}

	// Ensure probe-kick currently succeeds (fresh connections so keepalive doesn't mask ACL drops).
	freshClient := func() *http.Client {
		tr := &http.Transport{
			DialContext:       d.kickProbe.srv.Dial,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		}
		return &http.Client{Transport: tr, Timeout: 1500 * time.Millisecond}
	}

	preOK := false
	for i := 0; i < 20; i++ {
		if d.probeCore(freshClient(), in.CoreIP) {
			preOK = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !preOK {
		writeJSON(w, 500, map[string]any{"error": "probe-kick could not reach core before suspend"})
		return
	}

	tSus := time.Now()
	if err := d.adminAction(in.CoreIP, in.Handle, "suspend"); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	adminSusMS := time.Since(tSus).Milliseconds()
	suspendMS := int64(-1)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if !d.probeCore(freshClient(), in.CoreIP) {
			suspendMS = time.Since(tSus).Milliseconds()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	tRes := time.Now()
	if err := d.adminAction(in.CoreIP, in.Handle, "resume"); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	adminResMS := time.Since(tRes).Milliseconds()
	resumeMS := int64(-1)
	resAttempts := 0
	var lastResErr string
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resAttempts++
		ok, detail := d.probeCoreDetail(freshClient(), in.CoreIP)
		if ok {
			resumeMS = time.Since(tRes).Milliseconds()
			break
		}
		lastResErr = detail
		time.Sleep(100 * time.Millisecond)
	}

	writeJSON(w, 200, map[string]any{
		"admin_suspend_ms": adminSusMS,
		"suspend_ms":       suspendMS,
		"admin_resume_ms":  adminResMS,
		"resume_ms":        resumeMS,
		"resume_attempts":  resAttempts,
		"resume_last_err":  lastResErr,
	})
}

func (d *driver) handleTraffic(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target      string `json:"target"` // "echo" or "portal"
		CoreIP      string `json:"core_ip"`
		Requests    int    `json:"requests"`
		Concurrency int    `json:"concurrency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if in.Requests <= 0 {
		in.Requests = 100
	}
	if in.Concurrency <= 0 {
		in.Concurrency = 10
	}

	d.mu.Lock()
	var clients []*http.Client
	clients = append(clients, d.meshHTTPClient(d.owner, true, 10*time.Second))
	for _, n := range d.liveNodes {
		if n.kind == "personal" {
			clients = append(clients, d.meshHTTPClient(n, true, 10*time.Second))
		}
	}
	targetIP := d.echoServer.ip
	targetHost := "probe-server." + d.zone
	targetPath := "/"
	if in.Target == "portal" {
		targetIP = in.CoreIP
		targetHost = "home." + d.zone
		targetPath = "/api/me"
	}
	d.mu.Unlock()

	t0 := time.Now()
	jobs := make(chan int, in.Requests)
	for i := 0; i < in.Requests; i++ {
		jobs <- i
	}
	close(jobs)

	var mu sync.Mutex
	latencies := make([]int64, 0, in.Requests)
	var errCount atomic.Int64
	var firstErr string
	recordErr := func(s string) {
		errCount.Add(1)
		mu.Lock()
		if firstErr == "" {
			firstErr = s
		}
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for wkr := 0; wkr < in.Concurrency; wkr++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				c := clients[idx%len(clients)]
				st := time.Now()
				req, _ := http.NewRequest(http.MethodGet, "https://"+targetIP+targetPath, nil)
				req.Host = targetHost
				resp, err := c.Do(req)
				if err != nil {
					recordErr(err.Error())
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					recordErr(fmt.Sprintf("HTTP %d", resp.StatusCode))
					continue
				}
				ms := time.Since(st).Milliseconds()
				mu.Lock()
				latencies = append(latencies, ms)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(t0)

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pct := func(p float64) int64 {
		if len(latencies) == 0 {
			return -1
		}
		idx := int(float64(len(latencies)-1) * p)
		return latencies[idx]
	}
	rps := 0.0
	if elapsed > 0 {
		rps = float64(len(latencies)) / elapsed.Seconds()
	}

	writeJSON(w, 200, map[string]any{
		"target":       in.Target,
		"client_nodes": len(clients),
		"ok":           len(latencies),
		"errors":       errCount.Load(),
		"first_error":  firstErr,
		"elapsed_ms":   elapsed.Milliseconds(),
		"rps":          fmt.Sprintf("%.1f", rps),
		"p50_ms":       pct(0.50),
		"p95_ms":       pct(0.95),
		"p99_ms":       pct(0.99),
	})
}

func (d *driver) handleStats(w http.ResponseWriter, r *http.Request) {
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)

	peers := -1
	serverPeers := -1
	if d.owner != nil {
		if lc, err := d.owner.srv.LocalClient(); err == nil {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			if st, err := lc.Status(ctx); err == nil && st != nil {
				peers = len(st.Peer)
			}
			cancel()
		}
	}
	if d.echoServer != nil {
		if lc, err := d.echoServer.srv.LocalClient(); err == nil {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			if st, err := lc.Status(ctx); err == nil && st != nil {
				serverPeers = len(st.Peer)
			}
			cancel()
		}
	}

	d.mu.Lock()
	live := len(d.liveNodes) + 3
	total := d.totalJoined
	d.mu.Unlock()

	writeJSON(w, 200, map[string]any{
		"live_online":         live,
		"total_joined":        total,
		"owner_netmap_peers":  peers,
		"server_netmap_peers": serverPeers,
		"driver_heap_mb":      fmt.Sprintf("%.1f", float64(ms.HeapAlloc)/(1024*1024)),
		"driver_per_node_mb":  fmt.Sprintf("%.2f", float64(ms.HeapAlloc)/(1024*1024)/float64(live)),
	})
}
