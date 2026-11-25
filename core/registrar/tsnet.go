package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

const embeddedHealthAddr = "127.0.0.1:8089"

type embeddedMesh struct {
	srv       *tsnet.Server
	dns       *DNSServer
	homeMgr   *HomeCertManager
	portal    *http.Server
	health    *http.Server
	reqCancel context.CancelFunc
	coreV4    netip.Addr
	stateDir  string
	zone      string
	portalDir string
	ready     atomic.Bool
	portalOn  atomic.Bool
	shutOnce  sync.Once
}

// StartPortal opens https://home.<zone>:443 on the embedded tsnet node and
// flips /healthz to ready. Must be called only after the initial Headscale
// Sync() has succeeded so existing device rows have node_key/machine_key
// backfilled and policy control is established.
func (e *embeddedMesh) StartPortal(ctx context.Context) error {
	if e == nil || !e.portalOn.CompareAndSwap(false, true) {
		return nil
	}
	ln443, err := e.srv.Listen("tcp", ":443")
	if err != nil {
		e.portalOn.Store(false)
		return fmt.Errorf("tsnet Listen(tcp, :443): %w", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: e.homeMgr.GetCertificate,
	}
	tlsLn := tls.NewListener(ln443, tlsCfg)
	e.ready.Store(true)
	go func() {
		log.Printf("tsnet: portal + API listening on https://home.%s:443 (dir=%s)", e.zone, e.portalDir)
		if err := e.portal.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
			log.Printf("tsnet portal serve error: %v", err)
		}
	}()
	return nil
}

func (e *embeddedMesh) Shutdown(ctx context.Context) {
	if e == nil {
		return
	}
	e.shutOnce.Do(func() {
		e.ready.Store(false)
		if e.health != nil {
			_ = e.health.Shutdown(ctx)
		}
		if e.portalOn.Load() && e.portal != nil {
			_ = e.portal.Shutdown(ctx)
		}
		if e.reqCancel != nil {
			e.reqCancel()
		}
		if e.srv != nil {
			_ = e.srv.Close()
		}
	})
}

func embeddedHealthzHandler(ready *atomic.Bool, dnsSrv *DNSServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ready.Load() {
			http.Error(w, "not-ready: waiting for initial headscale sync", http.StatusServiceUnavailable)
			return
		}
		if dnsSrv != nil {
			if err := dnsSrv.SelfCheck(); err != nil {
				http.Error(w, "dns: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		if homeTLSDir := strings.TrimSpace(os.Getenv("HOME_TLS_DIR")); homeTLSDir != "" {
			if err := VerifyHomeTLS(homeTLSDir); err != nil {
				http.Error(w, "tls: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}
}

func whoIsPeer(lc *local.Client) func(ctx context.Context, remoteAddr string) (*PeerIdentity, error) {
	return func(ctx context.Context, remoteAddr string) (*PeerIdentity, error) {
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			return nil, err
		}
		want, err := netip.ParseAddr(host)
		if err != nil {
			return nil, err
		}
		want = want.Unmap()
		if !want.Is4() {
			return nil, fmt.Errorf("whois rejected non-IPv4 peer %s", want)
		}
		who, err := lc.WhoIs(ctx, remoteAddr)
		if err != nil {
			return nil, err
		}
		if who == nil || who.Node == nil {
			return nil, errors.New("whois returned no node")
		}
		if who.Node.ID <= 0 || who.Node.Key.IsZero() {
			return nil, errors.New("whois returned incomplete node identity")
		}
		if who.Node.Expired || who.Node.UnsignedPeerAPIOnly || who.Node.IsJailed {
			return nil, errors.New("whois returned expired or restricted node")
		}
		matched := false
		for _, pfx := range who.Node.Addresses {
			if pfx.IsSingleIP() && pfx.Addr().Unmap() == want {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("whois node addresses did not match peer %s", want)
		}
		return &PeerIdentity{
			IP:        want.String(),
			HSNodeID:  strconv.FormatInt(int64(who.Node.ID), 10),
			NodeKey:   who.Node.Key.String(),
			KeyExpiry: who.Node.KeyExpiry,
			Expired:   who.Node.Expired,
		}, nil
	}
}

// configureTestCA sets SSL_CERT_FILE to the test control host's CA root before
// crypto/x509 caches the system root pool. Only active when TEST_MODE=true.
func configureTestCA() {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("TEST_MODE")), "true") {
		return
	}
	if os.Getenv("SSL_CERT_FILE") != "" {
		return
	}
	caFile := env("TSNET_CA_FILE", "/edge-trust/root.crt")
	if caFile == "" {
		return
	}
	if _, err := os.Stat(caFile); err == nil {
		_ = os.Setenv("SSL_CERT_FILE", caFile)
	}
}

// startEmbeddedMesh brings up the pen's core Tailscale node inside the
// registrar process via tsnet, binds IPv4-only authoritative DNS (:53 UDP on
// coreV4 + :53 TCP), and serves the portal + direct API on :443 over TLS.
func startEmbeddedMesh(ctx context.Context, s *Service, homeMgr *HomeCertManager, stateDir, controlURL, hostname, authKeyFile, portalDir string) (*embeddedMesh, error) {
	if strings.TrimSpace(stateDir) == "" {
		return nil, nil
	}
	if strings.TrimSpace(controlURL) == "" {
		return nil, errors.New("tsnet: TSNET_CONTROL_URL is empty")
	}
	if strings.TrimSpace(hostname) == "" {
		hostname = "core"
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("tsnet: mkdir %s: %w", stateDir, err)
	}
	configureTestCA()

	var authKey string
	if authKeyFile != "" {
		if raw, err := os.ReadFile(authKeyFile); err == nil {
			authKey = strings.TrimSpace(string(raw))
		}
	}

	var logMu sync.Mutex
	var recentLogs []string
	srv := &tsnet.Server{
		Hostname:   hostname,
		ControlURL: controlURL,
		AuthKey:    authKey,
		Dir:        stateDir,
		Logf: func(format string, args ...any) {
			line := fmt.Sprintf(format, args...)
			logMu.Lock()
			if len(recentLogs) >= 25 {
				recentLogs = recentLogs[1:]
			}
			recentLogs = append(recentLogs, line)
			logMu.Unlock()
		},
	}

	upTimeout := durEnv("TSNET_UP_TIMEOUT", 2*time.Minute)
	upCtx, cancel := context.WithTimeout(ctx, upTimeout)
	st, err := srv.Up(upCtx)
	cancel()
	if err != nil {
		_ = srv.Close()
		logMu.Lock()
		tail := strings.Join(recentLogs, "\n  ")
		logMu.Unlock()
		if tail != "" {
			return nil, fmt.Errorf("tsnet Up: %w\n  %s", err, tail)
		}
		return nil, fmt.Errorf("tsnet Up: %w", err)
	}
	if authKeyFile != "" && authKey != "" {
		_ = os.Remove(authKeyFile)
	}

	var coreV4 netip.Addr
	for _, ip := range st.TailscaleIPs {
		ip = ip.Unmap()
		if ip.Is4() && !coreV4.IsValid() {
			coreV4 = ip
			break
		}
	}
	if !coreV4.IsValid() {
		_ = srv.Close()
		return nil, errors.New("tsnet Up succeeded but returned no IPv4 address; refusing to serve without DNS IPv4")
	}

	if s.cfg.CoreIP != "" && s.cfg.CoreIP != coreV4.String() {
		log.Printf("tsnet: live IPv4 %s differs from CORE_MESH_IP %s; using live IPv4", coreV4, s.cfg.CoreIP)
	}
	s.cfg.CoreIP = coreV4.String()

	// Publish live IPv4 atomically so ./hogman up and health checks can read it.
	ipPath := filepath.Join(stateDir, "mesh-ip")
	tmpPath := ipPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(coreV4.String()+"\n"), 0o600); err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("tsnet: write mesh-ip: %w", err)
	}
	if err := os.Rename(tmpPath, ipPath); err != nil {
		_ = os.Remove(tmpPath)
		_ = srv.Close()
		return nil, fmt.Errorf("tsnet: rename mesh-ip: %w", err)
	}

	dnsSrv, err := NewDNSServerWithIP(s, coreV4)
	if err != nil {
		_ = srv.Close()
		return nil, err
	}
	// tsnet.ListenPacket requires an explicit IP address (":53" is rejected).
	// Mesh policy and split-DNS are IPv4-only, so bind UDP :53 on coreV4 only.
	udp4Addr := net.JoinHostPort(coreV4.String(), "53")
	udp4, err := srv.ListenPacket("udp", udp4Addr)
	if err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("tsnet ListenPacket(udp, %s): %w", udp4Addr, err)
	}
	udpConns := []net.PacketConn{udp4}
	tcp53, err := srv.Listen("tcp", ":53")
	if err != nil {
		for _, c := range udpConns {
			_ = c.Close()
		}
		_ = srv.Close()
		return nil, fmt.Errorf("tsnet Listen(tcp, :53): %w", err)
	}
	dnsSrv.Serve(ctx, udpConns, tcp53)
	log.Printf("tsnet: core=%s dns listening on :53 (udp/tcp) for %s", coreV4, s.cfg.Zone)

	lc, err := srv.LocalClient()
	if err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("tsnet LocalClient: %w", err)
	}
	if homeMgr == nil {
		_ = srv.Close()
		return nil, errors.New("tsnet: HOME_TLS_DIR is required to serve https://home.<zone>:443")
	}
	apiHandler := MeshHandlerDirect(s, whoIsPeer(lc))
	reqCtx, reqCancel := context.WithCancel(context.Background())
	portalSrv := &http.Server{
		Handler:           PortalHandler(s.cfg.Zone, portalDir, apiHandler),
		BaseContext:       func(net.Listener) context.Context { return reqCtx },
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	em := &embeddedMesh{
		srv:       srv,
		dns:       dnsSrv,
		homeMgr:   homeMgr,
		portal:    portalSrv,
		reqCancel: reqCancel,
		coreV4:    coreV4,
		stateDir:  stateDir,
		zone:      s.cfg.Zone,
		portalDir: portalDir,
	}

	// Internal loopback health server queried by `registrar health`.
	// Returns 503 not-ready until StartPortal() runs after the initial Headscale Sync().
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", embeddedHealthzHandler(&em.ready, dnsSrv))
	healthMux.HandleFunc("/derp-map", func(w http.ResponseWriter, r *http.Request) {
		dm, err := lc.CurrentDERPMap(r.Context())
		if err != nil {
			http.Error(w, "derp-map: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		if dm == nil {
			http.Error(w, "derp-map: not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(dm)
	})
	healthLn, err := net.Listen("tcp", embeddedHealthAddr)
	if err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("tsnet health listen %s: %w", embeddedHealthAddr, err)
	}
	healthSrv := &http.Server{Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
	em.health = healthSrv
	go func() {
		if err := healthSrv.Serve(healthLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("tsnet health serve error: %v", err)
		}
	}()

	return em, nil
}
