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
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

const embeddedHealthAddr = "127.0.0.1:8089"

type embeddedMesh struct {
	srv      *tsnet.Server
	dns      *DNSServer
	portal   *http.Server
	health   *http.Server
	coreV4   netip.Addr
	coreV6   netip.Addr
	stateDir string
}

func (e *embeddedMesh) Shutdown(ctx context.Context) {
	if e == nil {
		return
	}
	if e.health != nil {
		_ = e.health.Shutdown(ctx)
	}
	if e.portal != nil {
		_ = e.portal.Shutdown(ctx)
	}
	if e.srv != nil {
		_ = e.srv.Close()
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
		matched := false
		for _, pfx := range who.Node.Addresses {
			if pfx.Addr().Unmap() == want {
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
// registrar process via tsnet, binds authoritative DNS (:53 UDP on the node's
// own IPv4 and optional IPv6 + :53 TCP), and serves the portal + direct API
// on :443 over TLS.
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

	var coreV4, coreV6 netip.Addr
	for _, ip := range st.TailscaleIPs {
		ip = ip.Unmap()
		if ip.Is4() && !coreV4.IsValid() {
			coreV4 = ip
		} else if ip.Is6() && !coreV6.IsValid() {
			coreV6 = ip
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

	dnsSrv, err := NewDNSServerWithIPs(s, coreV4, coreV6)
	if err != nil {
		_ = srv.Close()
		return nil, err
	}
	// tsnet.ListenPacket requires an explicit IP address (":53" is rejected).
	udp4Addr := net.JoinHostPort(coreV4.String(), "53")
	udp4, err := srv.ListenPacket("udp", udp4Addr)
	if err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("tsnet ListenPacket(udp, %s): %w", udp4Addr, err)
	}
	udpConns := []net.PacketConn{udp4}
	if coreV6.IsValid() {
		udp6Addr := net.JoinHostPort(coreV6.String(), "53")
		if udp6, err := srv.ListenPacket("udp", udp6Addr); err != nil {
			log.Printf("tsnet: IPv6 DNS listen on %s skipped: %v", udp6Addr, err)
		} else {
			udpConns = append(udpConns, udp6)
		}
	}
	tcp53, err := srv.Listen("tcp", ":53")
	if err != nil {
		for _, c := range udpConns {
			_ = c.Close()
		}
		_ = srv.Close()
		return nil, fmt.Errorf("tsnet Listen(tcp, :53): %w", err)
	}
	dnsSrv.Serve(ctx, udpConns, tcp53)
	log.Printf("tsnet: core=%s (v6=%v) dns listening on :53 (udp/tcp) for %s", coreV4, coreV6, s.cfg.Zone)

	lc, err := srv.LocalClient()
	if err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("tsnet LocalClient: %w", err)
	}
	ln443, err := srv.Listen("tcp", ":443")
	if err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("tsnet Listen(tcp, :443): %w", err)
	}
	if homeMgr == nil {
		_ = ln443.Close()
		_ = srv.Close()
		return nil, errors.New("tsnet: HOME_TLS_DIR is required to serve https://home.<zone>:443")
	}
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: homeMgr.GetCertificate,
	}
	tlsLn := tls.NewListener(ln443, tlsCfg)
	apiHandler := MeshHandlerDirect(s, whoIsPeer(lc))
	portalSrv := &http.Server{
		Handler:           PortalHandler(s.cfg.Zone, portalDir, apiHandler),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		log.Printf("tsnet: portal + API listening on https://home.%s:443 (dir=%s)", s.cfg.Zone, portalDir)
		if err := portalSrv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
			log.Printf("tsnet portal serve error: %v", err)
		}
	}()

	// Internal loopback health server queried by `registrar health`.
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := dnsSrv.SelfCheck(); err != nil {
			http.Error(w, "dns: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		if homeTLSDir := strings.TrimSpace(os.Getenv("HOME_TLS_DIR")); homeTLSDir != "" {
			if err := VerifyHomeTLS(homeTLSDir); err != nil {
				http.Error(w, "tls: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
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
		_ = portalSrv.Close()
		_ = srv.Close()
		return nil, fmt.Errorf("tsnet health listen %s: %w", embeddedHealthAddr, err)
	}
	healthSrv := &http.Server{Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := healthSrv.Serve(healthLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("tsnet health serve error: %v", err)
		}
	}()

	return &embeddedMesh{
		srv:      srv,
		dns:      dnsSrv,
		portal:   portalSrv,
		health:   healthSrv,
		coreV4:   coreV4,
		coreV6:   coreV6,
		stateDir: stateDir,
	}, nil
}
