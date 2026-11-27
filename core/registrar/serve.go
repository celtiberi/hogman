package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"hogman/registrar/internal/acme"
	"hogman/registrar/internal/api"
	"hogman/registrar/internal/registrar"
)

func healthCmd() error {
	hc := &http.Client{Timeout: 3 * time.Second}
	resp, err := hc.Get("http://" + embeddedHealthAddr + "/healthz")
	if err != nil {
		return fmt.Errorf("embedded mesh health: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("embedded mesh health: HTTP %d", resp.StatusCode)
	}
	pubAddr := env("PUBLIC_ADDR", ":8081")
	if strings.HasPrefix(pubAddr, ":") {
		pubAddr = "127.0.0.1" + pubAddr
	}
	conn, err := net.DialTimeout("tcp", pubAddr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("public API %s: %w", pubAddr, err)
	}
	_ = conn.Close()
	return nil
}

func derpMapCmd() error {
	hc := &http.Client{Timeout: 3 * time.Second}
	resp, err := hc.Get("http://" + embeddedHealthAddr + "/derp-map")
	if err != nil {
		return fmt.Errorf("embedded mesh derp-map: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("embedded mesh derp-map: HTTP %d", resp.StatusCode)
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func waitForInitialSync(ctx context.Context, s *registrar.Service, logger *slog.Logger) bool {
	backoff := time.Second
	for {
		if err := s.Sync(ctx); err == nil {
			logger.Info("in sync with headscale", "zone", s.Zone())
			return true
		} else {
			logger.Warn("waiting for headscale", "err", err)
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
		}
	}
}

func runSyncLoop(ctx context.Context, s *registrar.Service, logger *slog.Logger) {
	fastInterval := durEnv("SYNC_INTERVAL", 3*time.Second)
	if fastInterval <= 0 {
		fastInterval = 3 * time.Second
	}
	idleInterval := durEnv("SYNC_IDLE_INTERVAL", 30*time.Second)
	if idleInterval < fastInterval {
		idleInterval = fastInterval
	}
	t := time.NewTicker(fastInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !s.NeedsFastSync() && s.Clock().Sub(s.LastSyncAt()) < idleInterval {
				continue
			}
			if err := s.Sync(ctx); err != nil {
				logger.Warn("periodic sync failed", "err", err)
			}
		}
	}
}

func watchHomeCertRenewal(ctx context.Context, homeMgr *acme.HomeCertManager, logger *slog.Logger) func() {
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupCh:
				logger.Info("SIGHUP received, forcing certificate renewal", "host", homeMgr.Host())
				if err := homeMgr.ForceRenew(ctx); err != nil {
					logger.Error("forced certificate renewal failed", "host", homeMgr.Host(), "err", err)
				} else {
					logger.Info("forced certificate renewal succeeded", "host", homeMgr.Host())
				}
			}
		}
	}()
	go homeMgr.Run(ctx)
	return func() { signal.Stop(hupCh) }
}

func serve(s *registrar.Service, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Keep detached background workers (especially already-accepted 202
	// SelfRemoveDevice jobs) alive during graceful HTTP shutdown so SIGTERM
	// does not abort committed self-removals mid-flight.
	workerCtx, cancelWorkers := context.WithCancel(context.Background())
	defer cancelWorkers()
	s.SetBaseContext(workerCtx)
	// Always stop accepting new background workers and drain in-flight ones
	// before main() closes SQLite, including on early exit during initial sync.
	defer func() {
		s.BeginShutdown()
		cancelWorkers()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.WaitBackground(shut)
	}()

	tsnetStateDir, err := requireTsnetStateDir(os.Getenv("TSNET_STATE_DIR"))
	if err != nil {
		log.Fatal(err)
	}

	var homeMgr *acme.HomeCertManager
	if homeTLSDir := strings.TrimSpace(os.Getenv("HOME_TLS_DIR")); homeTLSDir != "" {
		mgr, err := acme.NewHomeCertManager(loadHomeCertConfig(s, homeTLSDir, logger))
		if err != nil {
			log.Fatalf("acme home manager: %v", err)
		}
		homeMgr = mgr
		defer homeMgr.Close()
	}

	// Phase 1 of embedded tsnet startup: bring up the core node, write mesh-ip,
	// and start DNS + /healthz (returning 503 not-ready) BEFORE initial Headscale
	// Sync(), so s.CoreIP() is populated and ./hogman up can read mesh-ip,
	// while the :443 portal stays closed until Sync() completes.
	controlURL := env("TSNET_CONTROL_URL", "https://"+s.PublicHost())
	hostname := env("TSNET_HOSTNAME", "core")
	authKeyFile := env("TSNET_AUTH_KEY_FILE", filepath.Join(tsnetStateDir, ".authkey"))
	portalDir := env("PORTAL_DIR", "/srv/portal")
	em, err := startEmbeddedMesh(ctx, s, homeMgr, tsnetStateDir, controlURL, hostname, authKeyFile, portalDir, logger)
	if err != nil {
		log.Fatalf("embedded mesh: %v", err)
	}
	defer func() {
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		em.Shutdown(shut)
	}()

	// Wait for Headscale, backfill node_key/machine_key on existing rows, and
	// take control of policy before serving HTTP (capped backoff: 1s -> 5s).
	if !waitForInitialSync(ctx, s, logger) {
		return
	}

	// Phase 2: now that initial Sync() succeeded, open https://home.<zone>:443
	// and flip /healthz to ready.
	if err := em.StartPortal(ctx); err != nil {
		log.Fatalf("embedded mesh portal: %v", err)
	}

	go runSyncLoop(ctx, s, logger)

	if homeMgr != nil {
		stopHUP := watchHomeCertRenewal(ctx, homeMgr, logger)
		defer stopHUP()
	}

	pub := newHTTPServer(env("PUBLIC_ADDR", ":8081"), api.PublicHandler(s))
	go func() {
		logger.Info("public API listening", "addr", pub.Addr)
		if err := pub.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	// Phase 1: stop accepting new HTTP requests and drain active handlers while
	// workerCtx is still alive.
	httpShut, httpCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = pub.Shutdown(httpShut)
	em.Shutdown(httpShut)
	httpCancel()

	// Phase 2: freeze new background spawns, then give already-accepted workers
	// (such as queued 202 self-deletes) a dedicated drain window to finish
	// Headscale + SQLite + policy cleanup before cancelling workerCtx.
	s.BeginShutdown()
	drainShut, drainCancel := context.WithTimeout(context.Background(), 8*time.Second)
	s.WaitBackground(drainShut)
	drainCancel()
	cancelWorkers()
}
