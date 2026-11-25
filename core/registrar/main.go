// Command registrar is the source of truth for one Hogman network: members,
// invites, devices, names, removal and the audit log. It drives Headscale
// (devices, access policy) and serves authoritative DNS for the network's zone.
//
// The same binary is the server ("registrar serve") and the owner's command
// line on the core node ("registrar member kick alice").
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s is not set", k)
	}
	return v
}

func durEnv(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("%s: %v", k, err)
		}
		return d
	}
	return def
}

func propTimeoutEnv(k string) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return 0
	}
	if v == "-1" {
		return -1
	}
	return durEnv(k, 0)
}

func parseCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func setup() *Service {
	var coreIP string
	if tsDir := strings.TrimSpace(os.Getenv("TSNET_STATE_DIR")); tsDir != "" {
		coreIP = strings.TrimSpace(os.Getenv("CORE_MESH_IP"))
		if coreIP == "" {
			if raw, err := os.ReadFile(filepath.Join(tsDir, "mesh-ip")); err == nil {
				coreIP = strings.TrimSpace(string(raw))
			}
		}
	} else {
		coreIP = mustEnv("CORE_MESH_IP")
	}
	var acmeBackend ACMEBackend
	if chURL := strings.TrimSpace(os.Getenv("CHALLENGE_DNS_URL")); chURL != "" {
		tokPath := env("CHALLENGE_DNS_TOKEN_FILE", "/secrets/challenge_dns_token")
		tokBytes, err := os.ReadFile(tokPath)
		if err != nil {
			log.Fatalf("challenge DNS token %s: %v", tokPath, err)
		}
		cli, err := NewChallengeDNSClient(chURL, string(tokBytes))
		if err != nil {
			log.Fatalf("challenge DNS client: %v", err)
		}
		acmeBackend = cli
	}
	dbPath := env("DB", "/var/lib/registrar/registrar.db")
	cfg := Config{
		Zone:              mustEnv("ZONE"),
		PublicHost:        mustEnv("PUBLIC_HOST"),
		CoreIP:            coreIP,
		Theme:             env("THEME", ""),
		InviteTTL:         durEnv("INVITE_TTL", 7*24*time.Hour),
		DeviceKeyTTL:      durEnv("DEVICE_KEY_TTL", time.Hour),
		MembersCanInvite:  env("MEMBERS_CAN_INVITE", "false") == "true",
		BillingStatusPath: env("BILLING_STATUS_FILE", filepath.Join(filepath.Dir(dbPath), "billing-status.json")),
		ACMEBackend:       acmeBackend,
	}
	key, err := os.ReadFile(env("HEADSCALE_API_KEY_FILE", "/secrets/headscale_api_key"))
	if err != nil {
		log.Fatalf("headscale API key: %v", err)
	}
	st, err := OpenStore(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	hs := NewHeadscale(env("HEADSCALE_URL", "http://headscale:8080"), strings.TrimSpace(string(key)))
	svc, err := NewService(cfg, st, hs)
	if err != nil {
		log.Fatal(err)
	}
	return svc
}

func healthCmd() error {
	if strings.TrimSpace(os.Getenv("TSNET_STATE_DIR")) != "" {
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
	if homeTLSDir := strings.TrimSpace(os.Getenv("HOME_TLS_DIR")); homeTLSDir != "" {
		if err := VerifyHomeTLS(homeTLSDir); err != nil {
			return err
		}
	}
	meshAddr := env("MESH_ADDR", "127.0.0.1:8082")
	netw, addr := "tcp", meshAddr
	if sock, ok := strings.CutPrefix(meshAddr, "unix:"); ok {
		netw, addr = "unix", sock
	}
	conn, err := net.DialTimeout(netw, addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("mesh API %s: %w", meshAddr, err)
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

func main() {
	log.SetFlags(0)
	configureTestCA()
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return
	}
	if args[0] == "health" {
		if err := healthCmd(); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	}
	if args[0] == "derp-map" {
		if err := derpMapCmd(); err != nil {
			fmt.Fprintln(os.Stderr, "derp-map:", err)
			os.Exit(1)
		}
		return
	}
	if args[0] == "gate-cert" {
		if err := gateCertCmd(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "gate-cert:", err)
			os.Exit(1)
		}
		return
	}
	if args[0] == "serve" {
		s := setup()
		defer s.st.Close()
		serve(s)
		return
	}
	s := setup()
	err := cli(context.Background(), s, args)
	_ = s.st.Close()
	if err != nil {
		var p *Problem
		if errors.As(err, &p) {
			fmt.Fprintln(os.Stderr, "error:", p.Msg)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

// ----------------------------------------------------------------- server --

// validateServeMode enforces that production serve requires TSNET_STATE_DIR
// unless explicitly configured for legacy Unix-socket test/migration mode.
func validateServeMode(tsnetStateDir, legacyFlag, meshAddr string) (legacy bool, err error) {
	tsnetStateDir = strings.TrimSpace(tsnetStateDir)
	legacy = strings.TrimSpace(legacyFlag) == "1"
	meshAddr = strings.TrimSpace(meshAddr)
	if tsnetStateDir == "" && !legacy {
		return false, errors.New("TSNET_STATE_DIR is required (set REGISTRAR_LEGACY_MESH_SOCKET=1 only for legacy test/migration harnesses)")
	}
	if tsnetStateDir != "" && legacy {
		return false, errors.New("TSNET_STATE_DIR and REGISTRAR_LEGACY_MESH_SOCKET=1 are mutually exclusive")
	}
	if legacy {
		sock, ok := strings.CutPrefix(meshAddr, "unix:")
		if !ok || strings.TrimSpace(sock) == "" {
			return false, fmt.Errorf("REGISTRAR_LEGACY_MESH_SOCKET=1 requires MESH_ADDR starting with unix:<path> (got %q)", meshAddr)
		}
	}
	return legacy, nil
}

func serve(s *Service) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Keep detached background workers (especially already-accepted 202
	// ScheduleSelfDelete jobs) alive during graceful HTTP shutdown so SIGTERM
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

	tsnetStateDir := strings.TrimSpace(os.Getenv("TSNET_STATE_DIR"))
	legacyMeshAddr := strings.TrimSpace(os.Getenv("MESH_ADDR"))
	legacySocket, err := validateServeMode(tsnetStateDir, os.Getenv("REGISTRAR_LEGACY_MESH_SOCKET"), legacyMeshAddr)
	if err != nil {
		log.Fatal(err)
	}
	if legacySocket {
		log.Printf("WARN: REGISTRAR_LEGACY_MESH_SOCKET=1 enabled (test/migration only; trusting X-Forwarded-For over %s)", legacyMeshAddr)
	}

	// Legacy mode (REGISTRAR_LEGACY_MESH_SOCKET=1): start OS-socket DNS first.
	if legacySocket {
		if dnsAddr := env("DNS_ADDR", ":53"); dnsAddr != "" && dnsAddr != "off" {
			dnsSrv, err := NewDNSServer(s)
			if err != nil {
				log.Fatalf("dns: %v", err)
			}
			if err := dnsSrv.Start(ctx, dnsAddr); err != nil {
				log.Fatalf("dns on %s: %v", dnsAddr, err)
			}
			log.Printf("dns listening on %s (udp/tcp) for %s", dnsAddr, s.cfg.Zone)
		}
	}

	var homeMgr *HomeCertManager
	if homeTLSDir := strings.TrimSpace(os.Getenv("HOME_TLS_DIR")); homeTLSDir != "" {
		mgr, err := NewHomeCertManager(HomeConfig{
			Zone:               s.cfg.Zone,
			HomeTLSDir:         homeTLSDir,
			CaddyAdminSocket:   strings.TrimSpace(os.Getenv("CADDY_ADMIN_SOCKET")),
			StorageDir:         env("ACME_STORAGE_DIR", "/var/lib/registrar/acme"),
			PrimaryCA:          strings.TrimSpace(os.Getenv("ACME_CA_URL")),
			FallbackCA:         strings.TrimSpace(os.Getenv("ACME_FALLBACK_CA_URL")),
			Email:              strings.TrimSpace(os.Getenv("ACME_EMAIL")),
			CARootFile:         strings.TrimSpace(os.Getenv("ACME_CA_ROOT")),
			Resolvers:          parseCSV(os.Getenv("ACME_RESOLVERS")),
			PropagationDelay:   durEnv("ACME_PROPAGATION_DELAY", 0),
			PropagationTimeout: propTimeoutEnv("ACME_PROPAGATION_TIMEOUT"),
			Backend:            s.acme,
			BillingStatusPath:  s.cfg.BillingStatusPath,
		})
		if err != nil {
			log.Fatalf("acme home manager: %v", err)
		}
		homeMgr = mgr
		defer homeMgr.Close()
	}

	// Phase 1 of embedded tsnet startup: bring up the core node, write mesh-ip,
	// and start DNS + /healthz (returning 503 not-ready) BEFORE initial Headscale
	// Sync(), so s.cfg.CoreIP is populated and ./hogman up can read mesh-ip,
	// while the :443 portal stays closed until Sync() completes.
	var em *embeddedMesh
	if tsnetStateDir != "" {
		controlURL := env("TSNET_CONTROL_URL", "https://"+s.cfg.PublicHost)
		hostname := env("TSNET_HOSTNAME", "core")
		authKeyFile := env("TSNET_AUTH_KEY_FILE", filepath.Join(tsnetStateDir, ".authkey"))
		portalDir := env("PORTAL_DIR", "/srv/portal")
		var err error
		em, err = startEmbeddedMesh(ctx, s, homeMgr, tsnetStateDir, controlURL, hostname, authKeyFile, portalDir)
		if err != nil {
			log.Fatalf("embedded mesh: %v", err)
		}
		defer func() {
			shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			em.Shutdown(shut)
		}()
	}

	// Wait for Headscale, backfill node_key/machine_key on existing rows, and
	// take control of policy before serving HTTP (capped backoff: 1s -> 5s).
	backoff := time.Second
	for {
		if err := s.Sync(ctx); err == nil {
			break
		} else {
			log.Printf("waiting for headscale: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
		}
	}
	log.Printf("registrar for %s: in sync with headscale", s.cfg.Zone)

	// Phase 2: now that initial Sync() succeeded, open https://home.<zone>:443
	// and flip /healthz to ready.
	if em != nil {
		if err := em.StartPortal(ctx); err != nil {
			log.Fatalf("embedded mesh portal: %v", err)
		}
	}

	go func() {
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
				if !s.NeedsFastSync() && s.clock().Sub(s.LastSyncAt()) < idleInterval {
					continue
				}
				if err := s.Sync(ctx); err != nil {
					log.Printf("sync: %v", err)
				}
			}
		}
	}()

	if homeMgr != nil {
		hupCh := make(chan os.Signal, 1)
		signal.Notify(hupCh, syscall.SIGHUP)
		defer signal.Stop(hupCh)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-hupCh:
					log.Printf("acme: SIGHUP received, forcing certificate renewal for %s", homeMgr.host)
					if err := homeMgr.ForceRenew(ctx); err != nil {
						log.Printf("acme: forced renewal for %s failed: %v", homeMgr.host, err)
					} else {
						log.Printf("acme: forced renewal for %s succeeded", homeMgr.host)
					}
				}
			}
		}()
		go homeMgr.Run(ctx)
	}

	pub := &http.Server{Addr: env("PUBLIC_ADDR", ":8081"), Handler: PublicHandler(s),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		log.Printf("listening on %s", pub.Addr)
		if err := pub.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	var mesh *http.Server
	if legacySocket {
		mesh = &http.Server{Addr: legacyMeshAddr, Handler: MeshHandler(s),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
			ConnContext: markSocketConn}
		ln, err := listenMesh(mesh.Addr)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			log.Printf("mesh API listening on %s", mesh.Addr)
			if err := mesh.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatal(err)
			}
		}()
	}

	<-ctx.Done()
	// Phase 1: stop accepting new HTTP requests and drain active handlers while
	// workerCtx is still alive.
	httpShut, httpCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = pub.Shutdown(httpShut)
	if mesh != nil {
		_ = mesh.Shutdown(httpShut)
	}
	if em != nil {
		em.Shutdown(httpShut)
	}
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

// -------------------------------------------------------------------- cli --

const usage = `registrar: members, invites, devices and names for one Hogman network

  serve                                  run the server
  health                                 check mesh socket and home TLS readiness

  member add <handle> [--role owner|admin|member]
  member list
  member suspend <handle> [reason...]    cut off all their devices; reversible
  member resume <handle>
  member kick <handle> [reason...]       end the membership (DESIGN.md section 9)
  member role <handle> <role>

  invite create [--role member|admin] [--ttl 168h] [--note text]
  invite list
  invite revoke <id>

  device key <handle> personal|server    one-time key to join a device (personal: a member's
                                         first device only; there is no account recovery)
  device list
  device rm <id>

  name list
  name claim <handle> <name> <device-id> [--note text]
  name release <name>

  audit [count]
  sync                                   reconcile with headscale now
`

// splitFlags pulls "--name value" pairs out of args, wherever they appear.
func splitFlags(args []string) (pos []string, flags map[string]string) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") && i+1 < len(args) {
			flags[strings.TrimPrefix(args[i], "--")] = args[i+1]
			i++
			continue
		}
		pos = append(pos, args[i])
	}
	return
}

func need(pos []string, n int, use string) error {
	if len(pos) < n {
		return bad("usage: registrar %s", use)
	}
	return nil
}

func table(rows [][]string) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	tw.Flush()
}

func ts(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02 15:04") }

func cli(ctx context.Context, s *Service, args []string) error {
	a := Actor{CLI: true}
	pos, flags := splitFlags(args)
	if len(pos) < 1 {
		return bad("missing command")
	}
	sub := ""
	if len(pos) > 1 {
		sub = pos[1]
	}
	rest := []string{}
	if len(pos) > 2 {
		rest = pos[2:]
	}
	switch pos[0] + " " + sub {

	case "member add":
		if err := need(rest, 1, "member add <handle> [--role r]"); err != nil {
			return err
		}
		role := flags["role"]
		if role == "" {
			role = "member"
		}
		m, err := s.AddMember(ctx, a, rest[0], role)
		if err != nil {
			return err
		}
		fmt.Printf("added %s (%s)\n", m.Handle, m.Role)
	case "member list":
		ms, err := s.st.Members()
		if err != nil {
			return err
		}
		rows := [][]string{{"ID", "HANDLE", "ROLE", "STATUS", "INVITED BY", "JOINED"}}
		byID := map[int64]string{}
		for _, m := range ms {
			byID[m.ID] = m.Handle
		}
		for _, m := range ms {
			inv := "-"
			if m.InvitedBy != nil {
				inv = byID[*m.InvitedBy]
			}
			rows = append(rows, []string{strconv.FormatInt(m.ID, 10), m.Handle, m.Role, m.Status, inv, ts(m.CreatedAt)})
		}
		table(rows)
	case "member suspend":
		if err := need(rest, 1, "member suspend <handle> [reason]"); err != nil {
			return err
		}
		if err := s.Suspend(ctx, a, rest[0], strings.Join(rest[1:], " ")); err != nil {
			return err
		}
		fmt.Printf("suspended %s\n", rest[0])
	case "member resume":
		if err := need(rest, 1, "member resume <handle>"); err != nil {
			return err
		}
		if err := s.Resume(ctx, a, rest[0]); err != nil {
			return err
		}
		fmt.Printf("resumed %s\n", rest[0])
	case "member kick":
		if err := need(rest, 1, "member kick <handle> [reason]"); err != nil {
			return err
		}
		rep, err := s.Kick(ctx, a, rest[0], strings.Join(rest[1:], " "))
		if err != nil {
			return err
		}
		fmt.Printf("removed %s: %d devices deleted, %d keys and %d invites revoked, %d names retired\n",
			rest[0], rep.Devices, rep.Keys, rep.Invites, rep.NamesRetired)
	case "member role":
		if err := need(rest, 2, "member role <handle> <role>"); err != nil {
			return err
		}
		if err := s.SetRole(ctx, a, rest[0], rest[1]); err != nil {
			return err
		}
		fmt.Printf("%s is now %s\n", rest[0], rest[1])

	case "invite create":
		var ttl time.Duration
		if v := flags["ttl"]; v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return bad("--ttl: %v", err)
			}
			ttl = d
		}
		inv, err := s.MintInvite(a, flags["role"], flags["note"], ttl)
		if err != nil {
			return err
		}
		fmt.Printf("invite %d (%s), expires %s\n", inv.ID, inv.Role, ts(inv.ExpiresAt))
		fmt.Printf("token: %s\n", inv.Token)
		fmt.Printf("link:  %s\n", inv.URL)
	case "invite list":
		invs, err := s.st.Invites(nil)
		if err != nil {
			return err
		}
		names := handles(s)
		rows := [][]string{{"ID", "ROLE", "STATE", "MINTED BY", "REDEEMED BY", "EXPIRES", "NOTE"}}
		for _, i := range invs {
			rows = append(rows, []string{strconv.FormatInt(i.ID, 10), i.Role, i.State(),
				nameOr(names, i.MintedBy, "owner@cli"), nameOr(names, i.RedeemedBy, "-"), ts(i.ExpiresAt), i.Note})
		}
		table(rows)
	case "invite revoke":
		if err := need(rest, 1, "invite revoke <id>"); err != nil {
			return err
		}
		id, _ := strconv.ParseInt(rest[0], 10, 64)
		if err := s.RevokeInvite(a, id); err != nil {
			return err
		}
		fmt.Printf("revoked invite %d\n", id)

	case "device key":
		if err := need(rest, 2, "device key <handle> personal|server"); err != nil {
			return err
		}
		key, exp, err := s.IssueDeviceKey(ctx, a, rest[0], rest[1])
		if err != nil {
			return err
		}
		fmt.Printf("key:   %s\n", key)
		fmt.Printf("link:  %s\n", s.DeviceLink(key, rest[1]))
		fmt.Printf("valid until %s, single use\n", ts(exp))
	case "device list":
		ds, err := s.st.LiveDevices()
		if err != nil {
			return err
		}
		rows := [][]string{{"ID", "MEMBER", "KIND", "NAME", "IPV4", "JOINED"}}
		for _, d := range ds {
			rows = append(rows, []string{strconv.FormatInt(d.ID, 10), d.Member, d.Kind, d.Name, d.IPv4, ts(d.CreatedAt)})
		}
		table(rows)
	case "device rm":
		if err := need(rest, 1, "device rm <id>"); err != nil {
			return err
		}
		id, _ := strconv.ParseInt(rest[0], 10, 64)
		if err := s.RemoveDevice(ctx, a, id); err != nil {
			return err
		}
		fmt.Printf("removed device %d\n", id)

	case "name list":
		ns, err := s.st.Names()
		if err != nil {
			return err
		}
		rows := [][]string{{"NAME", "MEMBER", "POINTS AT", "STATE", "NOTE"}}
		for _, n := range ns {
			state, at := "active", n.IPv4
			if n.RetiredAt != nil {
				state = "retired"
			}
			if at == "" {
				at = "-"
			}
			rows = append(rows, []string{n.Name + "." + s.cfg.Zone, n.Member, at, state, n.Note})
		}
		table(rows)
	case "name claim":
		if err := need(rest, 3, "name claim <handle> <name> <device-id> [--note text]"); err != nil {
			return err
		}
		id, _ := strconv.ParseInt(rest[2], 10, 64)
		var note *string
		if v, ok := flags["note"]; ok {
			note = &v
		}
		fqdn, err := s.Claim(a, rest[0], rest[1], id, note)
		if err != nil {
			return err
		}
		fmt.Printf("%s -> device %d\n", fqdn, id)
	case "name release":
		if err := need(rest, 1, "name release <name>"); err != nil {
			return err
		}
		if err := s.Release(a, rest[0]); err != nil {
			return err
		}
		fmt.Printf("released %s\n", rest[0])

	default:
		switch pos[0] {
		case "audit":
			n := 50
			if sub != "" {
				n, _ = strconv.Atoi(sub)
			}
			log, err := s.st.AuditLog(n)
			if err != nil {
				return err
			}
			rows := [][]string{{"WHEN", "ACTOR", "ACTION", "TARGET", "DETAIL"}}
			for i := len(log) - 1; i >= 0; i-- {
				e := log[i]
				rows = append(rows, []string{ts(e.At), e.Actor, e.Action, e.Target, e.Detail})
			}
			table(rows)
			return nil
		case "sync":
			if err := s.Sync(ctx); err != nil {
				return err
			}
			fmt.Println("in sync")
			return nil
		}
		fmt.Print(usage)
		return bad("unknown command %q", strings.TrimSpace(pos[0]+" "+sub))
	}
	return nil
}

func handles(s *Service) map[int64]string {
	out := map[int64]string{}
	ms, _ := s.st.Members()
	for _, m := range ms {
		out[m.ID] = m.Handle
	}
	return out
}

func nameOr(names map[int64]string, id *int64, def string) string {
	if id == nil {
		return def
	}
	return names[*id]
}

// gateCertCmd keeps the host's front-door wildcard certificate (D-18): by
// default *.gate.hogman.network, by DNS-01 through the host's challenge DNS
// server with the host credential (which may write only the gate challenge
// name). It writes gate.crt and gate.key into GATE_TLS_DIR; a systemd path
// unit on the host reloads the front door when they change. It needs nothing
// else from a pen: no database, no Headscale.
//
//	registrar gate-cert           run, renewing until stopped
//	registrar gate-cert health    exit 0 if a valid certificate is in place
func gateCertCmd(args []string) error {
	dir := env("GATE_TLS_DIR", "/var/lib/hogman-gate/tls")
	if len(args) == 1 && args[0] == "health" {
		return VerifyTLSFiles(dir, "gate")
	}
	if len(args) != 0 {
		return errors.New("usage: registrar gate-cert [health]")
	}
	chURL := strings.TrimSpace(os.Getenv("CHALLENGE_DNS_URL"))
	if chURL == "" {
		chURL = "unix:///run/hogman-acme/api.sock"
	}
	tokPath := env("CHALLENGE_DNS_TOKEN_FILE", "/etc/hogman/gate-challenge-token")
	tok, err := os.ReadFile(tokPath)
	if err != nil {
		return fmt.Errorf("challenge DNS token %s: %w", tokPath, err)
	}
	backend, err := NewChallengeDNSClient(chURL, string(tok))
	if err != nil {
		return err
	}
	mgr, err := NewHomeCertManager(HomeConfig{
		Host:               env("GATE_HOST", "*.gate.hogman.network"),
		FileBase:           "gate",
		HomeTLSDir:         dir,
		StorageDir:         env("ACME_STORAGE_DIR", "/var/lib/hogman-gate/acme"),
		PrimaryCA:          strings.TrimSpace(os.Getenv("ACME_CA_URL")),
		FallbackCA:         strings.TrimSpace(os.Getenv("ACME_FALLBACK_CA_URL")),
		Email:              strings.TrimSpace(os.Getenv("ACME_EMAIL")),
		CARootFile:         strings.TrimSpace(os.Getenv("ACME_CA_ROOT")),
		Resolvers:          parseCSV(os.Getenv("ACME_RESOLVERS")),
		PropagationDelay:   durEnv("ACME_PROPAGATION_DELAY", 0),
		PropagationTimeout: propTimeoutEnv("ACME_PROPAGATION_TIMEOUT"),
		Backend:            backend,
	})
	if err != nil {
		return err
	}
	defer mgr.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("gate-cert: keeping %s in %s", mgr.host, dir)
	mgr.Run(ctx)
	return nil
}
