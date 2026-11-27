// challenge-dns: the authoritative DNS server for ACME DNS-01 challenges
// under the delegated pens zone and the front door's challenge name, with a
// small API that lets each pen write only its own challenge records.
// Design: docs/security/public-certificates.md.
//
//	challenge-dns serve
//	challenge-dns cred add pen <penname> | cred add host | cred rm <id> | cred list
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const usage = `challenge-dns: DNS-01 challenge server for Hogman pens

  challenge-dns serve
  challenge-dns cred add pen <penname> [--plan personal|work]
                                         a credential for one pen (prints its token once)
  challenge-dns cred add host            the front door's credential (gate wildcard)
  challenge-dns cred plan <id-or-pen> personal|work
                                         change a pen credential's certificate cap plan
  challenge-dns cred rm <id> [--release-if-unused]
  challenge-dns cred list
  challenge-dns name used <penname>      prints "used" (exit 0) if the name was ever given out

Settings (environment):
  CDNS_LISTEN        public address for DNS, e.g. 203.0.113.10:53 (required to serve)
  CDNS_PENS_ZONE     default pens.hogman.network
  CDNS_GATE_NAME     default _acme-challenge.gate.hogman.network
  CDNS_NS            default ns1.hogman.network
  CDNS_MBOX          default hostmaster.hogman.network
  CDNS_STATE         default /var/lib/challenge-dns/state.json
  CDNS_API_SOCK      default /run/hogman-acme/api.sock (registrars)
  CDNS_API_GID       group allowed on the API socket, default 65532
  CDNS_ADMIN_SOCK    default /run/challenge-dns/admin.sock (root only)
  CDNS_HTTP_ADDR     optional TCP address for the API (tests and development only)
  CDNS_GCP_KEY       optional Google service-account key file (fallback CA)
  CDNS_GTS_CONTACT   contact email for fallback CA (Google) accounts; required for
                     handing out fallback account keys (Google refuses accounts without one)
  CDNS_HOURLY_CAP       distinct new certificate names per personal pen per rolling hour, default 5
  CDNS_WEEKLY_CAP       distinct new certificate names per personal pen per 7 days, default 20
  CDNS_WORK_HOURLY_CAP  distinct new certificate names per work pen per rolling hour, default 40
  CDNS_WORK_WEEKLY_CAP  distinct new certificate names per work pen per 7 days, default 120
  CDNS_GLOBAL_HOURLY_CAP       soft global cap across all pens per rolling hour, default 80
  CDNS_GLOBAL_HARD_HOURLY_CAP  hard global cap across all pens per rolling hour (headroom above soft
                               is reserved for quiet/new pens with <2 names this hour), default 120
  CDNS_LE_WEEKLY_ALLOWANCE     Let's Encrypt 7-day registered-domain allowance (alerts at 80%), default 300
  CDNS_NTFY_URL                optional https:// ntfy topic URL for the 80% global 7-day budget alert
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(2)
	}
	var err error
	switch args[0] {
	case "serve":
		err = serve()
	case "cred":
		err = credCmd(args[1:])
	case "name":
		err = nameCmd(args[1:])
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "challenge-dns:", err)
		os.Exit(1)
	}
}

func newNtfyAlerter(ntfyURL string, hc *http.Client, logger *slog.Logger) func(used, allowance, threshold int) {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	log := defaultLogger(logger)
	sem := make(chan struct{}, 2)
	return func(used, allowance, threshold int) {
		pct := 0
		if allowance > 0 {
			pct = (used * 100) / allowance
		}
		msg := fmt.Sprintf("Hogman challenge-dns: %d/%d (%d%%) of Let's Encrypt 7-day certificate allowance used across all pens (alert threshold %d). Google Trust Services fallback handles HTTP 429 overflow automatically.",
			used, allowance, pct, threshold)
		log.Warn("weekly certificate budget alert",
			"used", used,
			"allowance", allowance,
			"pct", pct,
			"threshold", threshold,
		)
		if ntfyURL == "" {
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			log.Warn("ntfy alert skipped: too many pushes in flight")
			return
		}
		go func() {
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, ntfyURL, strings.NewReader(msg))
			if err != nil {
				log.Error("ntfy build request failed", "err", err)
				return
			}
			req.Header.Set("Title", "Hogman: Let's Encrypt 7-day cert budget >= 80%")
			req.Header.Set("Priority", "high")
			req.Header.Set("Tags", "warning")
			resp, err := hc.Do(req)
			if err != nil {
				log.Error("ntfy push failed", "err", err)
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode >= 300 {
				log.Error("ntfy push returned non-2xx", "status", resp.StatusCode)
			}
		}()
	}
}

func configureFallbackEAB(ctx context.Context, api *API, gcpKeyFile, testEABFile, rawContact string, logger *slog.Logger) error {
	log := defaultLogger(logger)
	if gcpKeyFile != "" && testEABFile != "" {
		return errors.New("CDNS_GCP_KEY and CDNS_TEST_EAB_FILE are mutually exclusive")
	}
	if gcpKeyFile == "" && testEABFile == "" {
		return nil
	}
	if testEABFile != "" {
		m, err := loadTestEABMinter(testEABFile, log)
		if err != nil {
			return err
		}
		api.eab = m
	} else {
		m, err := newGCPMinter(ctx, gcpKeyFile)
		if err != nil {
			return fmt.Errorf("CDNS_GCP_KEY: %w", err)
		}
		api.eab = m
		log.Info("fallback CA account keys configured", "gcp_project", m.project)
	}
	contact, err := parseContact(rawContact)
	if err != nil {
		return err
	}
	if api.contact = contact; contact == "" {
		log.Warn("CDNS_GTS_CONTACT is not set; Google refuses accounts without a contact, so no fallback account keys will be handed out")
	} else {
		log.Info("fallback CA account contact configured", "contact", contact)
	}
	return nil
}

func serve() error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	listen := os.Getenv("CDNS_LISTEN")
	if listen == "" {
		return errors.New("set CDNS_LISTEN to the public address to answer on, e.g. 203.0.113.10:53 (not 127.0.0.53, where systemd-resolved sits)")
	}
	caps, err := CapsConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	ntfyURL, err := parseNtfyURL(os.Getenv("CDNS_NTFY_URL"))
	if err != nil {
		return err
	}
	zones := zonesFromEnv()
	statePath := env("CDNS_STATE", "/var/lib/challenge-dns/state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return err
	}
	store, err := OpenStore(statePath, zones)
	if err != nil {
		return err
	}
	store.caps = caps
	store.onWeeklyAlert = newNtfyAlerter(ntfyURL, nil, logger)
	logger.Info("certificate caps configured",
		"personal_hourly", caps.Hourly(),
		"personal_weekly", caps.Weekly(),
		"work_hourly", caps.WorkHourly(),
		"work_weekly", caps.WorkWeekly(),
		"global_soft_hourly", caps.GlobalHourly(),
		"global_hard_hourly", caps.GlobalHardHourly(),
		"weekly_alert_threshold", caps.WeeklyAlertThreshold(),
		"le_weekly_allowance", caps.LEWeekly(),
		"ntfy_enabled", ntfyURL != "",
	)
	d := &DNS{store: store, zones: zones, ns: env("CDNS_NS", "ns1.hogman.network"),
		mbox: env("CDNS_MBOX", "hostmaster.hogman.network"), caa: defaultCAA()}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	api := &API{
		store:   store,
		limiter: defaultEABLimiter(store.now),
		logger:  logger,
	}
	if err := configureFallbackEAB(
		ctx,
		api,
		strings.TrimSpace(os.Getenv("CDNS_GCP_KEY")),
		strings.TrimSpace(os.Getenv("CDNS_TEST_EAB_FILE")),
		os.Getenv("CDNS_GTS_CONTACT"),
		logger,
	); err != nil {
		return err
	}

	errc := make(chan error, 8)
	for _, netw := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: listen, Net: netw, Handler: d, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
		go func() { errc <- fmt.Errorf("dns %s: %w", srv.Net, srv.ListenAndServe()) }()
		defer srv.Shutdown()
	}
	logger.Info("dns server listening", "pens_zone", zones.Pens, "gate_name", zones.Gate, "listen", listen)

	serveHTTP := func(name string, ln net.Listener, h http.Handler) {
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
			WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second}
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}()
		go func() { <-ctx.Done(); _ = srv.Close() }()
		logger.Info("http listener started", "name", name, "addr", ln.Addr().String())
	}

	gid, err := strconv.Atoi(env("CDNS_API_GID", "65532"))
	if err != nil {
		return fmt.Errorf("CDNS_API_GID: %w", err)
	}
	apiSock := env("CDNS_API_SOCK", "/run/hogman-acme/api.sock")
	if err := os.MkdirAll(filepath.Dir(apiSock), 0o755); err != nil {
		return err
	}
	apiLn, err := listenUnix(apiSock, 0o660, gid)
	if err != nil {
		return fmt.Errorf("API socket: %w", err)
	}
	serveHTTP("API", apiLn, api.Handler())

	adminSock := env("CDNS_ADMIN_SOCK", "/run/challenge-dns/admin.sock")
	if err := os.MkdirAll(filepath.Dir(adminSock), 0o700); err != nil {
		return err
	}
	adminLn, err := listenUnix(adminSock, 0o600, -1)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	serveHTTP("admin", adminLn, AdminHandler(store, logger))

	if addr := os.Getenv("CDNS_HTTP_ADDR"); addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		serveHTTP("API (TCP, tests only)", ln, api.Handler())
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

func credCmd(args []string) error {
	sock := env("CDNS_ADMIN_SOCK", "/run/challenge-dns/admin.sock")
	show := func(b []byte, code, want int) error {
		if code != want {
			var e struct{ Error string }
			_ = json.Unmarshal(b, &e)
			return fmt.Errorf("HTTP %d: %s", code, e.Error)
		}
		return nil
	}
	switch {
	case len(args) >= 2 && args[0] == "add":
		body := map[string]string{"kind": args[1]}
		if args[1] == "pen" {
			if len(args) < 3 {
				return errors.New("usage: cred add pen <penname> [--plan personal|work]")
			}
			body["pen_id"] = args[2]
			switch len(args) {
			case 3:
			case 5:
				if args[3] != "--plan" {
					return errors.New("usage: cred add pen <penname> [--plan personal|work]")
				}
				body["plan"] = args[4]
			default:
				return errors.New("usage: cred add pen <penname> [--plan personal|work]")
			}
		} else if len(args) != 2 {
			return errors.New("usage: cred add host")
		}
		b, code, err := adminDo(sock, "POST", "/admin/creds", body)
		if err != nil {
			return err
		}
		if err := show(b, code, http.StatusCreated); err != nil {
			return err
		}
		var out struct{ ID, Token string }
		_ = json.Unmarshal(b, &out)
		fmt.Printf("id:    %s\ntoken: %s\n(shown once: put it in the pen's registrar config, nowhere else)\n", out.ID, out.Token)
	case len(args) == 3 && args[0] == "plan":
		b, code, err := adminDo(sock, "PUT", "/admin/creds/"+url.PathEscape(args[1])+"/plan", map[string]string{"plan": args[2]})
		if err != nil {
			return err
		}
		if err := show(b, code, http.StatusOK); err != nil {
			return err
		}
		var out struct {
			ID    string `json:"id"`
			PenID string `json:"pen_id"`
			Plan  string `json:"plan"`
		}
		_ = json.Unmarshal(b, &out)
		fmt.Printf("%s (%s): plan=%s\n", out.PenID, out.ID, out.Plan)
	case (len(args) == 2 || (len(args) == 3 && args[2] == "--release-if-unused")) && args[0] == "rm":
		path := "/admin/creds/" + url.PathEscape(args[1])
		if len(args) == 3 {
			path += "?release_if_unused=1"
		}
		b, code, hdr, err := adminDoWithHeaders(sock, "DELETE", path, nil)
		if err != nil {
			return err
		}
		if err := show(b, code, http.StatusNoContent); err != nil {
			return err
		}
		if hdr.Get("X-Name-Released") == "true" {
			fmt.Println("removed", args[1], "(name released)")
		} else {
			fmt.Println("removed", args[1])
		}
	case len(args) == 1 && args[0] == "list":
		b, code, err := adminDo(sock, "GET", "/admin/creds", nil)
		if err != nil {
			return err
		}
		if err := show(b, code, http.StatusOK); err != nil {
			return err
		}
		var out []struct {
			ID      string    `json:"id"`
			Kind    string    `json:"kind"`
			PenID   string    `json:"pen_id"`
			Plan    string    `json:"plan"`
			Created time.Time `json:"created"`
		}
		_ = json.Unmarshal(b, &out)
		fmt.Printf("%-14s %-5s %-14s %-9s %s\n", "ID", "KIND", "PEN", "PLAN", "CREATED")
		for _, c := range out {
			plan := "-"
			if c.Kind == "pen" {
				plan = c.Plan
				if plan == "" {
					plan = planPersonal
				}
			}
			fmt.Printf("%-14s %-5s %-14s %-9s %s\n", c.ID, c.Kind, c.PenID, plan, c.Created.Format("2006-01-02 15:04"))
		}
	default:
		return errors.New("usage: cred add pen <penname> [--plan personal|work] | cred add host | cred plan <id-or-pen> personal|work | cred rm <id> [--release-if-unused] | cred list")
	}
	return nil
}

// nameCmd: "name used <penname>" prints used or free; exit 0 if used, 1 if free.
func nameCmd(args []string) error {
	if len(args) != 2 || args[0] != "used" {
		return errors.New("usage: name used <penname>")
	}
	b, code, err := adminDo(env("CDNS_ADMIN_SOCK", "/run/challenge-dns/admin.sock"), "GET", "/admin/names/"+url.PathEscape(args[1]), nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("HTTP %d", code)
	}
	var out struct{ Used bool }
	if err := json.Unmarshal(b, &out); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}
	if out.Used {
		fmt.Println("used")
		return nil
	}
	fmt.Println("free")
	os.Exit(1)
	return nil
}
