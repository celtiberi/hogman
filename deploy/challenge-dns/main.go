// challenge-dns: the authoritative DNS server for ACME DNS-01 challenges
// under the delegated pens zone and the front door's challenge name, with a
// small API that lets each pen write only its own challenge records.
// Design: docs/security/public-certificates.md (D-18, D-19).
//
//	challenge-dns serve
//	challenge-dns cred add pen <penname> | cred add host | cred rm <id> | cred list
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
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

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

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

func zonesFromEnv() Zones {
	return Zones{
		Pens: normalize(env("CDNS_PENS_ZONE", "pens.hogman.network")),
		Gate: normalize(env("CDNS_GATE_NAME", "_acme-challenge.gate.hogman.network")),
	}
}

// parseContact checks the operator's contact address for fallback CA accounts:
// a bare address (no display name), or empty for none.
func parseContact(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	a, err := mail.ParseAddress(raw)
	if err != nil || a.Name != "" || a.Address != raw || strings.ContainsAny(raw, " ,;<>") {
		return "", fmt.Errorf("CDNS_GTS_CONTACT must be a plain email address like ops@example.com (got %q)", raw)
	}
	return raw, nil
}

func parseCap(envName, raw string, def, max int) (int, error) {
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > max {
		return 0, fmt.Errorf("%s must be an integer between 1 and %d (got %q)", envName, max, raw)
	}
	return n, nil
}

func parseWeeklyCap(raw string) (int, error) {
	return parseCap("CDNS_WEEKLY_CAP", raw, defaultCapNames, 1000)
}

func parseCapsFromEnv(hourlyRaw, weeklyRaw, globalHourlyRaw, globalHardHourlyRaw string) (hourly, weekly, globalHourly, globalHardHourly int, err error) {
	weekly, err = parseWeeklyCap(weeklyRaw)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	hourlyDef := defaultHourlyCap
	if hourlyRaw == "" && weekly < hourlyDef {
		hourlyDef = weekly
	}
	hourly, err = parseCap("CDNS_HOURLY_CAP", hourlyRaw, hourlyDef, 1000)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	if hourly > weekly {
		return 0, 0, 0, 0, fmt.Errorf("CDNS_HOURLY_CAP (%d) must not exceed CDNS_WEEKLY_CAP (%d)", hourly, weekly)
	}
	globalHourly, err = parseCap("CDNS_GLOBAL_HOURLY_CAP", globalHourlyRaw, defaultGlobalHourlyCap, 10000)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	if globalHourly < hourly {
		return 0, 0, 0, 0, fmt.Errorf("CDNS_GLOBAL_HOURLY_CAP (%d) must be at least CDNS_HOURLY_CAP (%d)", globalHourly, hourly)
	}
	globalHardDef := defaultGlobalHardHourlyCap
	if globalHardHourlyRaw == "" && globalHourly > globalHardDef {
		globalHardDef = globalHourly
	}
	globalHardHourly, err = parseCap("CDNS_GLOBAL_HARD_HOURLY_CAP", globalHardHourlyRaw, globalHardDef, 10000)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	if globalHardHourly < globalHourly {
		return 0, 0, 0, 0, fmt.Errorf("CDNS_GLOBAL_HARD_HOURLY_CAP (%d) must be at least CDNS_GLOBAL_HOURLY_CAP (%d)", globalHardHourly, globalHourly)
	}
	return hourly, weekly, globalHourly, globalHardHourly, nil
}

func parseWorkCapsFromEnv(workHourlyRaw, workWeeklyRaw string, globalHourly int) (workHourly, workWeekly int, err error) {
	workWeekly, err = parseCap("CDNS_WORK_WEEKLY_CAP", workWeeklyRaw, defaultWorkWeeklyCap, 1000)
	if err != nil {
		return 0, 0, err
	}
	workHourlyDef := defaultWorkHourlyCap
	if workHourlyRaw == "" {
		if workWeekly < workHourlyDef {
			workHourlyDef = workWeekly
		}
		if globalHourly < workHourlyDef {
			workHourlyDef = globalHourly
		}
	}
	workHourly, err = parseCap("CDNS_WORK_HOURLY_CAP", workHourlyRaw, workHourlyDef, 1000)
	if err != nil {
		return 0, 0, err
	}
	if workHourly > workWeekly {
		return 0, 0, fmt.Errorf("CDNS_WORK_HOURLY_CAP (%d) must not exceed CDNS_WORK_WEEKLY_CAP (%d)", workHourly, workWeekly)
	}
	if workHourly > globalHourly {
		return 0, 0, fmt.Errorf("CDNS_WORK_HOURLY_CAP (%d) must not exceed CDNS_GLOBAL_HOURLY_CAP (%d)", workHourly, globalHourly)
	}
	return workHourly, workWeekly, nil
}

func parseLEWeeklyAllowance(raw string) (int, error) {
	return parseCap("CDNS_LE_WEEKLY_ALLOWANCE", raw, defaultLEWeeklyAllowance, 100000)
}

func parseNtfyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Path == "" || u.Path == "/" {
		return "", fmt.Errorf("CDNS_NTFY_URL must be an https:// URL with a topic path (got %q)", raw)
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		if u.Scheme != "http" || (host != "127.0.0.1" && host != "::1") {
			return "", fmt.Errorf("CDNS_NTFY_URL must use https:// (got %q)", raw)
		}
	}
	return raw, nil
}

func newNtfyAlerter(ntfyURL string, hc *http.Client) func(used, allowance, threshold int) {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	sem := make(chan struct{}, 2)
	return func(used, allowance, threshold int) {
		pct := 0
		if allowance > 0 {
			pct = (used * 100) / allowance
		}
		msg := fmt.Sprintf("Hogman challenge-dns: %d/%d (%d%%) of Let's Encrypt 7-day certificate allowance used across all pens (alert threshold %d). Google Trust Services fallback handles HTTP 429 overflow automatically.",
			used, allowance, pct, threshold)
		log.Printf("WARNING: %s", msg)
		if ntfyURL == "" {
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			log.Printf("ntfy: skipping 7-day budget alert (too many pushes in flight)")
			return
		}
		go func() {
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, ntfyURL, strings.NewReader(msg))
			if err != nil {
				log.Printf("ntfy: build request: %v", err)
				return
			}
			req.Header.Set("Title", "Hogman: Let's Encrypt 7-day cert budget >= 80%")
			req.Header.Set("Priority", "high")
			req.Header.Set("Tags", "warning")
			resp, err := hc.Do(req)
			if err != nil {
				log.Printf("ntfy: push failed: %v", err)
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode >= 300 {
				log.Printf("ntfy: push returned HTTP %d", resp.StatusCode)
			}
		}()
	}
}

func serve() error {
	listen := os.Getenv("CDNS_LISTEN")
	if listen == "" {
		return errors.New("set CDNS_LISTEN to the public address to answer on, e.g. 203.0.113.10:53 (not 127.0.0.53, where systemd-resolved sits)")
	}
	hourlyCap, weeklyCap, globalHourlyCap, globalHardHourlyCap, err := parseCapsFromEnv(
		os.Getenv("CDNS_HOURLY_CAP"),
		os.Getenv("CDNS_WEEKLY_CAP"),
		os.Getenv("CDNS_GLOBAL_HOURLY_CAP"),
		os.Getenv("CDNS_GLOBAL_HARD_HOURLY_CAP"),
	)
	if err != nil {
		return err
	}
	workHourlyCap, workWeeklyCap, err := parseWorkCapsFromEnv(
		os.Getenv("CDNS_WORK_HOURLY_CAP"),
		os.Getenv("CDNS_WORK_WEEKLY_CAP"),
		globalHourlyCap,
	)
	if err != nil {
		return err
	}
	leWeeklyAllowance, err := parseLEWeeklyAllowance(os.Getenv("CDNS_LE_WEEKLY_ALLOWANCE"))
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
	store.hourlyCapNames = hourlyCap
	store.capNames = weeklyCap
	store.workHourlyCapNames = workHourlyCap
	store.workCapNames = workWeeklyCap
	store.globalHourlyCapNames = globalHourlyCap
	store.globalHardHourlyCapNames = globalHardHourlyCap
	store.leWeeklyAllowance = leWeeklyAllowance
	store.onWeeklyAlert = newNtfyAlerter(ntfyURL, nil)
	log.Printf("certificate caps: personal %d/hour %d/7d, work %d/hour %d/7d, global %d/hour soft (%d/hour hard with quiet-pen floor); 7d alert at %d/%d (ntfy=%v)",
		store.hourlyCap(), store.weeklyCap(), store.workHourlyCap(), store.workWeeklyCap(), store.globalHourlyCap(), store.globalHardHourlyCap(),
		store.weeklyAlertThreshold(), store.leWeeklyAllowanceVal(), ntfyURL != "")
	d := &DNS{store: store, zones: zones, ns: env("CDNS_NS", "ns1.hogman.network"),
		mbox: env("CDNS_MBOX", "hostmaster.hogman.network"), caa: defaultCAA()}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	api := &API{store: store, global: &windowLimiter{perMin: 20, perHour: 90}}
	if kf := os.Getenv("CDNS_GCP_KEY"); kf != "" {
		m, err := newGCPMinter(ctx, kf)
		if err != nil {
			return fmt.Errorf("CDNS_GCP_KEY: %w", err)
		}
		api.eab = m
		log.Printf("fallback CA account keys: Google project %s", m.project)
		contact, err := parseContact(os.Getenv("CDNS_GTS_CONTACT"))
		if err != nil {
			return err
		}
		if api.contact = contact; contact == "" {
			log.Printf("warning: CDNS_GTS_CONTACT is not set; Google refuses accounts without a contact, so no fallback account keys will be handed out")
		} else {
			log.Printf("fallback CA account contact: %s", contact)
		}
	}

	errc := make(chan error, 8)
	for _, netw := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: listen, Net: netw, Handler: d, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
		go func() { errc <- fmt.Errorf("dns %s: %w", srv.Net, srv.ListenAndServe()) }()
		defer srv.Shutdown()
	}
	log.Printf("answering for %s and %s on %s", zones.Pens, zones.Gate, listen)

	serveHTTP := func(name string, ln net.Listener, h http.Handler) {
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
			WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second}
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}()
		go func() { <-ctx.Done(); _ = srv.Close() }()
		log.Printf("%s on %s", name, ln.Addr())
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
	serveHTTP("admin", adminLn, AdminHandler(store))

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
