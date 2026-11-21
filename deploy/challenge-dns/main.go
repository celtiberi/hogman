// challenge-dns: the authoritative DNS server for ACME DNS-01 challenges
// under the delegated pens zone and the front door's challenge name, with a
// small API that lets each pen write only its own challenge records.
// Design: docs/security/public-certificates.md (D-18, D-19).
//
//	challenge-dns serve
//	challenge-dns cred add pen <penid> | cred add host | cred rm <id> | cred list
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type netUDPAddr = net.UDPAddr

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

const usage = `challenge-dns: DNS-01 challenge server for Hogman pens

  challenge-dns serve
  challenge-dns cred add pen <penid>     a credential for one pen (prints its token once)
  challenge-dns cred add host            the front door's credential (gate wildcard)
  challenge-dns cred rm <id>
  challenge-dns cred list

Settings (environment):
  CDNS_LISTEN        public address for DNS, e.g. 159.65.78.95:53 (required to serve)
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

func serve() error {
	listen := os.Getenv("CDNS_LISTEN")
	if listen == "" {
		return errors.New("set CDNS_LISTEN to the public address to answer on, e.g. 159.65.78.95:53 (not 127.0.0.53, where systemd-resolved sits)")
	}
	zones := zonesFromEnv()
	statePath := env("CDNS_STATE", "/var/lib/challenge-dns/state.json")
	if err := os.MkdirAll(dirOf(statePath), 0o700); err != nil {
		return err
	}
	store, err := OpenStore(statePath, zones)
	if err != nil {
		return err
	}
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
	if err := os.MkdirAll(dirOf(apiSock), 0o755); err != nil {
		return err
	}
	apiLn, err := listenUnix(apiSock, 0o660, gid)
	if err != nil {
		return fmt.Errorf("API socket: %w", err)
	}
	serveHTTP("API", apiLn, api.Handler())

	adminSock := env("CDNS_ADMIN_SOCK", "/run/challenge-dns/admin.sock")
	if err := os.MkdirAll(dirOf(adminSock), 0o700); err != nil {
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

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
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
			if len(args) != 3 {
				return errors.New("usage: cred add pen <penid>")
			}
			body["pen_id"] = args[2]
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
	case len(args) == 2 && args[0] == "rm":
		b, code, err := adminDo(sock, "DELETE", "/admin/creds/"+args[1], nil)
		if err != nil {
			return err
		}
		if err := show(b, code, http.StatusNoContent); err != nil {
			return err
		}
		fmt.Println("removed", args[1])
	case len(args) == 1 && args[0] == "list":
		b, code, err := adminDo(sock, "GET", "/admin/creds", nil)
		if err != nil {
			return err
		}
		if err := show(b, code, http.StatusOK); err != nil {
			return err
		}
		var out []struct {
			ID, Kind, PenID string
			Created         time.Time
		}
		_ = json.Unmarshal(b, &out)
		fmt.Printf("%-14s %-5s %-14s %s\n", "ID", "KIND", "PEN", "CREATED")
		for _, c := range out {
			fmt.Printf("%-14s %-5s %-14s %s\n", c.ID, c.Kind, c.PenID, c.Created.Format("2006-01-02 15:04"))
		}
	default:
		return errors.New("usage: cred add pen <penid> | cred add host | cred rm <id> | cred list")
	}
	return nil
}
