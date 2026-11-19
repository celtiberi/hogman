// Command registrar is the source of truth for one Hogman network: members,
// invites, devices, names, removal and the audit log. It drives Headscale
// (devices, access policy) and CoreDNS (the zone file).
//
// The same binary is the server ("registrar serve") and the owner's command
// line on the core node ("registrar member kick alice").
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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

func setup() *Service {
	cfg := Config{
		Zone:             mustEnv("ZONE"),
		PublicHost:       mustEnv("PUBLIC_HOST"),
		CoreIP:           mustEnv("CORE_MESH_IP"),
		CAIP:             mustEnv("CA_MESH_IP"),
		ZoneFile:         env("ZONE_FILE", "/zone/db.zone"),
		RootCAFile:       env("ROOT_CA", "/pki/root_ca.crt"),
		NameHold:         durEnv("NAME_HOLD", 90*24*time.Hour),
		InviteTTL:        durEnv("INVITE_TTL", 7*24*time.Hour),
		DeviceKeyTTL:     durEnv("DEVICE_KEY_TTL", time.Hour),
		MembersCanInvite: env("MEMBERS_CAN_INVITE", "false") == "true",
	}
	key, err := os.ReadFile(env("HEADSCALE_API_KEY_FILE", "/secrets/headscale_api_key"))
	if err != nil {
		log.Fatalf("headscale API key: %v", err)
	}
	st, err := OpenStore(env("DB", "/var/lib/registrar/registrar.db"))
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

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return
	}
	if args[0] == "serve" {
		serve(setup())
		return
	}
	s := setup()
	if err := cli(context.Background(), s, args); err != nil {
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

func serve(s *Service) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Wait for Headscale, then take control of policy and DNS before serving.
	for {
		if err := s.Sync(ctx); err == nil {
			break
		} else {
			log.Printf("waiting for headscale: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	log.Printf("registrar for %s: in sync with headscale", s.cfg.Zone)

	go func() {
		t := time.NewTicker(durEnv("SYNC_INTERVAL", 3*time.Second))
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.Sync(ctx); err != nil {
					log.Printf("sync: %v", err)
				}
			}
		}
	}()

	pub := &http.Server{Addr: env("PUBLIC_ADDR", ":8081"), Handler: PublicHandler(s),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
	mesh := &http.Server{Addr: env("MESH_ADDR", "127.0.0.1:8082"), Handler: MeshHandler(s),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
	for _, srv := range []*http.Server{pub, mesh} {
		go func(srv *http.Server) {
			log.Printf("listening on %s", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatal(err)
			}
		}(srv)
	}
	<-ctx.Done()
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = pub.Shutdown(shut)
	_ = mesh.Shutdown(shut)
}

// -------------------------------------------------------------------- cli --

const usage = `registrar: members, invites, devices and names for one Hogman network

  serve                                  run the server

  member add <handle> [--role owner|admin|member]
  member list
  member suspend <handle> [reason...]    cut off all their devices; reversible
  member resume <handle>
  member kick <handle> [reason...]       end the membership (DESIGN.md section 9)
  member role <handle> <role>

  invite create [--role member|admin] [--ttl 168h] [--note text]
  invite list
  invite revoke <id>

  device key <handle> personal|server    one-time key to join a device
  device list
  device rm <id>

  name list
  name claim <handle> <name> <device-id>
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
		fmt.Printf("removed %s: %d devices deleted, %d keys and %d invites revoked, %d names held until %s\n",
			rest[0], rep.Devices, rep.Keys, rep.Invites, rep.NamesHeld, ts(rep.HeldUntil))
	case "member role":
		if err := need(rest, 2, "member role <handle> <role>"); err != nil {
			return err
		}
		if err := s.SetRole(a, rest[0], rest[1]); err != nil {
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
		fmt.Printf("link:  %s\n", s.DeviceLink(key))
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
		rows := [][]string{{"NAME", "MEMBER", "POINTS AT", "STATE"}}
		for _, n := range ns {
			state, at := "active", n.IPv4
			if n.HeldUntil != nil {
				state = "held until " + ts(*n.HeldUntil)
			}
			if at == "" {
				at = "-"
			}
			rows = append(rows, []string{n.Name + "." + s.cfg.Zone, n.Member, at, state})
		}
		table(rows)
	case "name claim":
		if err := need(rest, 3, "name claim <handle> <name> <device-id>"); err != nil {
			return err
		}
		id, _ := strconv.ParseInt(rest[2], 10, 64)
		fqdn, err := s.Claim(a, rest[0], rest[1], id)
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
