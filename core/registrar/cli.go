package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"hogman/registrar/internal/registrar"
)

const usage = `registrar: members, invites, devices and names for one Hogman network

  serve                                  run the server
  health                                 check mesh socket and home TLS readiness
  derp-map                               print the embedded mesh DERP map as JSON
  gate-cert [health]                     maintain (or check) the host front-door wildcard certificate

  member add <handle> [--role owner|admin|member]
  member list
  member suspend <handle> [reason...]    cut off all their devices; reversible
  member resume <handle>
  member kick <handle> [reason...]       end the membership, delete devices, and retire names
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

func cliBad(f string, a ...any) error {
	return &registrar.Error{Kind: registrar.KindInvalid, Msg: fmt.Sprintf(f, a...)}
}

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
		return cliBad("usage: registrar %s", use)
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

func parsePositiveID(raw, kind string) (int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, cliBad("invalid %s id %q", kind, raw)
	}
	return id, nil
}

func cli(ctx context.Context, s *registrar.Service, args []string) error {
	a := registrar.Actor{CLI: true}
	pos, flags := splitFlags(args)
	if len(pos) < 1 {
		return cliBad("missing command")
	}
	sub := ""
	if len(pos) > 1 {
		sub = pos[1]
	}
	rest := []string{}
	if len(pos) > 2 {
		rest = pos[2:]
	}

	var (
		handled bool
		err     error
	)
	switch pos[0] {
	case "member":
		handled, err = cliMember(ctx, s, a, sub, rest, flags)
	case "invite":
		handled, err = cliInvite(s, a, sub, rest, flags)
	case "device":
		handled, err = cliDevice(ctx, s, a, sub, rest)
	case "name":
		handled, err = cliName(s, a, sub, rest, flags)
	case "audit":
		return cliAudit(s, sub)
	case "sync":
		return cliSync(ctx, s)
	}
	if handled {
		return err
	}
	fmt.Print(usage)
	return cliBad("unknown command %q", strings.TrimSpace(pos[0]+" "+sub))
}

func cliMember(ctx context.Context, s *registrar.Service, a registrar.Actor, sub string, rest []string, flags map[string]string) (bool, error) {
	switch sub {
	case "add":
		if err := need(rest, 1, "member add <handle> [--role r]"); err != nil {
			return true, err
		}
		role := flags["role"]
		if role == "" {
			role = "member"
		}
		m, err := s.AddMember(ctx, a, rest[0], role)
		if err != nil {
			return true, err
		}
		fmt.Printf("added %s (%s)\n", m.Handle, m.Role)
	case "list":
		ms, err := s.ListMembers()
		if err != nil {
			return true, err
		}
		rows := make([][]string, 0, len(ms)+1)
		rows = append(rows, []string{"ID", "HANDLE", "ROLE", "STATUS", "INVITED BY", "JOINED"})
		byID := make(map[int64]string, len(ms))
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
	case "suspend":
		if err := need(rest, 1, "member suspend <handle> [reason]"); err != nil {
			return true, err
		}
		if err := s.Suspend(ctx, a, rest[0], strings.Join(rest[1:], " ")); err != nil {
			return true, err
		}
		fmt.Printf("suspended %s\n", rest[0])
	case "resume":
		if err := need(rest, 1, "member resume <handle>"); err != nil {
			return true, err
		}
		if err := s.Resume(ctx, a, rest[0]); err != nil {
			return true, err
		}
		fmt.Printf("resumed %s\n", rest[0])
	case "kick":
		if err := need(rest, 1, "member kick <handle> [reason]"); err != nil {
			return true, err
		}
		rep, err := s.Kick(ctx, a, rest[0], strings.Join(rest[1:], " "))
		if err != nil {
			return true, err
		}
		fmt.Printf("removed %s: %d devices deleted, %d keys and %d invites revoked, %d names retired\n",
			rest[0], rep.Devices, rep.Keys, rep.Invites, rep.NamesRetired)
	case "role":
		if err := need(rest, 2, "member role <handle> <role>"); err != nil {
			return true, err
		}
		if err := s.SetRole(ctx, a, rest[0], rest[1]); err != nil {
			return true, err
		}
		fmt.Printf("%s is now %s\n", rest[0], rest[1])
	default:
		return false, nil
	}
	return true, nil
}

func cliInvite(s *registrar.Service, a registrar.Actor, sub string, rest []string, flags map[string]string) (bool, error) {
	switch sub {
	case "create":
		var ttl time.Duration
		if v := flags["ttl"]; v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return true, cliBad("--ttl: %v", err)
			}
			ttl = d
		}
		inv, err := s.MintInvite(a, flags["role"], flags["note"], ttl)
		if err != nil {
			return true, err
		}
		fmt.Printf("invite %d (%s), expires %s\n", inv.ID, inv.Role, ts(inv.ExpiresAt))
		fmt.Printf("token: %s\n", inv.Token)
		fmt.Printf("link:  %s\n", inv.URL)
	case "list":
		invs, err := s.ListInvites(nil)
		if err != nil {
			return true, err
		}
		names, err := handles(s)
		if err != nil {
			return true, err
		}
		rows := make([][]string, 0, len(invs)+1)
		rows = append(rows, []string{"ID", "ROLE", "STATE", "MINTED BY", "REDEEMED BY", "EXPIRES", "NOTE"})
		for _, i := range invs {
			rows = append(rows, []string{strconv.FormatInt(i.ID, 10), i.Role, i.State(),
				nameOr(names, i.MintedBy, "owner@cli"), nameOr(names, i.RedeemedBy, "-"), ts(i.ExpiresAt), i.Note})
		}
		table(rows)
	case "revoke":
		if err := need(rest, 1, "invite revoke <id>"); err != nil {
			return true, err
		}
		id, err := parsePositiveID(rest[0], "invite")
		if err != nil {
			return true, err
		}
		if err := s.RevokeInvite(a, id); err != nil {
			return true, err
		}
		fmt.Printf("revoked invite %d\n", id)
	default:
		return false, nil
	}
	return true, nil
}

func cliDevice(ctx context.Context, s *registrar.Service, a registrar.Actor, sub string, rest []string) (bool, error) {
	switch sub {
	case "key":
		if err := need(rest, 2, "device key <handle> personal|server"); err != nil {
			return true, err
		}
		key, exp, err := s.IssueDeviceKey(ctx, a, rest[0], rest[1])
		if err != nil {
			return true, err
		}
		fmt.Printf("key:   %s\n", key)
		fmt.Printf("link:  %s\n", s.DeviceLink(key, rest[1]))
		fmt.Printf("valid until %s, single use\n", ts(exp))
	case "list":
		ds, err := s.ListLiveDevices()
		if err != nil {
			return true, err
		}
		rows := make([][]string, 0, len(ds)+1)
		rows = append(rows, []string{"ID", "MEMBER", "KIND", "NAME", "IPV4", "JOINED"})
		for _, d := range ds {
			rows = append(rows, []string{strconv.FormatInt(d.ID, 10), d.Member, d.Kind, d.Name, d.IPv4, ts(d.CreatedAt)})
		}
		table(rows)
	case "rm":
		if err := need(rest, 1, "device rm <id>"); err != nil {
			return true, err
		}
		id, err := parsePositiveID(rest[0], "device")
		if err != nil {
			return true, err
		}
		if err := s.RemoveDevice(ctx, a, id); err != nil {
			return true, err
		}
		fmt.Printf("removed device %d\n", id)
	default:
		return false, nil
	}
	return true, nil
}

func cliName(s *registrar.Service, a registrar.Actor, sub string, rest []string, flags map[string]string) (bool, error) {
	switch sub {
	case "list":
		ns, err := s.ListNames()
		if err != nil {
			return true, err
		}
		rows := make([][]string, 0, len(ns)+1)
		rows = append(rows, []string{"NAME", "MEMBER", "POINTS AT", "STATE", "NOTE"})
		for _, n := range ns {
			state, at := "active", n.IPv4
			if n.RetiredAt != nil {
				state = "retired"
			}
			if at == "" {
				at = "-"
			}
			rows = append(rows, []string{n.Name + "." + s.Zone(), n.Member, at, state, n.Note})
		}
		table(rows)
	case "claim":
		if err := need(rest, 3, "name claim <handle> <name> <device-id> [--note text]"); err != nil {
			return true, err
		}
		id, err := parsePositiveID(rest[2], "device")
		if err != nil {
			return true, err
		}
		var note *string
		if v, ok := flags["note"]; ok {
			note = &v
		}
		fqdn, err := s.Claim(a, rest[0], rest[1], id, note)
		if err != nil {
			return true, err
		}
		fmt.Printf("%s -> device %d\n", fqdn, id)
	case "release":
		if err := need(rest, 1, "name release <name>"); err != nil {
			return true, err
		}
		if err := s.Release(a, rest[0]); err != nil {
			return true, err
		}
		fmt.Printf("released %s\n", rest[0])
	default:
		return false, nil
	}
	return true, nil
}

func cliAudit(s *registrar.Service, sub string) error {
	n := 50
	if sub != "" {
		var err error
		n, err = strconv.Atoi(sub)
		if err != nil || n <= 0 {
			return cliBad("invalid audit count %q", sub)
		}
	}
	entries, err := s.ListAuditLog(n)
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(entries)+1)
	rows = append(rows, []string{"WHEN", "ACTOR", "ACTION", "TARGET", "DETAIL"})
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		rows = append(rows, []string{ts(e.At), e.Actor, e.Action, e.Target, e.Detail})
	}
	table(rows)
	return nil
}

func cliSync(ctx context.Context, s *registrar.Service) error {
	if err := s.Sync(ctx); err != nil {
		return err
	}
	fmt.Println("in sync")
	return nil
}

func handles(s *registrar.Service) (map[int64]string, error) {
	ms, err := s.ListMembers()
	if err != nil {
		return nil, err
	}
	out := make(map[int64]string, len(ms))
	for _, m := range ms {
		out[m.ID] = m.Handle
	}
	return out, nil
}

func nameOr(names map[int64]string, id *int64, def string) string {
	if id == nil {
		return def
	}
	return names[*id]
}
