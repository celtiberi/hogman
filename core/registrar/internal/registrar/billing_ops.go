package registrar

import (
	"log/slog"
	"sort"
	"strings"
	"time"

	"hogman/registrar/internal/acme"
	"hogman/registrar/internal/billing"
	"hogman/registrar/internal/store"
)

// Zone returns the pen's DNS zone (e.g. demo.pens.hogman.network).
func (s *Service) Zone() string { return s.cfg.Zone }

// PublicHost returns the pen's public control/gate hostname.
func (s *Service) PublicHost() string { return s.cfg.PublicHost }

// CoreIP returns the pen core node's mesh IPv4 address.
func (s *Service) CoreIP() string { return s.cfg.CoreIP }

// SetCoreIP updates the core node's mesh IPv4 address (e.g. once embedded tsnet comes up).
func (s *Service) SetCoreIP(ip string) { s.cfg.CoreIP = ip }

// MembersCanInvite reports whether plain members are allowed to mint member invites.
func (s *Service) MembersCanInvite() bool { return s.cfg.MembersCanInvite }

// Config returns a copy of the service's normalized configuration.
func (s *Service) Config() Config { return s.cfg }

// BillingStatusPath returns the configured billing-status.json path.
func (s *Service) BillingStatusPath() string { return s.cfg.BillingStatusPath }

// SetBillingStatusPath updates the billing-status.json path (used by tests).
func (s *Service) SetBillingStatusPath(path string) { s.cfg.BillingStatusPath = path }

// Billing returns the host-managed billing policy for this pen.
func (s *Service) Billing() *billing.Policy { return billing.NewPolicy(s.cfg.BillingStatusPath) }

// IsRenewOnly reports whether the pen is currently in restricted renew-only mode.
func (s *Service) IsRenewOnly() bool { return s.Billing().IsRenewOnly() }

// ACMEBackend returns the configured challenge-DNS ACME backend, if any.
func (s *Service) ACMEBackend() acme.Backend { return s.acme }

// Logger returns the service's structured logger.
func (s *Service) Logger() *slog.Logger { return s.loggerOrDefault() }

// Clock returns the current time from the service's injected clock.
func (s *Service) Clock() time.Time { return s.clock() }

// SetClock overrides the service (and store) clock (intended for deterministic tests).
func (s *Service) SetClock(fn func() time.Time) {
	s.nowFn = fn
	if s.st != nil && fn != nil {
		s.st.SetClock(s.clock)
	}
}

// SetPresenceTTL overrides the presence cache TTL (intended for tests).
func (s *Service) SetPresenceTTL(d time.Duration) {
	s.cfg.PresenceTTL = d
	if s.presence != nil {
		s.presence.SetTTL(d)
	}
}

// ClearPresenceCache empties the display-only presence cache (intended for tests).
func (s *Service) ClearPresenceCache() {
	if s.presence != nil {
		s.presence.Clear()
	}
}

// SetPrivateLabelGenerator overrides random private-label generation (intended for tests).
func (s *Service) SetPrivateLabelGenerator(fn func() (string, error)) {
	s.privateLabelFn = fn
}

// BuildPolicy renders the current Headscale ACL policy JSON and renew-only flag.
func (s *Service) BuildPolicy() (string, bool, error) { return s.buildPolicy() }

// LookupNameIPv4 implements dns.NameLookup against the service's SQLite store.
func (s *Service) LookupNameIPv4(rel string) (string, bool, error) {
	return s.st.LookupNameIPv4(rel)
}

// HasResolvableChild implements dns.NameLookup against the service's SQLite store.
func (s *Service) HasResolvableChild(rel string) (bool, error) {
	return s.st.HasResolvableChild(rel)
}

// Read-only queries exposing ledger views to internal/api and CLI without
// leaking direct Store handles outside internal/registrar.
func (s *Service) ListMembers() ([]*store.Member, error) { return s.st.Members() }
func (s *Service) ListHerd(q string, limit, offset int) ([]*store.HerdMember, int, error) {
	return s.st.Herd(q, limit, offset)
}
func (s *Service) ListMemberDevices(memberID int64) ([]*store.Device, error) {
	return s.st.MemberDevices(memberID)
}
func (s *Service) ListLiveDevices() ([]*store.Device, error)   { return s.st.LiveDevices() }
func (s *Service) ListNames() ([]*store.Name, error)           { return s.st.Names() }
func (s *Service) ListResolvableNames() ([]*store.Name, error) { return s.st.ResolvableNames() }
func (s *Service) ListInvites(memberID *int64) ([]*store.Invite, error) {
	return s.st.Invites(memberID)
}
func (s *Service) ListOpenInvites(limit int) ([]*store.Invite, error) { return s.st.OpenInvites(limit) }
func (s *Service) ListAuditLog(limit int) ([]*store.AuditEntry, error) {
	return s.st.AuditLog(limit)
}
func (s *Service) CountOwners() (int, error) { return s.st.CountOwners() }

// MintRenewToken authenticates an active owner/admin actor and mints a
// short-lived (15m) HMAC renewal link when the pen is in grace or renew_only.
func (s *Service) MintRenewToken(a Actor) (string, time.Time, error) {
	bp := s.Billing()
	st := bp.Status()
	if st == nil || (st.State != "grace" && st.State != "renew_only") || st.Pen == "" || st.RenewURL == "" {
		return "", time.Time{}, conflict("this pen is not currently in a renewable grace or wake window")
	}
	fresh, err := s.RefreshActor(a)
	if err != nil {
		return "", time.Time{}, err
	}
	if fresh.Member == nil || fresh.Member.Status != "active" || !fresh.IsAdmin() {
		return "", time.Time{}, forbidden("only active owners or admins can renew")
	}
	token, exp, err := bp.MintRenewToken(st.Pen, fresh.Member.Handle, fresh.Member.Role, s.clock().UTC())
	if err != nil {
		s.loggerOrDefault().Error("mint billing renew token failed", "err", err)
		return "", time.Time{}, err
	}
	return strings.TrimRight(st.RenewURL, "/") + "/#renew=" + token, exp, nil
}

// MintPenDeleteToken authenticates an active owner, verifies exact pen-name
// confirmation against host-meta.json, mints a short-lived delete HMAC token,
// and records the audit entry.
func (s *Service) MintPenDeleteToken(a Actor, confirm string) (string, time.Time, error) {
	fresh, err := s.RefreshActor(a)
	if err != nil {
		return "", time.Time{}, err
	}
	if fresh.Member == nil || fresh.Member.Status != "active" || !fresh.IsOwner() {
		return "", time.Time{}, forbidden("only active owners can delete this pen")
	}
	bp := s.Billing()
	meta := bp.HostMeta()
	if meta == nil || meta.Pen == "" || meta.DeleteURL == "" {
		return "", time.Time{}, conflict("self-service pen deletion is not configured for this pen")
	}
	if !strings.EqualFold(strings.TrimSpace(confirm), meta.Pen) {
		return "", time.Time{}, bad("type the exact pen name (%s) to confirm", meta.Pen)
	}
	token, exp, err := bp.MintDeleteToken(meta.Pen, fresh.Member.Handle, s.clock().UTC())
	if err != nil {
		s.loggerOrDefault().Error("mint pen delete token failed", "err", err)
		return "", time.Time{}, err
	}
	s.st.Audit(fresh.Member.Handle, "pen.delete.token", meta.Pen, "")
	return strings.TrimRight(meta.DeleteURL, "/") + "/#delete=" + token, exp, nil
}

// PenDeleteView returns the owner-only summary shown on /api/me for hosted pens,
// or nil if self-service pen deletion is not configured.
func (s *Service) PenDeleteView(callerHandle string) (*billing.PenDeleteView, error) {
	meta := s.Billing().HostMeta()
	if meta == nil || meta.Pen == "" || meta.DeleteURL == "" {
		return nil, nil
	}
	v := billing.PenDeleteView{
		Pen:             meta.Pen,
		CanDelete:       true,
		HasSubscription: meta.HasSubscription,
	}
	ms, err := s.st.Members()
	if err != nil {
		return nil, err
	}
	var others []string
	for _, m := range ms {
		if m.Status == "removed" {
			continue
		}
		v.MemberCount++
		if m.Role == "owner" && m.Status == "active" && !strings.EqualFold(m.Handle, callerHandle) {
			others = append(others, m.Handle)
		}
	}
	if len(others) > 0 {
		sort.Strings(others)
		v.OtherOwners = others
	}
	ds, err := s.st.LiveDevices()
	if err != nil {
		return nil, err
	}
	v.DeviceCount = len(ds)
	return &v, nil
}
