package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ----------------------------------------------------------------- public --

// PublicHandler serves the one thing reachable from the internet: redeeming
// an invite. Mounted by the edge at https://<public host>/hogman/.
func PublicHandler(s *Service) http.Handler {
	return PublicHandlerWithRateLimit(s, 20, time.Minute)
}

func PublicHandlerWithRateLimit(s *Service, redeemLimit int, window time.Duration) http.Handler {
	logger := s.loggerOrDefault()
	lim := newSlidingWindow[string](redeemLimit, window, defaultLimiterMaxKeys)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hogman/v1/redeem", func(w http.ResponseWriter, r *http.Request) {
		if s.isRenewOnly() {
			failWithLogger(logger, w, forbidden("this pen is woken for renewal only; invites and new devices are unavailable until renewal"))
			return
		}
		if ok, retry := lim.Allow(rateLimitKey(clientIP(r)), s.clock()); !ok {
			failWithLogger(logger, w, &Problem{
				Status:     http.StatusTooManyRequests,
				Msg:        "too many requests; try again shortly",
				RetryAfter: retry,
			})
			return
		}
		var in struct {
			Token  string `json:"token"`
			Handle string `json:"handle"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		enr, err := s.Redeem(r.Context(), in.Token, strings.ToLower(strings.TrimSpace(in.Handle)))
		if err != nil {
			failWithLogger(logger, w, err)
			return
		}
		writeJSON(w, http.StatusCreated, enr)
	})
	// What a joining device needs before it is on the mesh. Nothing secret:
	// the join tool pins the root against the fingerprint in its link.
	mux.HandleFunc("GET /hogman/v1/network", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.NetworkInfo())
	})
	return recoverAndLog(logger, mux)
}

// ------------------------------------------------------------------- mesh --

type ctxKey struct{}

type caller struct {
	member *Member
	device *Device
}

func (c caller) actor() Actor { return Actor{Member: c.member} }

// MeshHandler is the legacy IP-only member and admin API, kept strictly behind
// REGISTRAR_LEGACY_MESH_SOCKET=1 for legacy test/migration harnesses.
func MeshHandler(s *Service) http.Handler {
	api := &meshAPI{svc: s, logger: s.loggerOrDefault()}
	return recoverAndLog(api.logger, requireSameOriginAndJSON(s.cfg.Zone, identify(s, api.routes())))
}

// MeshHandlerDirect is the member and admin API served directly on the
// embedded tsnet listener (https://home.<zone>/api/). Caller identity comes
// strictly from the WireGuard connection's RemoteAddr verified via tsnet WhoIs
// (node ID + node public key + IP, checked against SQLite); X-Forwarded-For
// and all other HTTP headers are ignored.
func MeshHandlerDirect(s *Service, resolvePeer func(ctx context.Context, remoteAddr string) (*PeerIdentity, error)) http.Handler {
	api := &meshAPI{svc: s, logger: s.loggerOrDefault()}
	return recoverAndLog(api.logger, requireSameOriginAndJSON(s.cfg.Zone, identifyDirect(s, resolvePeer, api.routes())))
}

// PortalHandler serves https://home.<zone> directly inside the registrar:
// static assets from portalDir and /api/* via apiHandler, with the same strict
// security headers previously set by portal.Caddyfile.
func PortalHandler(zone, portalDir string, apiHandler http.Handler) http.Handler {
	wantHost := "home." + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	fileSrv := http.FileServer(noDirListingFS{http.Dir(portalDir)})
	return recoverAndLog(slog.Default(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqHost := strings.ToLower(strings.TrimSpace(r.Host))
		if h, _, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = h
		}
		if wantHost != "home." && reqHost != wantHost {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Origin-Agent-Cluster", "?1")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiHandler.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		fileSrv.ServeHTTP(w, r)
	}))
}

type noDirListingFS struct{ fs http.FileSystem }

func (n noDirListingFS) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if fi.IsDir() {
		idx, err := n.fs.Open(strings.TrimSuffix(name, "/") + "/index.html")
		if err != nil {
			_ = f.Close()
			return nil, os.ErrNotExist
		}
		_ = idx.Close()
	}
	return f, nil
}

// --------------------------------------------------------------- mesh API --

type meshAPI struct {
	svc    *Service
	logger *slog.Logger
}

func (a *meshAPI) routes() http.Handler {
	mux := http.NewServeMux()
	reg := func(pattern string, pol routePolicy, fn func(w http.ResponseWriter, r *http.Request, c caller)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			c := r.Context().Value(ctxKey{}).(caller)
			if err := enforceRoutePolicy(pol, c, a.svc.isRenewOnly()); err != nil {
				failWithLogger(a.logger, w, err)
				return
			}
			fn(w, r, c)
		})
	}

	// Member routes
	reg("GET /api/me", routePolicy{Device: deviceAny, AllowRenewOnly: true}, a.handleMe)
	reg("POST /api/billing/renew-token", routePolicy{Role: roleAdmin, AllowRenewOnly: true}, a.handleRenewToken)
	reg("POST /api/pen/delete-token", routePolicy{Role: roleAdmin, AllowRenewOnly: true}, a.handlePenDeleteToken)
	reg("POST /api/devices", routePolicy{}, a.handleCreateDevice)
	reg("DELETE /api/devices/{id}", routePolicy{Device: deviceAny}, a.handleDeleteDevice)
	reg("POST /api/names", routePolicy{Device: deviceAny}, a.handleClaimName)
	reg("DELETE /api/names/{name}", routePolicy{Device: deviceAny}, a.handleReleaseName)
	reg("POST /api/acme/txt", routePolicy{Device: deviceServerOnly}, a.handleSetACMETXT)
	reg("DELETE /api/acme/txt", routePolicy{Device: deviceServerOnly}, a.handleDeleteACMETXT)
	reg("POST /api/acme/eab", routePolicy{Device: deviceServerOnly}, a.handleMintACMEEAB)
	reg("GET /api/directory", routePolicy{Device: deviceAny}, a.handleDirectory)
	reg("POST /api/invites", routePolicy{}, a.handleCreateInvite)
	reg("DELETE /api/invites/{id}", routePolicy{}, a.handleRevokeInvite)

	// Admin routes
	reg("GET /api/admin/members", routePolicy{Role: roleAdmin}, a.handleAdminMembers)
	reg("GET /api/admin/herd", routePolicy{Role: roleAdmin}, a.handleAdminHerd)
	reg("POST /api/admin/members/{handle}/{action}", routePolicy{Role: roleAdmin}, a.handleAdminMemberAction)
	reg("GET /api/admin/devices", routePolicy{Role: roleAdmin}, a.handleAdminDevices)
	reg("GET /api/admin/invites", routePolicy{Role: roleAdmin}, a.handleAdminInvites)
	reg("GET /api/admin/audit", routePolicy{Role: roleAdmin}, a.handleAdminAudit)

	return mux
}

func (a *meshAPI) handleMe(w http.ResponseWriter, r *http.Request, c caller) {
	s := a.svc
	if c.device.Kind == "server" {
		writeJSON(w, http.StatusOK, map[string]any{
			"member": c.member, "this_device": c.device, "zone": s.cfg.Zone,
			"network": s.NetworkInfo(),
		})
		return
	}
	devs, err := s.st.MemberDevices(c.member.ID)
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	names, err := s.st.Names()
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	mine := []*Name{}
	for _, n := range names {
		if n.MemberID == c.member.ID && n.RetiredAt == nil {
			mine = append(mine, n)
		}
	}
	invs, err := s.st.Invites(&c.member.ID)
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	act := c.actor()
	resp := map[string]any{
		"member": c.member, "this_device": c.device, "devices": devs, "names": mine,
		"invites": inviteViews(invs), "zone": s.cfg.Zone,
		// What the page should offer. The API checks again on every call.
		"can_invite": act.IsAdmin() || s.cfg.MembersCanInvite,
		"is_admin":   act.IsAdmin(), "is_owner": act.IsOwner(),
		// What `hogman share` needs to start a server of its own.
		"network": s.NetworkInfo(),
	}
	// Owners and admins see the owner count; omit for plain members.
	if n, ok, err := ownerCount(s, act); err != nil {
		failWithLogger(a.logger, w, err)
		return
	} else if ok {
		resp["owners"] = n
	}
	bp := s.billingPolicy()
	if view := bp.View(act.IsAdmin()); view != nil {
		resp["billing"] = *view
	}
	if act.IsOwner() && c.member.Status == "active" {
		if meta := bp.HostMeta(); meta != nil && meta.Pen != "" && meta.DeleteURL != "" {
			delView, err := buildPenDeleteView(s, c.member.Handle, meta)
			if err != nil {
				failWithLogger(a.logger, w, err)
				return
			}
			resp["pen_delete"] = delView
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// D-35: In-pen authenticated renewal (owners & admins on a personal device).
// Mints a short-lived (15m), single-use, purpose- and pen-bound HMAC token
// returned in the URL fragment (#renew=<token>) so it never hits logs or referers.
func (a *meshAPI) handleRenewToken(w http.ResponseWriter, r *http.Request, c caller) {
	s := a.svc
	bp := s.billingPolicy()
	billing := bp.Status()
	if billing == nil || (billing.State != "grace" && billing.State != "renew_only") || billing.Pen == "" || billing.RenewURL == "" {
		failWithLogger(a.logger, w, &Problem{Status: http.StatusConflict, Msg: "this pen is not currently in a renewable grace or wake window"})
		return
	}
	fresh, err := s.RefreshActor(c.actor())
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	if fresh.Member == nil || fresh.Member.Status != "active" || !fresh.IsAdmin() {
		failWithLogger(a.logger, w, forbidden("only active owners or admins can renew"))
		return
	}
	token, exp, err := bp.MintRenewToken(billing.Pen, fresh.Member.Handle, fresh.Member.Role, s.clock().UTC())
	if err != nil {
		a.logger.Error("mint billing renew token failed", "err", err)
		failWithLogger(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"url":        strings.TrimRight(billing.RenewURL, "/") + "/#renew=" + token,
		"expires_at": exp.UTC().Format(time.RFC3339),
	})
}

// I-24: In-pen authenticated self-service pen deletion (active owners on a
// personal device only; available in active, grace, and renew_only states).
// Mints a short-lived (15m), single-use, domain-separated HMAC token under
// hogman-delete-v1: returned in the URL fragment (#delete=<token>).
func (a *meshAPI) handlePenDeleteToken(w http.ResponseWriter, r *http.Request, c caller) {
	s := a.svc
	fresh, err := s.RefreshActor(c.actor())
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	if fresh.Member == nil || fresh.Member.Status != "active" || !fresh.IsOwner() {
		failWithLogger(a.logger, w, forbidden("only active owners can delete this pen"))
		return
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	bp := s.billingPolicy()
	meta := bp.HostMeta()
	if meta == nil || meta.Pen == "" || meta.DeleteURL == "" {
		failWithLogger(a.logger, w, &Problem{Status: http.StatusConflict, Msg: "self-service pen deletion is not configured for this pen"})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(in.Confirm), meta.Pen) {
		failWithLogger(a.logger, w, bad("type the exact pen name (%s) to confirm", meta.Pen))
		return
	}
	token, exp, err := bp.MintDeleteToken(meta.Pen, fresh.Member.Handle, s.clock().UTC())
	if err != nil {
		a.logger.Error("mint pen delete token failed", "err", err)
		failWithLogger(a.logger, w, err)
		return
	}
	s.st.Audit(fresh.Member.Handle, "pen.delete.token", meta.Pen, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"url":        strings.TrimRight(meta.DeleteURL, "/") + "/#delete=" + token,
		"expires_at": exp.UTC().Format(time.RFC3339),
	})
}

func (a *meshAPI) handleCreateDevice(w http.ResponseWriter, r *http.Request, c caller) {
	s := a.svc
	var in struct {
		Kind string `json:"kind"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	key, exp, err := s.IssueDeviceKey(r.Context(), c.actor(), c.member.Handle, in.Kind)
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	link := s.DeviceLink(key, in.Kind)
	out := map[string]any{
		"auth_key": key, "expires_at": exp, "login_server": s.LoginServer(),
		"kind": in.Kind, "join_link": link,
	}
	if svg, err := qrSVG(link); err == nil {
		out["join_qr_svg"] = svg
	} else {
		a.logger.Warn("device link QR generation failed", "err", err)
	}
	writeJSON(w, http.StatusCreated, out)
}

// A server may remove itself (how `hogman share stop` cleans up), and nothing
// else. Self-removal (personal or server) runs asynchronously on a detached
// context and answers 202 Accepted before Headscale tears down the caller's
// WireGuard link (I-34).
func (a *meshAPI) handleDeleteDevice(w http.ResponseWriter, r *http.Request, c caller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if c.device.Kind == "server" && id != c.device.ID {
		failWithLogger(a.logger, w, forbidden("a server can only remove itself"))
		return
	}
	if id == c.device.ID {
		if err := a.svc.SelfRemoveDevice(c.actor(), id); err != nil {
			failWithLogger(a.logger, w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
		return
	}
	doneWithLogger(a.logger, w, a.svc.RemoveDevice(r.Context(), c.actor(), id))
}

// A server may claim a name for itself (device_id 0 or its own id), as long as
// the name is new or already points at it: `hogman share` names itself without
// a trip to the home page, but cannot take over its member's other names.
func (a *meshAPI) handleClaimName(w http.ResponseWriter, r *http.Request, c caller) {
	s := a.svc
	var in struct {
		Name     string  `json:"name"`
		DeviceID int64   `json:"device_id"`
		Note     *string `json:"note"`
		Private  bool    `json:"private"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Private && strings.TrimSpace(in.Name) != "" {
		failWithLogger(a.logger, w, bad("cannot pass both name and private"))
		return
	}
	var fqdn string
	var err error
	if c.device.Kind == "server" {
		if in.DeviceID != 0 && in.DeviceID != c.device.ID {
			failWithLogger(a.logger, w, forbidden("a server can only name itself"))
			return
		}
		if in.Private {
			fqdn, err = s.ServerClaimPrivate(c.actor(), c.device, in.Note)
		} else {
			fqdn, err = s.ServerClaim(c.actor(), c.device, in.Name, in.Note)
		}
	} else {
		if in.Private {
			fqdn, err = s.ClaimPrivate(c.actor(), c.member.Handle, in.DeviceID, in.Note)
		} else {
			fqdn, err = s.Claim(c.actor(), c.member.Handle, in.Name, in.DeviceID, in.Note)
		}
	}
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	if in.Private {
		writeJSON(w, http.StatusCreated, map[string]any{"name": fqdn, "private": true})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"name": fqdn})
}

func (a *meshAPI) handleReleaseName(w http.ResponseWriter, r *http.Request, c caller) {
	if c.device.Kind == "server" {
		doneWithLogger(a.logger, w, a.svc.ServerRelease(c.actor(), c.device, r.PathValue("name")))
		return
	}
	doneWithLogger(a.logger, w, a.svc.Release(c.actor(), r.PathValue("name")))
}

func (a *meshAPI) handleSetACMETXT(w http.ResponseWriter, r *http.Request, c caller) {
	var in struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	fqdn, err := a.svc.ServerSetACMETXT(r.Context(), c.device, in.Name, in.Value)
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"fqdn": fqdn})
}

func (a *meshAPI) handleDeleteACMETXT(w http.ResponseWriter, r *http.Request, c caller) {
	var in struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := a.svc.ServerDeleteACMETXT(r.Context(), c.device, in.Name, in.Value); err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *meshAPI) handleMintACMEEAB(w http.ResponseWriter, r *http.Request, c caller) {
	pair, err := a.svc.ServerMintACMEEAB(r.Context(), c.device)
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

func (a *meshAPI) handleDirectory(w http.ResponseWriter, r *http.Request, c caller) {
	s := a.svc
	names, err := s.st.ResolvableNames()
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	byID := s.PresenceSnapshot(r.Context())
	out := make([]directoryEntry, 0, len(names))
	for _, n := range names {
		entry := directoryEntry{
			Name:    n.Name + "." + s.cfg.Zone,
			Member:  n.Member,
			Note:    n.Note,
			Private: n.Private,
		}
		// Only expose live presence for sites/servers on /api/directory;
		// personal device presence stays admin-only on /api/admin/devices.
		if n.DeviceKind == "server" {
			entry.Online, entry.LastSeen = nodePresence(byID, n.HSNodeID)
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *meshAPI) handleCreateInvite(w http.ResponseWriter, r *http.Request, c caller) {
	var in struct {
		Role     string  `json:"role"`
		Note     string  `json:"note"`
		TTLHours float64 `json:"ttl_hours"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	inv, err := a.svc.MintInvite(c.actor(), in.Role, in.Note, time.Duration(in.TTLHours*float64(time.Hour)))
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	out := struct {
		*MintedInvite
		QRSVG string `json:"qr_svg,omitempty"`
	}{MintedInvite: inv}
	if svg, err := qrSVG(inv.URL); err == nil {
		out.QRSVG = svg
	} else {
		a.logger.Warn("invite link QR generation failed", "err", err)
	}
	writeJSON(w, http.StatusCreated, out)
}

func (a *meshAPI) handleRevokeInvite(w http.ResponseWriter, r *http.Request, c caller) {
	id, ok := pathID(w, r)
	if ok {
		doneWithLogger(a.logger, w, a.svc.RevokeInvite(c.actor(), id))
	}
}

func (a *meshAPI) handleAdminMembers(w http.ResponseWriter, r *http.Request, c caller) {
	ms, err := a.svc.st.Members()
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, ms)
}

// The keeper's page: a searchable page of members with device counts, so a pen
// of ten thousand loads as fast as a pen of ten.
func (a *meshAPI) handleAdminHerd(w http.ResponseWriter, r *http.Request, c caller) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	for _, ch := range q {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			failWithLogger(a.logger, w, bad("search with the letters, digits and dashes a handle can have"))
			return
		}
	}
	if len(q) > 32 {
		q = q[:32]
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	const limit = 20
	ms, total, err := a.svc.st.Herd(q, limit, offset)
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": ms, "total": total, "offset": offset, "limit": limit})
}

func (a *meshAPI) handleAdminMemberAction(w http.ResponseWriter, r *http.Request, c caller) {
	var in struct {
		Reason string `json:"reason"`
		Role   string `json:"role"`
	}
	if !readOptionalJSON(w, r, &in) {
		return
	}
	handle := r.PathValue("handle")
	switch r.PathValue("action") {
	case "suspend":
		doneWithLogger(a.logger, w, a.svc.Suspend(r.Context(), c.actor(), handle, in.Reason))
	case "resume":
		doneWithLogger(a.logger, w, a.svc.Resume(r.Context(), c.actor(), handle))
	case "kick":
		rep, err := a.svc.Kick(r.Context(), c.actor(), handle, in.Reason)
		if err != nil {
			failWithLogger(a.logger, w, err)
			return
		}
		writeJSON(w, http.StatusOK, rep)
	case "role":
		doneWithLogger(a.logger, w, a.svc.SetRole(r.Context(), c.actor(), handle, in.Role))
	default:
		failWithLogger(a.logger, w, missing("unknown action"))
	}
}

func (a *meshAPI) handleAdminDevices(w http.ResponseWriter, r *http.Request, c caller) {
	ds, err := a.svc.st.LiveDevices()
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	byID := a.svc.PresenceSnapshot(r.Context())
	out := make([]deviceView, 0, len(ds))
	for _, d := range ds {
		online, lastSeen := nodePresence(byID, d.HSNodeID)
		out = append(out, deviceView{Device: d, Online: online, LastSeen: lastSeen})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *meshAPI) handleAdminInvites(w http.ResponseWriter, r *http.Request, c caller) {
	if r.URL.Query().Get("open") == "1" {
		invs, err := a.svc.st.OpenInvites(100)
		if err != nil {
			failWithLogger(a.logger, w, err)
			return
		}
		writeJSON(w, http.StatusOK, inviteViews(invs))
		return
	}
	invs, err := a.svc.st.Invites(nil)
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, inviteViews(invs))
}

func (a *meshAPI) handleAdminAudit(w http.ResponseWriter, r *http.Request, c caller) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 || n > 1000 {
		n = 100
	}
	entries, err := a.svc.st.AuditLog(n)
	if err != nil {
		failWithLogger(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// ------------------------------------------------------------------ views --

type directoryEntry struct {
	Name     string `json:"name"`
	Member   string `json:"member"`
	Note     string `json:"note"`
	Private  bool   `json:"private,omitempty"`
	Online   *bool  `json:"online,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
}

type deviceView struct {
	*Device
	Online   *bool  `json:"online,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
}

func indexNodesByID(nodes []HSNode) map[string]HSNode {
	byID := make(map[string]HSNode, len(nodes))
	for _, n := range nodes {
		if n.ID != "" {
			byID[n.ID] = n
		}
	}
	return byID
}

func normalizeLastSeen(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || t.IsZero() || t.Unix() <= 0 {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func nodePresence(byID map[string]HSNode, hsNodeID string) (*bool, string) {
	if hsNodeID == "" || len(byID) == 0 {
		return nil, ""
	}
	n, ok := byID[hsNodeID]
	if !ok {
		return nil, ""
	}
	online := n.Online
	return &online, normalizeLastSeen(n.LastSeen)
}

type inviteView struct {
	*Invite
	State string `json:"state"`
}

func inviteViews(in []*Invite) []inviteView {
	out := make([]inviteView, 0, len(in))
	for _, i := range in {
		out = append(out, inviteView{i, i.State()})
	}
	return out
}

func buildPenDeleteView(s *Service, callerHandle string, meta *hostMeta) (penDeleteView, error) {
	v := penDeleteView{
		Pen:             meta.Pen,
		CanDelete:       true,
		HasSubscription: meta.HasSubscription,
	}
	ms, err := s.st.Members()
	if err != nil {
		return penDeleteView{}, err
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
		return penDeleteView{}, err
	}
	v.DeviceCount = len(ds)
	return v, nil
}

// ownerCount tells owners and admins how many owners the pen has; plain members
// omit the field entirely.
func ownerCount(s *Service, a Actor) (int, bool, error) {
	if !a.IsAdmin() {
		return 0, false, nil
	}
	n, err := s.st.CountOwners()
	if err != nil {
		return 0, false, err
	}
	return n, true, nil
}
