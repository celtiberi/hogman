package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"hogman/registrar/internal/headscale"
	"hogman/registrar/internal/ratelimit"
	"hogman/registrar/internal/registrar"
	"hogman/registrar/internal/store"
)

// ----------------------------------------------------------------- public --

// PublicHandler serves the one thing reachable from the internet: redeeming
// an invite. Mounted by the edge at https://<public host>/hogman/.
func PublicHandler(s *registrar.Service) http.Handler {
	return PublicHandlerWithRateLimit(s, 20, time.Minute)
}

func PublicHandlerWithRateLimit(s *registrar.Service, redeemLimit int, window time.Duration) http.Handler {
	logger := s.Logger()
	lim := ratelimit.NewWindow[string](redeemLimit, window, ratelimit.DefaultMaxKeys)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hogman/v1/redeem", func(w http.ResponseWriter, r *http.Request) {
		if s.IsRenewOnly() {
			writeError(logger, w, httpForbidden("this pen is woken for renewal only; invites and new devices are unavailable until renewal"))
			return
		}
		if ok, retry := lim.Allow(ratelimit.Key(clientIP(r)), s.Clock()); !ok {
			writeError(logger, w, &apiError{
				status:     http.StatusTooManyRequests,
				msg:        "too many requests; try again shortly",
				retryAfter: retry,
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
			writeError(logger, w, err)
			return
		}
		writeJSON(w, http.StatusCreated, enr)
	})
	// What a joining device needs before it is on the mesh. Nothing secret.
	mux.HandleFunc("GET /hogman/v1/network", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.NetworkInfo())
	})
	return recoverAndLog(logger, mux)
}

// ------------------------------------------------------------------- mesh --

type ctxKey struct{}

type caller struct {
	member *store.Member
	device *store.Device
}

func (c caller) actor() registrar.Actor { return registrar.Actor{Member: c.member} }

// MeshHandlerDirect is the member and admin API served directly on the
// embedded tsnet listener (https://home.<zone>/api/). Caller identity comes
// strictly from the WireGuard connection's RemoteAddr verified via tsnet WhoIs
// (node ID + node public key + IP, checked against SQLite); X-Forwarded-For
// and all other HTTP headers are ignored.
func MeshHandlerDirect(s *registrar.Service, resolvePeer func(ctx context.Context, remoteAddr string) (*registrar.PeerIdentity, error)) http.Handler {
	api := &meshAPI{svc: s, logger: s.Logger()}
	return recoverAndLog(api.logger, requireSameOriginAndJSON(s.Zone(), identifyDirect(s, resolvePeer, api.routes())))
}

// PortalHandler serves https://home.<zone> directly inside the registrar:
// static assets from portalDir and /api/* via apiHandler, with strict security
// headers.
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
	svc    *registrar.Service
	logger *slog.Logger
}

func (a *meshAPI) routes() http.Handler {
	mux := http.NewServeMux()
	reg := func(pattern string, pol routePolicy, fn func(w http.ResponseWriter, r *http.Request, c caller)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			c := r.Context().Value(ctxKey{}).(caller)
			if err := enforceRoutePolicy(pol, c, a.svc.IsRenewOnly()); err != nil {
				writeError(a.logger, w, err)
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
			"member": c.member, "this_device": c.device, "zone": s.Zone(),
			"network": s.NetworkInfo(),
		})
		return
	}
	devs, err := s.ListMemberDevices(c.member.ID)
	if err != nil {
		writeError(a.logger, w, err)
		return
	}
	names, err := s.ListNames()
	if err != nil {
		writeError(a.logger, w, err)
		return
	}
	mine := []*store.Name{}
	for _, n := range names {
		if n.MemberID == c.member.ID && n.RetiredAt == nil {
			mine = append(mine, n)
		}
	}
	invs, err := s.ListInvites(&c.member.ID)
	if err != nil {
		writeError(a.logger, w, err)
		return
	}
	act := c.actor()
	resp := map[string]any{
		"member": c.member, "this_device": c.device, "devices": devs, "names": mine,
		"invites": inviteViews(invs), "zone": s.Zone(),
		"can_invite": act.IsAdmin() || s.MembersCanInvite(),
		"is_admin":   act.IsAdmin(), "is_owner": act.IsOwner(),
		"network": s.NetworkInfo(),
	}
	if act.IsAdmin() {
		n, err := s.CountOwners()
		if err != nil {
			writeError(a.logger, w, err)
			return
		}
		resp["owners"] = n
	}
	if view := s.Billing().View(act.IsAdmin()); view != nil {
		resp["billing"] = *view
	}
	if act.IsOwner() && c.member.Status == "active" {
		delView, err := s.PenDeleteView(c.member.Handle)
		if err != nil {
			writeError(a.logger, w, err)
			return
		}
		if delView != nil {
			resp["pen_delete"] = *delView
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *meshAPI) handleRenewToken(w http.ResponseWriter, r *http.Request, c caller) {
	renewURL, exp, err := a.svc.MintRenewToken(c.actor())
	if err != nil {
		writeError(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"url":        renewURL,
		"expires_at": exp.UTC().Format(time.RFC3339),
	})
}

func (a *meshAPI) handlePenDeleteToken(w http.ResponseWriter, r *http.Request, c caller) {
	var in struct {
		Confirm string `json:"confirm"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	delURL, exp, err := a.svc.MintPenDeleteToken(c.actor(), in.Confirm)
	if err != nil {
		writeError(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"url":        delURL,
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
		writeError(a.logger, w, err)
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

func (a *meshAPI) handleDeleteDevice(w http.ResponseWriter, r *http.Request, c caller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if c.device.Kind == "server" && id != c.device.ID {
		writeError(a.logger, w, httpForbidden("a server can only remove itself"))
		return
	}
	if id == c.device.ID {
		if err := a.svc.SelfRemoveDevice(c.actor(), id); err != nil {
			writeError(a.logger, w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
		return
	}
	writeOK(a.logger, w, a.svc.RemoveDevice(r.Context(), c.actor(), id))
}

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
		writeError(a.logger, w, httpBad("cannot pass both name and private"))
		return
	}
	var fqdn string
	var err error
	if c.device.Kind == "server" {
		if in.DeviceID != 0 && in.DeviceID != c.device.ID {
			writeError(a.logger, w, httpForbidden("a server can only name itself"))
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
		writeError(a.logger, w, err)
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
		writeOK(a.logger, w, a.svc.ServerRelease(c.actor(), c.device, r.PathValue("name")))
		return
	}
	writeOK(a.logger, w, a.svc.Release(c.actor(), r.PathValue("name")))
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
		writeError(a.logger, w, err)
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
		writeError(a.logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *meshAPI) handleMintACMEEAB(w http.ResponseWriter, r *http.Request, c caller) {
	pair, err := a.svc.ServerMintACMEEAB(r.Context(), c.device)
	if err != nil {
		writeError(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

func (a *meshAPI) handleDirectory(w http.ResponseWriter, r *http.Request, c caller) {
	s := a.svc
	names, err := s.ListResolvableNames()
	if err != nil {
		writeError(a.logger, w, err)
		return
	}
	byID := s.PresenceSnapshot(r.Context())
	out := make([]DirectoryEntry, 0, len(names))
	for _, n := range names {
		entry := DirectoryEntry{
			Name:    n.Name + "." + s.Zone(),
			Member:  n.Member,
			Note:    n.Note,
			Private: n.Private,
		}
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
		writeError(a.logger, w, err)
		return
	}
	out := struct {
		*registrar.MintedInvite
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
		writeOK(a.logger, w, a.svc.RevokeInvite(c.actor(), id))
	}
}

func (a *meshAPI) handleAdminMembers(w http.ResponseWriter, r *http.Request, c caller) {
	ms, err := a.svc.ListMembers()
	if err != nil {
		writeError(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, ms)
}

func (a *meshAPI) handleAdminHerd(w http.ResponseWriter, r *http.Request, c caller) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	for _, ch := range q {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			writeError(a.logger, w, httpBad("search with the letters, digits and dashes a handle can have"))
			return
		}
	}
	if len(q) > 32 {
		writeError(a.logger, w, httpBad("search query is too long (max 32 characters)"))
		return
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	const limit = 20
	ms, total, err := a.svc.ListHerd(q, limit, offset)
	if err != nil {
		writeError(a.logger, w, err)
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
		writeOK(a.logger, w, a.svc.Suspend(r.Context(), c.actor(), handle, in.Reason))
	case "resume":
		writeOK(a.logger, w, a.svc.Resume(r.Context(), c.actor(), handle))
	case "kick":
		rep, err := a.svc.Kick(r.Context(), c.actor(), handle, in.Reason)
		if err != nil {
			writeError(a.logger, w, err)
			return
		}
		writeJSON(w, http.StatusOK, rep)
	case "role":
		writeOK(a.logger, w, a.svc.SetRole(r.Context(), c.actor(), handle, in.Role))
	default:
		writeError(a.logger, w, httpNotFound("unknown action"))
	}
}

func (a *meshAPI) handleAdminDevices(w http.ResponseWriter, r *http.Request, c caller) {
	ds, err := a.svc.ListLiveDevices()
	if err != nil {
		writeError(a.logger, w, err)
		return
	}
	byID := a.svc.PresenceSnapshot(r.Context())
	out := make([]DeviceView, 0, len(ds))
	for _, d := range ds {
		online, lastSeen := nodePresence(byID, d.HSNodeID)
		out = append(out, DeviceView{Device: d, Online: online, LastSeen: lastSeen})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *meshAPI) handleAdminInvites(w http.ResponseWriter, r *http.Request, c caller) {
	if r.URL.Query().Get("open") == "1" {
		invs, err := a.svc.ListOpenInvites(100)
		if err != nil {
			writeError(a.logger, w, err)
			return
		}
		writeJSON(w, http.StatusOK, inviteViews(invs))
		return
	}
	invs, err := a.svc.ListInvites(nil)
	if err != nil {
		writeError(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, inviteViews(invs))
}

func (a *meshAPI) handleAdminAudit(w http.ResponseWriter, r *http.Request, c caller) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 || n > 1000 {
		n = 100
	}
	entries, err := a.svc.ListAuditLog(n)
	if err != nil {
		writeError(a.logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// ------------------------------------------------------------------ views --

type DirectoryEntry struct {
	Name     string `json:"name"`
	Member   string `json:"member"`
	Note     string `json:"note"`
	Private  bool   `json:"private,omitempty"`
	Online   *bool  `json:"online,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
}

type DeviceView struct {
	*store.Device
	Online   *bool  `json:"online,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
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

func nodePresence(byID map[string]headscale.Node, hsNodeID string) (*bool, string) {
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

type InviteView struct {
	*store.Invite
	State string `json:"state"`
}

func inviteViews(in []*store.Invite) []InviteView {
	out := make([]InviteView, 0, len(in))
	for _, i := range in {
		out = append(out, InviteView{i, i.State()})
	}
	return out
}
