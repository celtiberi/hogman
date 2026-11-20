package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ----------------------------------------------------------------- public --

// PublicHandler serves the one thing reachable from the internet: redeeming
// an invite. Mounted by the edge at https://<public host>/hogman/.
func PublicHandler(s *Service) http.Handler {
	return PublicHandlerWithRateLimit(s, 20, time.Minute)
}

func PublicHandlerWithRateLimit(s *Service, redeemLimit int, window time.Duration) http.Handler {
	lim := newIPRateLimiter(redeemLimit, window)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hogman/v1/redeem", func(w http.ResponseWriter, r *http.Request) {
		if !lim.allow(clientIP(r), time.Now()) {
			fail(w, &Problem{http.StatusTooManyRequests, "too many requests; try again shortly"})
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
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, enr)
	})
	// What a joining device needs before it is on the mesh. Nothing secret:
	// the join tool pins the root against the fingerprint in its link.
	mux.HandleFunc("GET /hogman/v1/network", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.NetworkInfo())
	})
	return mux
}

type rateBucket struct {
	count int
	reset time.Time
}

type ipRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]*rateBucket
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{limit: limit, window: window, buckets: map[string]*rateBucket{}}
}

func (l *ipRateLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > 1024 {
		for k, b := range l.buckets {
			if !now.Before(b.reset) {
				delete(l.buckets, k)
			}
		}
	}
	b, ok := l.buckets[ip]
	if !ok || !now.Before(b.reset) {
		l.buckets[ip] = &rateBucket{count: 1, reset: now.Add(l.window)}
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		last := strings.TrimSpace(parts[len(parts)-1])
		if ip := net.ParseIP(last); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		return host
	}
	return r.RemoteAddr
}

// ------------------------------------------------------------------- mesh --

type ctxKey struct{}

type caller struct {
	member *Member
	device *Device
}

func (c caller) actor() Actor { return Actor{Member: c.member} }

// MeshHandler is the member and admin API, served only on the mesh behind the
// portal (https://home.<zone>/api/). The caller is identified by the mesh
// address their request came from: no passwords, no sessions.
func MeshHandler(s *Service) http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, admin, allowServer bool, fn func(w http.ResponseWriter, r *http.Request, c caller)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			c := r.Context().Value(ctxKey{}).(caller)
			if !allowServer && c.device.Kind == "server" {
				fail(w, forbidden("server devices cannot perform this action; use a personal device"))
				return
			}
			if admin && !c.actor().IsAdmin() {
				fail(w, forbidden("admins only"))
				return
			}
			fn(w, r, c)
		})
	}

	// --- member ---------------------------------------------------------

	h("GET /api/me", false, true, func(w http.ResponseWriter, r *http.Request, c caller) {
		if c.device.Kind == "server" {
			writeJSON(w, 200, map[string]any{
				"member": c.member, "this_device": c.device, "zone": s.cfg.Zone,
				"network": s.NetworkInfo(),
			})
			return
		}
		devs, _ := s.st.MemberDevices(c.member.ID)
		names, _ := s.st.Names()
		mine := []*Name{}
		for _, n := range names {
			if n.MemberID == c.member.ID && n.HeldUntil == nil {
				mine = append(mine, n)
			}
		}
		invs, _ := s.st.Invites(&c.member.ID)
		a := c.actor()
		writeJSON(w, 200, map[string]any{
			"member": c.member, "this_device": c.device, "devices": devs, "names": mine,
			"invites": inviteViews(invs), "zone": s.cfg.Zone,
			// What the page should offer. The API checks again on every call.
			"can_invite": a.IsAdmin() || s.cfg.MembersCanInvite,
			"is_admin":   a.IsAdmin(), "is_owner": a.IsOwner(),
			// A lone owner is warned: another owner is the only way back in (D-16).
			"owners": ownerCount(s, a),
			// What `hogman-join share` needs to start a server of its own.
			"network": s.NetworkInfo(),
		})
	})

	h("POST /api/devices", false, false, func(w http.ResponseWriter, r *http.Request, c caller) {
		var in struct {
			Kind string `json:"kind"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		key, exp, err := s.IssueDeviceKey(r.Context(), c.actor(), c.member.Handle, in.Kind)
		if err != nil {
			fail(w, err)
			return
		}
		link := s.DeviceLink(key, in.Kind)
		out := map[string]any{"auth_key": key, "expires_at": exp, "login_server": s.LoginServer(),
			"kind": in.Kind, "join_link": link}
		if svg, err := qrSVG(link); err == nil {
			out["join_qr_svg"] = svg
		} else {
			log.Printf("device link QR: %v", err)
		}
		writeJSON(w, 201, out)
	})

	// A server may remove itself (how `hogman-join share stop` cleans up), and
	// nothing else.
	h("DELETE /api/devices/{id}", false, true, func(w http.ResponseWriter, r *http.Request, c caller) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		if c.device.Kind == "server" && id != c.device.ID {
			fail(w, forbidden("a server can only remove itself"))
			return
		}
		done(w, s.RemoveDevice(r.Context(), c.actor(), id))
	})

	// A server may claim a name for itself (device_id 0 or its own id), as long
	// as the name is new or already points at it: `hogman-join share` names
	// itself without a trip to the home page, but cannot take over its
	// member's other names.
	h("POST /api/names", false, true, func(w http.ResponseWriter, r *http.Request, c caller) {
		var in struct {
			Name     string  `json:"name"`
			DeviceID int64   `json:"device_id"`
			Note     *string `json:"note"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		var fqdn string
		var err error
		if c.device.Kind == "server" {
			if in.DeviceID != 0 && in.DeviceID != c.device.ID {
				fail(w, forbidden("a server can only name itself"))
				return
			}
			fqdn, err = s.ServerClaim(c.actor(), c.device, in.Name, in.Note)
		} else {
			fqdn, err = s.Claim(c.actor(), c.member.Handle, in.Name, in.DeviceID, in.Note)
		}
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 201, map[string]string{"name": fqdn})
	})

	h("DELETE /api/names/{name}", false, true, func(w http.ResponseWriter, r *http.Request, c caller) {
		if c.device.Kind == "server" {
			done(w, s.ServerRelease(c.actor(), c.device, r.PathValue("name")))
			return
		}
		done(w, s.Release(c.actor(), r.PathValue("name")))
	})

	h("GET /api/directory", false, true, func(w http.ResponseWriter, r *http.Request, c caller) {
		names, err := s.st.ResolvableNames()
		if err != nil {
			fail(w, err)
			return
		}
		out := []map[string]string{}
		for _, n := range names {
			out = append(out, map[string]string{"name": n.Name + "." + s.cfg.Zone, "member": n.Member, "note": n.Note})
		}
		writeJSON(w, 200, out)
	})

	h("POST /api/invites", false, false, func(w http.ResponseWriter, r *http.Request, c caller) {
		var in struct {
			Role     string  `json:"role"`
			Note     string  `json:"note"`
			TTLHours float64 `json:"ttl_hours"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		inv, err := s.MintInvite(c.actor(), in.Role, in.Note, time.Duration(in.TTLHours*float64(time.Hour)))
		if err != nil {
			fail(w, err)
			return
		}
		out := struct {
			*MintedInvite
			QRSVG string `json:"qr_svg,omitempty"`
		}{MintedInvite: inv}
		if svg, err := qrSVG(inv.URL); err == nil {
			out.QRSVG = svg
		} else {
			log.Printf("invite link QR: %v", err)
		}
		writeJSON(w, 201, out)
	})

	h("DELETE /api/invites/{id}", false, false, func(w http.ResponseWriter, r *http.Request, c caller) {
		id, ok := pathID(w, r)
		if ok {
			done(w, s.RevokeInvite(c.actor(), id))
		}
	})

	// --- admin ----------------------------------------------------------

	h("GET /api/admin/members", true, false, func(w http.ResponseWriter, r *http.Request, c caller) {
		ms, err := s.st.Members()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, ms)
	})

	// The keeper's page: a searchable page of members with device counts, so a
	// pen of ten thousand loads as fast as a pen of ten.
	h("GET /api/admin/herd", true, false, func(w http.ResponseWriter, r *http.Request, c caller) {
		q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		for _, ch := range q {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				fail(w, bad("search with the letters, digits and dashes a handle can have"))
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
		ms, total, err := s.st.Herd(q, limit, offset)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"members": ms, "total": total, "offset": offset, "limit": limit})
	})

	h("POST /api/admin/members/{handle}/{action}", true, false, func(w http.ResponseWriter, r *http.Request, c caller) {
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
			done(w, s.Suspend(r.Context(), c.actor(), handle, in.Reason))
		case "resume":
			done(w, s.Resume(r.Context(), c.actor(), handle))
		case "kick":
			rep, err := s.Kick(r.Context(), c.actor(), handle, in.Reason)
			if err != nil {
				fail(w, err)
				return
			}
			writeJSON(w, 200, rep)
		case "role":
			done(w, s.SetRole(c.actor(), handle, in.Role))
		default:
			fail(w, missing("unknown action"))
		}
	})

	h("GET /api/admin/devices", true, false, func(w http.ResponseWriter, r *http.Request, c caller) {
		ds, err := s.st.LiveDevices()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, ds)
	})

	h("GET /api/admin/invites", true, false, func(w http.ResponseWriter, r *http.Request, c caller) {
		if r.URL.Query().Get("open") == "1" {
			invs, err := s.st.OpenInvites(100)
			if err != nil {
				fail(w, err)
				return
			}
			writeJSON(w, 200, inviteViews(invs))
			return
		}
		invs, err := s.st.Invites(nil)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, inviteViews(invs))
	})

	h("GET /api/admin/audit", true, false, func(w http.ResponseWriter, r *http.Request, c caller) {
		n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if n <= 0 || n > 1000 {
			n = 100
		}
		log, err := s.st.AuditLog(n)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, log)
	})

	return identify(s, requireSameOriginAndJSON(s.cfg.Zone, mux))
}

// requireSameOriginAndJSON blocks cross-site browser requests (CSRF) against the
// IP-authenticated mesh API. Because .hogman is not on the Public Suffix List,
// member sites like bob.<zone> share a "site" with home.<zone>, so Sec-Fetch-Site
// "same-site" must also be rejected.
func requireSameOriginAndJSON(zone string, next http.Handler) http.Handler {
	portalOrigin := "https://home." + zone
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
				fail(w, forbidden("cross-origin request refused"))
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && origin != portalOrigin {
				fail(w, forbidden("cross-origin request refused"))
				return
			}
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
				mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || mt != "application/json" {
					fail(w, &Problem{http.StatusUnsupportedMediaType, "Content-Type must be application/json"})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// identify resolves the calling device from its mesh address. The portal's
// Caddy is the only client (it runs in the same network namespace and the
// API listens on loopback), and it reports the caller in X-Forwarded-For.
func identify(s *Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			fail(w, forbidden("mesh API is only reachable through the portal"))
			return
		}
		xff := r.Header.Get("X-Forwarded-For")
		parts := strings.Split(xff, ",")
		src := strings.TrimSpace(parts[len(parts)-1])
		if src == "" || net.ParseIP(src) == nil {
			fail(w, forbidden("this device is not enrolled in the network"))
			return
		}
		m, d, err := s.VerifyLiveCaller(r.Context(), src)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				fail(w, forbidden("this device is not enrolled in the network"))
				return
			}
			fail(w, err)
			return
		}
		if m.Status != "active" {
			fail(w, forbidden("membership %s", m.Status))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, caller{member: m, device: d})))
	})
}

// --------------------------------------------------------------- helpers --

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

func decodeJSON(w http.ResponseWriter, r *http.Request, v any, allowEmpty bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if allowEmpty && errors.Is(err, io.EOF) {
			return true
		}
		fail(w, bad("bad request body: %v", err))
		return false
	}
	return true
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeJSON(w, r, v, false)
}

func readOptionalJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeJSON(w, r, v, true)
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, bad("bad id"))
		return 0, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func done(w http.ResponseWriter, err error) {
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func fail(w http.ResponseWriter, err error) {
	var p *Problem
	if errors.As(err, &p) {
		writeJSON(w, p.Status, map[string]string{"error": p.Msg})
		return
	}
	log.Printf("internal error: %v", err)
	writeJSON(w, 500, map[string]string{"error": "internal error"})
}

// ownerCount tells an owner how many owners the pen has; others get 0.
func ownerCount(s *Service, a Actor) int {
	if !a.IsOwner() {
		return 0
	}
	n, _ := s.st.CountOwners()
	return n
}
