package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
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
		if s.isRenewOnly() {
			fail(w, forbidden("this pen is woken for renewal only; invites and new devices are unavailable until renewal"))
			return
		}
		if !lim.allow(rateLimitKey(clientIP(r)), time.Now()) {
			fail(w, &Problem{Status: http.StatusTooManyRequests, Msg: "too many requests; try again shortly"})
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
	last  time.Time
}

type ipRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	maxKeys int
	buckets map[string]*rateBucket
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return newIPRateLimiterWithCap(limit, window, 1024)
}

func newIPRateLimiterWithCap(limit int, window time.Duration, maxKeys int) *ipRateLimiter {
	if maxKeys <= 0 {
		maxKeys = 1024
	}
	return &ipRateLimiter{limit: limit, window: window, maxKeys: maxKeys, buckets: map[string]*rateBucket{}}
}

func (l *ipRateLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.buckets[ip]; ok {
		if !now.Before(b.reset) {
			b.count = 1
			b.reset = now.Add(l.window)
			b.last = now
			return true
		}
		b.last = now
		if b.count >= l.limit {
			return false
		}
		b.count++
		return true
	}
	maxKeys := l.maxKeys
	if maxKeys <= 0 {
		maxKeys = 1024
	}
	if len(l.buckets) >= maxKeys {
		for k, b := range l.buckets {
			if !now.Before(b.reset) {
				delete(l.buckets, k)
			}
		}
	}
	if len(l.buckets) >= maxKeys {
		var oldestKey string
		var oldestAt time.Time
		first := true
		for k, b := range l.buckets {
			if first || b.last.Before(oldestAt) {
				first = false
				oldestKey = k
				oldestAt = b.last
			}
		}
		if !first {
			delete(l.buckets, oldestKey)
		}
	}
	l.buckets[ip] = &rateBucket{count: 1, reset: now.Add(l.window), last: now}
	return true
}

func rateLimitKey(raw string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	a = a.Unmap()
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().String()
	}
	return a.String()
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
	nodes  []HSNode
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
			if s.isRenewOnly() {
				if c.device.Kind == "server" || c.member.Status != "active" || !c.actor().IsAdmin() {
					fail(w, forbidden("this pen is woken for renewal only; only active owners or admins on personal devices can access billing"))
					return
				}
				if pattern != "GET /api/me" && pattern != "POST /api/billing/renew-token" {
					fail(w, forbidden("this pen is woken for renewal only; shares, devices, invites, and directory are unavailable until renewal"))
					return
				}
			}
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
			if n.MemberID == c.member.ID && n.RetiredAt == nil {
				mine = append(mine, n)
			}
		}
		invs, _ := s.st.Invites(&c.member.ID)
		a := c.actor()
		resp := map[string]any{
			"member": c.member, "this_device": c.device, "devices": devs, "names": mine,
			"invites": inviteViews(invs), "zone": s.cfg.Zone,
			// What the page should offer. The API checks again on every call.
			"can_invite": a.IsAdmin() || s.cfg.MembersCanInvite,
			"is_admin":   a.IsAdmin(), "is_owner": a.IsOwner(),
			// A lone owner is warned: another owner is the only way back in (D-16).
			"owners": ownerCount(s, a),
			// What `hogman share` needs to start a server of its own.
			"network": s.NetworkInfo(),
		}
		if billing := readBillingStatus(s.cfg.BillingStatusPath); billing != nil {
			resp["billing"] = billingView{
				State:      billing.State,
				PaidUntil:  billing.PaidUntil,
				GraceUntil: billing.GraceUntil,
				WakeUntil:  billing.WakeUntil,
				CanRenew:   a.IsAdmin() && billing.Pen != "" && billing.RenewURL != "",
			}
		} else if s.isRenewOnly() {
			resp["billing"] = billingView{
				State:    "renew_only",
				CanRenew: false,
			}
		}
		writeJSON(w, 200, resp)
	})

	// D-35: In-pen authenticated renewal (owners & admins on a personal device).
	// Mints a short-lived (15m), single-use, purpose- and pen-bound HMAC token
	// returned in the URL fragment (#renew=<token>) so it never hits logs or referers.
	h("POST /api/billing/renew-token", true, false, func(w http.ResponseWriter, r *http.Request, c caller) {
		billing := readBillingStatus(s.cfg.BillingStatusPath)
		if billing == nil || (billing.State != "grace" && billing.State != "renew_only") || billing.Pen == "" || billing.RenewURL == "" {
			fail(w, &Problem{Status: http.StatusConflict, Msg: "this pen is not currently in a renewable grace or wake window"})
			return
		}
		if c.member.Status != "active" || (c.member.Role != "owner" && c.member.Role != "admin") {
			fail(w, forbidden("only active owners or admins can renew"))
			return
		}
		keyPath := filepath.Join(filepath.Dir(s.cfg.BillingStatusPath), "renew.key")
		token, exp, err := mintRenewToken(keyPath, billing.Pen, c.member.Handle, c.member.Role, time.Now().UTC())
		if err != nil {
			log.Printf("billing renew-token: %v", err)
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"url":        strings.TrimRight(billing.RenewURL, "/") + "/#renew=" + token,
			"expires_at": exp.UTC().Format(time.RFC3339),
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

	// A server may remove itself (how `hogman share stop` cleans up), and
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
	// as the name is new or already points at it: `hogman share` names
	// itself without a trip to the home page, but cannot take over its
	// member's other names.
	h("POST /api/names", false, true, func(w http.ResponseWriter, r *http.Request, c caller) {
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
			fail(w, bad("cannot pass both name and private"))
			return
		}
		var fqdn string
		var err error
		if c.device.Kind == "server" {
			if in.DeviceID != 0 && in.DeviceID != c.device.ID {
				fail(w, forbidden("a server can only name itself"))
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
			fail(w, err)
			return
		}
		if in.Private {
			writeJSON(w, 201, map[string]any{"name": fqdn, "private": true})
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

	h("POST /api/acme/txt", false, true, func(w http.ResponseWriter, r *http.Request, c caller) {
		if c.device.Kind != "server" {
			fail(w, forbidden("server devices only"))
			return
		}
		var in struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		fqdn, err := s.ServerSetACMETXT(r.Context(), c.device, in.Name, in.Value)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"fqdn": fqdn})
	})

	h("DELETE /api/acme/txt", false, true, func(w http.ResponseWriter, r *http.Request, c caller) {
		if c.device.Kind != "server" {
			fail(w, forbidden("server devices only"))
			return
		}
		var in struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if err := s.ServerDeleteACMETXT(r.Context(), c.device, in.Name, in.Value); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	h("POST /api/acme/eab", false, true, func(w http.ResponseWriter, r *http.Request, c caller) {
		if c.device.Kind != "server" {
			fail(w, forbidden("server devices only"))
			return
		}
		pair, err := s.ServerMintACMEEAB(r.Context(), c.device)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, pair)
	})

	h("GET /api/directory", false, true, func(w http.ResponseWriter, r *http.Request, c caller) {
		names, err := s.st.ResolvableNames()
		if err != nil {
			fail(w, err)
			return
		}
		byID := indexNodesByID(c.nodes)
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
		byID := indexNodesByID(c.nodes)
		out := make([]deviceView, 0, len(ds))
		for _, d := range ds {
			online, lastSeen := nodePresence(byID, d.HSNodeID)
			out = append(out, deviceView{Device: d, Online: online, LastSeen: lastSeen})
		}
		writeJSON(w, 200, out)
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

	return requireSameOriginAndJSON(s.cfg.Zone, identify(s, mux))
}

// requireSameOriginAndJSON blocks cross-site browser requests (CSRF and
// drive-by Headscale amplification) before identify() runs. Because .hogman
// and pens.hogman.network are not on the Public Suffix List, member sites like
// bob.<zone> share a "site" with home.<zone>, so Sec-Fetch-Site "same-site"
// must also be rejected (including on browser GETs; non-browser CLI callers
// omit Sec-Fetch-Site).
func requireSameOriginAndJSON(zone string, next http.Handler) http.Handler {
	portalOrigin := "https://home." + zone
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
			fail(w, forbidden("cross-origin request refused"))
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if origin := r.Header.Get("Origin"); origin != "" && origin != portalOrigin {
				fail(w, forbidden("cross-origin request refused"))
				return
			}
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
				mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || mt != "application/json" {
					fail(w, &Problem{Status: http.StatusUnsupportedMediaType, Msg: "Content-Type must be application/json"})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// identify resolves the calling device from its mesh address. In a pen, the
// portal's Caddy reaches it only over the mounted Unix socket (or loopback TCP
// in dev/tests) and reports the caller in X-Forwarded-For.
func identify(s *Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip := net.ParseIP(host); !viaSocket(r.Context()) && (ip == nil || !ip.IsLoopback()) {
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
		m, d, nodes, err := s.verifyLiveCallerWithNodes(r.Context(), src)
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
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, caller{member: m, device: d, nodes: nodes})))
	})
}

// --------------------------------------------------------------- helpers --

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
	if len(nodes) == 0 {
		return nil
	}
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
		if p.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(p.RetryAfter))
		}
		writeJSON(w, p.Status, map[string]string{"error": p.Msg})
		return
	}
	log.Printf("internal error: %v", err)
	writeJSON(w, 500, map[string]string{"error": "internal error"})
}

// billingStatus is the host-written grace/renew-only notice at
// /var/lib/registrar/billing-status.json.
type billingStatus struct {
	Pen        string `json:"pen,omitempty"`
	State      string `json:"state"`
	PaidUntil  string `json:"paid_until,omitempty"`
	GraceUntil string `json:"grace_until,omitempty"`
	WakeUntil  string `json:"wake_until,omitempty"`
	RenewURL   string `json:"renew_url,omitempty"`
}

// billingView is the sanitized projection returned on GET /api/me (never exposes
// signing material or unauthenticated renewal URLs).
type billingView struct {
	State      string `json:"state"`
	PaidUntil  string `json:"paid_until,omitempty"`
	GraceUntil string `json:"grace_until,omitempty"`
	WakeUntil  string `json:"wake_until,omitempty"`
	CanRenew   bool   `json:"can_renew,omitempty"`
}

const (
	renewTokenPurpose = "hogman-renew-v1:"
	renewTokenTTL     = 15 * time.Minute
)

func loadOrCreateRenewKey(path string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil {
		if k, derr := hex.DecodeString(strings.TrimSpace(string(raw))); derr == nil && len(k) == 32 {
			return k, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	encoded := []byte(hex.EncodeToString(key) + "\n")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			raw, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil, rerr
			}
			k, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
			if derr != nil || len(k) != 32 {
				return nil, errors.New("corrupt renew.key")
			}
			return k, nil
		}
		return nil, err
	}
	_, werr := f.Write(encoded)
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(path)
		return nil, werr
	}
	if cerr != nil {
		_ = os.Remove(path)
		return nil, cerr
	}
	return key, nil
}

func mintRenewToken(keyPath, pen, handle, role string, now time.Time) (string, time.Time, error) {
	key, err := loadOrCreateRenewKey(keyPath)
	if err != nil {
		return "", time.Time{}, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", time.Time{}, err
	}
	exp := now.UTC().Add(renewTokenTTL)
	rawPayload := fmt.Sprintf("v1|%s|%s|%s|%d|%s", pen, handle, role, exp.Unix(), hex.EncodeToString(nonce))
	payload := base64.RawURLEncoding.EncodeToString([]byte(rawPayload))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(renewTokenPurpose))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig, exp, nil
}

func renewOnlyMarkerPath(billingStatusPath string) string {
	if billingStatusPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(billingStatusPath), ".renew-only")
}

// isRenewOnlyMode reports whether the pen must run in restricted renew_only
// mode. Fails closed (B4):
//   - if the .renew-only marker exists (or cannot be stat'd for a reason other
//     than ENOENT), returns true even if billing-status.json is absent;
//   - if billing-status.json exists but is unreadable, oversized (>4096B),
//     unparseable JSON, or has state "renew_only", returns true.
func isRenewOnlyMode(billingStatusPath string) bool {
	if billingStatusPath == "" {
		return false
	}
	marker := renewOnlyMarkerPath(billingStatusPath)
	if _, err := os.Stat(marker); err == nil || !os.IsNotExist(err) {
		return true
	}
	fi, err := os.Stat(billingStatusPath)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil || fi.Size() > 4096 {
		return true
	}
	b, err := os.ReadFile(billingStatusPath)
	if err != nil || len(b) > 4096 {
		return true
	}
	var st billingStatus
	if err := json.Unmarshal(b, &st); err != nil {
		return true
	}
	return st.State != "grace"
}

func readBillingStatus(path string) *billingStatus {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 4096 {
		return nil
	}
	var st billingStatus
	if err := json.Unmarshal(b, &st); err != nil || (st.State != "grace" && st.State != "renew_only") {
		return nil
	}
	st.Pen = strings.ToLower(strings.TrimSpace(st.Pen))
	if st.RenewURL != "" {
		u, err := url.Parse(strings.TrimSpace(st.RenewURL))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			st.RenewURL = ""
		} else {
			st.RenewURL = "https://" + u.Host
		}
	}
	return &st
}

// ownerCount tells an owner how many owners the pen has; others get 0.
func ownerCount(s *Service, a Actor) int {
	if !a.IsOwner() {
		return 0
	}
	n, _ := s.st.CountOwners()
	return n
}

// The mesh API trusts X-Forwarded-For to say who is asking, so who can reach
// it matters (audit H2). In a pen it listens only on a Unix socket in a folder
// mounted into the registrar and the portal and nothing else: other services
// sharing the network namespace (core-mesh) have no way to it, and
// the kernel enforces that. MESH_ADDR "unix:/path" selects it; a host:port
// (the default, for development and tests) listens on loopback TCP instead.
type viaSocketKey struct{}

func markSocketConn(ctx context.Context, c net.Conn) context.Context {
	if _, ok := c.(*net.UnixConn); ok {
		return context.WithValue(ctx, viaSocketKey{}, true)
	}
	return ctx
}

func viaSocket(ctx context.Context) bool {
	v, _ := ctx.Value(viaSocketKey{}).(bool)
	return v
}

func listenMesh(addr string) (net.Listener, error) {
	path, ok := strings.CutPrefix(addr, "unix:")
	if !ok {
		return net.Listen("tcp", addr)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
