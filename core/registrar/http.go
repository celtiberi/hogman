package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ----------------------------------------------------------------- public --

// PublicHandler serves the one thing reachable from the internet: redeeming
// an invite. Mounted by the edge at https://<public host>/hogman/.
func PublicHandler(s *Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hogman/v1/redeem", func(w http.ResponseWriter, r *http.Request) {
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
	h := func(pattern string, admin bool, fn func(w http.ResponseWriter, r *http.Request, c caller)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			c := r.Context().Value(ctxKey{}).(caller)
			if admin && !c.actor().IsAdmin() {
				fail(w, forbidden("admins only"))
				return
			}
			fn(w, r, c)
		})
	}

	// --- member ---------------------------------------------------------

	h("GET /api/me", false, func(w http.ResponseWriter, r *http.Request, c caller) {
		devs, _ := s.st.MemberDevices(c.member.ID)
		names, _ := s.st.Names()
		mine := []*Name{}
		for _, n := range names {
			if n.MemberID == c.member.ID && n.HeldUntil == nil {
				mine = append(mine, n)
			}
		}
		invs, _ := s.st.Invites(&c.member.ID)
		writeJSON(w, 200, map[string]any{
			"member": c.member, "this_device": c.device, "devices": devs, "names": mine,
			"invites": inviteViews(invs), "zone": s.cfg.Zone,
		})
	})

	h("POST /api/devices", false, func(w http.ResponseWriter, r *http.Request, c caller) {
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
		writeJSON(w, 201, map[string]any{"auth_key": key, "expires_at": exp, "login_server": s.LoginServer(),
			"kind": in.Kind, "join_link": s.DeviceLink(key)})
	})

	h("DELETE /api/devices/{id}", false, func(w http.ResponseWriter, r *http.Request, c caller) {
		id, ok := pathID(w, r)
		if ok {
			done(w, s.RemoveDevice(r.Context(), c.actor(), id))
		}
	})

	h("POST /api/names", false, func(w http.ResponseWriter, r *http.Request, c caller) {
		var in struct {
			Name     string `json:"name"`
			DeviceID int64  `json:"device_id"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		fqdn, err := s.Claim(c.actor(), c.member.Handle, in.Name, in.DeviceID)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 201, map[string]string{"name": fqdn})
	})

	h("DELETE /api/names/{name}", false, func(w http.ResponseWriter, r *http.Request, c caller) {
		done(w, s.Release(c.actor(), r.PathValue("name")))
	})

	h("GET /api/directory", false, func(w http.ResponseWriter, r *http.Request, c caller) {
		names, err := s.st.ResolvableNames()
		if err != nil {
			fail(w, err)
			return
		}
		out := []map[string]string{}
		for _, n := range names {
			out = append(out, map[string]string{"name": n.Name + "." + s.cfg.Zone, "member": n.Member})
		}
		writeJSON(w, 200, out)
	})

	h("POST /api/invites", false, func(w http.ResponseWriter, r *http.Request, c caller) {
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
		writeJSON(w, 201, inv)
	})

	h("DELETE /api/invites/{id}", false, func(w http.ResponseWriter, r *http.Request, c caller) {
		id, ok := pathID(w, r)
		if ok {
			done(w, s.RevokeInvite(c.actor(), id))
		}
	})

	// --- admin ----------------------------------------------------------

	h("GET /api/admin/members", true, func(w http.ResponseWriter, r *http.Request, c caller) {
		ms, err := s.st.Members()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, ms)
	})

	h("POST /api/admin/members/{handle}/{action}", true, func(w http.ResponseWriter, r *http.Request, c caller) {
		var in struct {
			Reason string `json:"reason"`
			Role   string `json:"role"`
		}
		if r.ContentLength > 0 && !readJSON(w, r, &in) {
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

	h("GET /api/admin/devices", true, func(w http.ResponseWriter, r *http.Request, c caller) {
		ds, err := s.st.LiveDevices()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, ds)
	})

	h("GET /api/admin/invites", true, func(w http.ResponseWriter, r *http.Request, c caller) {
		invs, err := s.st.Invites(nil)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, inviteViews(invs))
	})

	h("GET /api/admin/audit", true, func(w http.ResponseWriter, r *http.Request, c caller) {
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

	return identify(s, mux)
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
		m, d, err := s.WhoIs(src)
		if err != nil {
			fail(w, forbidden("this device is not enrolled in the network"))
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

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, bad("bad request body: %v", err))
		return false
	}
	return true
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
