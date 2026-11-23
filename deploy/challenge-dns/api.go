package main

// Two HTTP surfaces, each on its own Unix socket:
//   API (registrars):  POST/DELETE /v1/txt, POST /v1/eab. Bearer token.
//   admin (root CLI):  credentials. The socket itself is the authentication:
//                      mode 0600, root only, never mounted anywhere.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type API struct {
	store *Store
	eab   EABMinter // nil when no GTS service account is configured
	// contact is the operator's address for fallback CA accounts. Google refuses
	// an account without one, so no key is minted (and none wasted) without it.
	contact string
	global  *windowLimiter
}

type txtReq struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func failRateLimit(w http.ResponseWriter, rle *rateLimitError) {
	secs := int(rle.retryAfter / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	fail(w, http.StatusTooManyRequests, rle.Error())
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return false
	}
	return true
}

func (a *API) auth(w http.ResponseWriter, r *http.Request) (Cred, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		fail(w, http.StatusUnauthorized, "missing bearer token")
		return Cred{}, false
	}
	c, ok := a.store.Auth(strings.TrimSpace(tok))
	if !ok {
		fail(w, http.StatusUnauthorized, "unknown token")
		return Cred{}, false
	}
	return c, true
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/txt", func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.auth(w, r)
		if !ok {
			return
		}
		var in txtReq
		if !readJSON(w, r, &in) {
			return
		}
		var rle *rateLimitError
		switch err := a.store.PutTXT(c, in.FQDN, in.Value); {
		case err == nil:
			log.Printf("txt put %s by %s", normalize(in.FQDN), c.ID)
			writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
		case errors.Is(err, errRevoked):
			fail(w, http.StatusUnauthorized, "unauthorized")
		case errors.Is(err, errScope):
			fail(w, http.StatusForbidden, err.Error())
		case errors.Is(err, errValue):
			fail(w, http.StatusBadRequest, err.Error())
		case errors.As(err, &rle):
			failRateLimit(w, rle)
		case errors.Is(err, errFull):
			fail(w, http.StatusConflict, err.Error())
		default:
			log.Printf("txt put: %v", err)
			fail(w, http.StatusInternalServerError, "internal error")
		}
	})
	mux.HandleFunc("DELETE /v1/txt", func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.auth(w, r)
		if !ok {
			return
		}
		var in txtReq
		if !readJSON(w, r, &in) {
			return
		}
		switch err := a.store.DeleteTXT(c, in.FQDN, in.Value); {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, errRevoked):
			fail(w, http.StatusUnauthorized, "unauthorized")
		case errors.Is(err, errScope):
			fail(w, http.StatusForbidden, err.Error())
		default:
			fail(w, http.StatusInternalServerError, "internal error")
		}
	})
	mux.HandleFunc("POST /v1/eab", func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.auth(w, r)
		if !ok {
			return
		}
		if a.eab == nil {
			fail(w, http.StatusServiceUnavailable, "no fallback certificate authority is configured")
			return
		}
		if a.contact == "" {
			fail(w, http.StatusServiceUnavailable, "the fallback certificate authority has no contact address configured (CDNS_GTS_CONTACT)")
			return
		}
		// Check per-credential EAB caps BEFORE consuming the shared global
		// burst limiter so one exhausted pen cannot starve other pens or host failover.
		if err := a.store.CheckEAB(c); err != nil {
			var rle *rateLimitError
			switch {
			case errors.Is(err, errRevoked):
				fail(w, http.StatusUnauthorized, "unauthorized")
			case errors.As(err, &rle):
				failRateLimit(w, rle)
			default:
				log.Printf("eab check for %s: %v", c.ID, err)
				fail(w, http.StatusInternalServerError, "internal error")
			}
			return
		}
		// Exempt the host gate-cert credential from the shared pen global limiter.
		if c.Kind != "host" && !a.global.allow(a.store.now()) {
			w.Header().Set("Retry-After", "60")
			fail(w, http.StatusTooManyRequests, "fallback account keys are rate-limited; try later")
			return
		}
		if err := a.store.AllowEAB(c); err != nil {
			var rle *rateLimitError
			switch {
			case errors.Is(err, errRevoked):
				fail(w, http.StatusUnauthorized, "unauthorized")
			case errors.As(err, &rle):
				failRateLimit(w, rle)
			default:
				log.Printf("eab allow for %s: %v", c.ID, err)
				fail(w, http.StatusInternalServerError, "internal error")
			}
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		kid, hmac, err := a.eab.Mint(ctx)
		if err != nil {
			log.Printf("eab mint for %s: %v", c.ID, err)
			fail(w, http.StatusBadGateway, "could not get a fallback account key")
			return
		}
		log.Printf("eab minted for %s", c.ID)
		writeJSON(w, http.StatusCreated, map[string]string{"kid": kid, "hmac_b64url": hmac, "contact": a.contact})
	})
	return mux
}

// AdminHandler manages credentials. Served only on the root-only socket.
func AdminHandler(s *Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/creds", func(w http.ResponseWriter, r *http.Request) {
		type view struct {
			ID      string    `json:"id"`
			Kind    string    `json:"kind"`
			PenID   string    `json:"pen_id,omitempty"`
			Plan    string    `json:"plan,omitempty"`
			Created time.Time `json:"created"`
		}
		var out []view
		for _, c := range s.Creds() {
			out = append(out, view{c.ID, c.Kind, c.PenID, c.Plan, c.Created})
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /admin/creds", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Kind  string `json:"kind"`
			PenID string `json:"pen_id"`
			Plan  string `json:"plan,omitempty"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		c, tok, err := s.AddCredWithPlan(in.Kind, in.PenID, in.Plan)
		if err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		res := map[string]string{"id": c.ID, "token": tok}
		if c.Plan != "" {
			res["plan"] = c.Plan
		}
		writeJSON(w, http.StatusCreated, res)
	})
	mux.HandleFunc("PUT /admin/creds/{id}/plan", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Plan string `json:"plan"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		c, err := s.SetCredPlan(r.PathValue("id"), in.Plan)
		if err != nil {
			code := http.StatusBadRequest
			if strings.HasPrefix(err.Error(), "no pen credential ") {
				code = http.StatusNotFound
			}
			fail(w, code, err.Error())
			return
		}
		plan := c.Plan
		if plan == "" {
			plan = planPersonal
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": c.ID, "pen_id": c.PenID, "plan": plan})
	})
	// Sign-up asks before raising a pen: a name used once is never used again.
	mux.HandleFunc("GET /admin/names/{name}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"used": s.NameUsed(r.PathValue("name"))})
	})
	mux.HandleFunc("DELETE /admin/creds/{id}", func(w http.ResponseWriter, r *http.Request) {
		release := r.URL.Query().Get("release_if_unused") == "1"
		released, err := s.RemoveCredWithOptions(r.PathValue("id"), release)
		if err != nil {
			fail(w, http.StatusNotFound, err.Error())
			return
		}
		if released {
			w.Header().Set("X-Name-Released", "true")
		} else {
			w.Header().Set("X-Name-Released", "false")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// windowLimiter allows at most perMin events a minute and perHour an hour.
type windowLimiter struct {
	mu              sync.Mutex
	perMin, perHour int
	events          []time.Time
}

func (l *windowLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.events[:0]
	min := 0
	for _, t := range l.events {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
			if now.Sub(t) < time.Minute {
				min++
			}
		}
	}
	l.events = kept
	if min >= l.perMin || len(kept) >= l.perHour {
		return false
	}
	l.events = append(l.events, now)
	return true
}

// listenUnix listens on a socket path with the given mode and group.
func listenUnix(path string, mode os.FileMode, gid int) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			ln.Close()
			return nil, err
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// adminClient talks to the admin socket from the CLI.
func adminClient(sock string) *http.Client {
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
}

func adminDo(sock, method, path string, body any) ([]byte, int, error) {
	b, code, _, err := adminDoWithHeaders(sock, method, path, body)
	return b, code, err
}

func adminDoWithHeaders(sock, method, path string, body any) ([]byte, int, http.Header, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, "http://admin"+path, rd)
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := adminClient(sock).Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("is the server running? %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return b, resp.StatusCode, resp.Header, nil
}
