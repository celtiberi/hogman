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
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	maxHTTPBodyBytes  = 4 << 10
	maxAdminRespBytes = 1 << 20
)

func defaultLogger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

type boundaryWrappedKey struct{}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}

// wrapHTTP applies HTTP boundary hygiene idempotently:
//   - Cache-Control: no-store on every response
//   - Request body limit via http.MaxBytesReader
//   - Panic recovery returning JSON HTTP 500 with structured error logging
//   - Structured logging for server errors (HTTP >= 500)
func wrapHTTP(logger *slog.Logger, maxBodyBytes int64, next http.Handler) http.Handler {
	log := defaultLogger(logger)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(boundaryWrappedKey{}) != nil {
			next.ServeHTTP(w, r)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), boundaryWrappedKey{}, true))
		w.Header().Set("Cache-Control", "no-store")
		if maxBodyBytes > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		defer func() {
			if p := recover(); p != nil {
				log.Error("http handler panic",
					"method", r.Method,
					"path", r.URL.Path,
					"panic", fmt.Sprint(p),
				)
				if !rec.wroteHeader {
					fail(rec, http.StatusInternalServerError, "internal error")
				}
				return
			}
			if rec.status >= http.StatusInternalServerError {
				log.Error("http server error",
					"method", r.Method,
					"path", r.URL.Path,
					"status", rec.status,
					"duration_ms", time.Since(start).Milliseconds(),
				)
			}
		}()
		next.ServeHTTP(rec, r)
	})
}

type API struct {
	store *Store
	eab   EABMinter // nil when no GTS service account is configured
	// contact is the operator's address for fallback CA accounts. Google refuses
	// an account without one, so no key is minted (and none wasted) without it.
	contact string
	limiter *eabLimiter
	logger  *slog.Logger
}

func (a *API) log() *slog.Logger {
	return defaultLogger(a.logger)
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
	if a.limiter == nil {
		var clock func() time.Time
		if a.store != nil {
			clock = a.store.now
		}
		a.limiter = defaultEABLimiter(clock)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/txt", a.handlePutTXT)
	mux.HandleFunc("DELETE /v1/txt", a.handleDeleteTXT)
	mux.HandleFunc("POST /v1/eab", a.handlePostEAB)
	return wrapHTTP(a.logger, maxHTTPBodyBytes, mux)
}

func (a *API) handlePutTXT(w http.ResponseWriter, r *http.Request) {
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
		a.log().Info("txt put", "fqdn", normalize(in.FQDN), "cred_id", c.ID)
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
		a.log().Error("txt put failed", "cred_id", c.ID, "err", err)
		fail(w, http.StatusInternalServerError, "internal error")
	}
}

func (a *API) handleDeleteTXT(w http.ResponseWriter, r *http.Request) {
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
		a.log().Error("txt delete failed", "cred_id", c.ID, "err", err)
		fail(w, http.StatusInternalServerError, "internal error")
	}
}

func (a *API) handlePostEAB(w http.ResponseWriter, r *http.Request) {
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
	// Reserve per-credential EAB cap BEFORE consuming the shared global
	// burst limiter so one exhausted pen cannot starve other pens or host failover,
	// and do not persist quota or EverChallenged until upstream Mint succeeds.
	res, err := a.store.ReserveEAB(c)
	if err != nil {
		a.writeEABError(w, c.ID, "reserve", err)
		return
	}
	defer res.Cancel()
	if allowed, reason := a.limiter.Allow(c.Kind, c.ID); !allowed {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusTooManyRequests, reason)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	kid, hmac, err := a.eab.Mint(ctx)
	if err != nil {
		a.limiter.RecordFailure(c.Kind, c.ID)
		a.log().Error("eab mint failed", "cred_id", c.ID, "err", err)
		fail(w, http.StatusBadGateway, "could not get a fallback account key")
		return
	}
	if err := res.Commit(); err != nil {
		a.writeEABError(w, c.ID, "commit", err)
		return
	}
	a.log().Info("eab minted", "cred_id", c.ID)
	writeJSON(w, http.StatusCreated, map[string]string{"kid": kid, "hmac_b64url": hmac, "contact": a.contact})
}

func (a *API) writeEABError(w http.ResponseWriter, credID, op string, err error) {
	var rle *rateLimitError
	switch {
	case errors.Is(err, errRevoked):
		fail(w, http.StatusUnauthorized, "unauthorized")
	case errors.As(err, &rle):
		failRateLimit(w, rle)
	default:
		a.log().Error("eab operation failed", "op", op, "cred_id", credID, "err", err)
		fail(w, http.StatusInternalServerError, "internal error")
	}
}

// AdminHandler manages credentials. Served only on the root-only socket.
func AdminHandler(s *Store, logger *slog.Logger) http.Handler {
	log := defaultLogger(logger)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/creds", func(w http.ResponseWriter, r *http.Request) {
		type view struct {
			ID      string    `json:"id"`
			Kind    string    `json:"kind"`
			PenID   string    `json:"pen_id,omitempty"`
			Plan    string    `json:"plan,omitempty"`
			Created time.Time `json:"created"`
		}
		creds := s.Creds()
		out := make([]view, 0, len(creds))
		for _, c := range creds {
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
			if errors.Is(err, errInvalidInput) {
				fail(w, http.StatusBadRequest, err.Error())
			} else {
				log.Error("add cred failed", "kind", in.Kind, "pen_id", in.PenID, "err", err)
				fail(w, http.StatusInternalServerError, "internal error")
			}
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
			switch {
			case errors.Is(err, errNotFound):
				fail(w, http.StatusNotFound, err.Error())
			case errors.Is(err, errInvalidInput):
				fail(w, http.StatusBadRequest, err.Error())
			default:
				log.Error("set cred plan failed", "id", r.PathValue("id"), "err", err)
				fail(w, http.StatusInternalServerError, "internal error")
			}
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
			if errors.Is(err, errNotFound) {
				fail(w, http.StatusNotFound, err.Error())
			} else {
				log.Error("remove cred failed", "id", r.PathValue("id"), "err", err)
				fail(w, http.StatusInternalServerError, "internal error")
			}
			return
		}
		if released {
			w.Header().Set("X-Name-Released", "true")
		} else {
			w.Header().Set("X-Name-Released", "false")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return wrapHTTP(log, maxHTTPBodyBytes, mux)
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
	return adminDoWithClient(adminClient(sock), "http://admin"+path, method, body)
}

func adminDoWithClient(hc *http.Client, targetURL, method string, body any) ([]byte, int, http.Header, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, nil, err
		}
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, targetURL, rd)
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("is the server running? %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAdminRespBytes+1))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("read admin response: %w", err)
	}
	if len(b) > maxAdminRespBytes {
		return nil, 0, nil, fmt.Errorf("admin response exceeds %d-byte limit", maxAdminRespBytes)
	}
	return b, resp.StatusCode, resp.Header, nil
}
