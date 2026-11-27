package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"hogman/registrar/internal/acme"
	"hogman/registrar/internal/registrar"
)

// apiError represents an HTTP-edge error (CSRF, Content-Type, malformed body,
// unauthenticated peer, public rate limit).
type apiError struct {
	status     int
	msg        string
	retryAfter int
}

func (e *apiError) Error() string { return e.msg }

func httpBad(f string, a ...any) error {
	return &apiError{status: http.StatusBadRequest, msg: fmt.Sprintf(f, a...)}
}
func httpForbidden(f string, a ...any) error {
	return &apiError{status: http.StatusForbidden, msg: fmt.Sprintf(f, a...)}
}
func httpNotFound(f string, a ...any) error {
	return &apiError{status: http.StatusNotFound, msg: fmt.Sprintf(f, a...)}
}

type roleRequirement int

const (
	roleAny roleRequirement = iota
	roleAdmin
)

type devicePolicy int

const (
	// devicePersonalOnly is the zero value so routes fail closed for server
	// devices unless explicitly opened.
	devicePersonalOnly devicePolicy = iota
	deviceAny
	deviceServerOnly
)

// routePolicy declares the authorization and renew-only constraints for a
// single mesh API route right at registration time.
type routePolicy struct {
	Role           roleRequirement
	Device         devicePolicy
	AllowRenewOnly bool
}

// enforceRoutePolicy checks caller eligibility against pol and renew-only mode.
func enforceRoutePolicy(pol routePolicy, c caller, renewOnly bool) error {
	if renewOnly {
		if c.device.Kind == "server" || c.member.Status != "active" || !c.actor().IsAdmin() {
			return httpForbidden("this pen is woken for renewal only; only active owners or admins on personal devices can access billing")
		}
		if !pol.AllowRenewOnly {
			return httpForbidden("this pen is woken for renewal only; shares, devices, invites, and directory are unavailable until renewal")
		}
	}
	switch pol.Device {
	case devicePersonalOnly:
		if c.device.Kind == "server" {
			return httpForbidden("server devices cannot perform this action; use a personal device")
		}
	case deviceServerOnly:
		if c.device.Kind != "server" {
			return httpForbidden("server devices only")
		}
	case deviceAny:
	default:
		return httpForbidden("unsupported device policy")
	}
	if pol.Role == roleAdmin && !c.actor().IsAdmin() {
		return httpForbidden("admins only")
	}
	return nil
}

type httpBoundaryKey struct{}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if !sr.written {
		sr.status = code
		sr.written = true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	if !sr.written {
		sr.status = http.StatusOK
		sr.written = true
	}
	return sr.ResponseWriter.Write(b)
}

func (sr *statusRecorder) Unwrap() http.ResponseWriter {
	return sr.ResponseWriter
}

// recoverAndLog wraps an HTTP handler with panic recovery (returning JSON 500
// without leaking stack traces) and structured logging of server errors (5xx).
// It is idempotent when nested (e.g. PortalHandler wrapping MeshHandlerDirect).
func recoverAndLog(logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(httpBoundaryKey{}) != nil {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		req := r.WithContext(context.WithValue(r.Context(), httpBoundaryKey{}, true))
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				logger.Error("http handler panic",
					"method", r.Method,
					"path", r.URL.Path,
					"panic", fmt.Sprint(rec),
					"stack", string(debug.Stack()),
				)
				if !sr.written {
					writeJSON(sr, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				}
				return
			}
			if sr.status >= http.StatusInternalServerError {
				logger.Error("http server error",
					"method", r.Method,
					"path", r.URL.Path,
					"status", sr.status,
					"duration_ms", time.Since(start).Milliseconds(),
				)
			}
		}()
		next.ServeHTTP(sr, req)
	})
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
			writeError(nil, w, httpForbidden("cross-origin request refused"))
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if origin := r.Header.Get("Origin"); origin != "" && origin != portalOrigin {
				writeError(nil, w, httpForbidden("cross-origin request refused"))
				return
			}
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
				mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || mt != "application/json" {
					writeError(nil, w, &apiError{status: http.StatusUnsupportedMediaType, msg: "Content-Type must be application/json"})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// identifyDirect resolves the calling device strictly from the authenticated
// WireGuard peer identity returned by tsnet WhoIs (node ID, node public key,
// key expiry, and IP) matched against SQLite. X-Forwarded-For is never consulted
// and no Headscale REST call is made on steady-state requests.
func identifyDirect(s *registrar.Service, resolvePeer func(ctx context.Context, remoteAddr string) (*registrar.PeerIdentity, error), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if resolvePeer == nil {
			writeError(s.Logger(), w, httpForbidden("this device is not enrolled in the network"))
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || net.ParseIP(host) == nil {
			writeError(s.Logger(), w, httpForbidden("this device is not enrolled in the network"))
			return
		}
		peer, err := resolvePeer(r.Context(), r.RemoteAddr)
		if err != nil || peer == nil || peer.IP == "" || net.ParseIP(peer.IP) == nil {
			writeError(s.Logger(), w, httpForbidden("this device is not enrolled in the network"))
			return
		}
		m, d, err := s.VerifyDirectPeer(r.Context(), peer)
		if err != nil {
			if errors.Is(err, registrar.ErrNotFound) {
				writeError(s.Logger(), w, httpForbidden("this device is not enrolled in the network"))
				return
			}
			writeError(s.Logger(), w, err)
			return
		}
		if m.Status != "active" {
			writeError(s.Logger(), w, httpForbidden("membership %s", m.Status))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, caller{member: m, device: d})))
	})
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

func decodeJSON(w http.ResponseWriter, r *http.Request, v any, allowEmpty bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if allowEmpty && errors.Is(err, io.EOF) {
			return true
		}
		writeError(nil, w, httpBad("bad request body: %v", err))
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
		writeError(nil, w, httpBad("bad id"))
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

func writeOK(logger *slog.Logger, w http.ResponseWriter, err error) {
	if err != nil {
		writeError(logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func domainErrorStatus(kind registrar.ErrorKind) int {
	switch kind {
	case registrar.KindInvalid:
		return http.StatusBadRequest
	case registrar.KindForbidden:
		return http.StatusForbidden
	case registrar.KindNotFound:
		return http.StatusNotFound
	case registrar.KindConflict:
		return http.StatusConflict
	case registrar.KindRateLimited:
		return http.StatusTooManyRequests
	case registrar.KindUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// writeError is the single HTTP-edge error translator mapping HTTP-edge errors,
// domain *registrar.Error values, and upstream *acme.ChallengeError values to
// JSON responses and Retry-After headers. Unexpected errors are logged and
// returned as an opaque HTTP 500.
func writeError(logger *slog.Logger, w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		if ae.retryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(ae.retryAfter))
		}
		writeJSON(w, ae.status, map[string]string{"error": ae.msg})
		return
	}
	var de *registrar.Error
	if errors.As(err, &de) {
		if de.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(de.RetryAfter))
		}
		writeJSON(w, domainErrorStatus(de.Kind), map[string]string{"error": de.Msg})
		return
	}
	var ce *acme.ChallengeError
	if errors.As(err, &ce) {
		if ce.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(ce.RetryAfter))
		}
		writeJSON(w, ce.Status, map[string]string{"error": ce.Msg})
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger.Error("internal error", "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
}
