package main

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
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

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
			return forbidden("this pen is woken for renewal only; only active owners or admins on personal devices can access billing")
		}
		if !pol.AllowRenewOnly {
			return forbidden("this pen is woken for renewal only; shares, devices, invites, and directory are unavailable until renewal")
		}
	}
	switch pol.Device {
	case devicePersonalOnly:
		if c.device.Kind == "server" {
			return forbidden("server devices cannot perform this action; use a personal device")
		}
	case deviceServerOnly:
		if c.device.Kind != "server" {
			return forbidden("server devices only")
		}
	case deviceAny:
	default:
		return forbidden("unsupported device policy")
	}
	if pol.Role == roleAdmin && !c.actor().IsAdmin() {
		return forbidden("admins only")
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

// identifyDirect resolves the calling device strictly from the authenticated
// WireGuard peer identity returned by tsnet WhoIs (node ID, node public key,
// key expiry, and IP) matched against SQLite. X-Forwarded-For is never consulted
// and no Headscale REST call is made on steady-state requests.
func identifyDirect(s *Service, resolvePeer func(ctx context.Context, remoteAddr string) (*PeerIdentity, error), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if resolvePeer == nil {
			fail(w, forbidden("this device is not enrolled in the network"))
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || net.ParseIP(host) == nil {
			fail(w, forbidden("this device is not enrolled in the network"))
			return
		}
		peer, err := resolvePeer(r.Context(), r.RemoteAddr)
		if err != nil || peer == nil || peer.IP == "" || net.ParseIP(peer.IP) == nil {
			fail(w, forbidden("this device is not enrolled in the network"))
			return
		}
		m, d, err := s.VerifyDirectPeer(r.Context(), peer)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				fail(w, forbidden("this device is not enrolled in the network"))
				return
			}
			failWithLogger(s.loggerOrDefault(), w, err)
			return
		}
		if m.Status != "active" {
			fail(w, forbidden("membership %s", m.Status))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, caller{member: m, device: d})))
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
		m, d, err := s.VerifyLiveCaller(r.Context(), src)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				fail(w, forbidden("this device is not enrolled in the network"))
				return
			}
			failWithLogger(s.loggerOrDefault(), w, err)
			return
		}
		if m.Status != "active" {
			fail(w, forbidden("membership %s", m.Status))
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

func doneWithLogger(logger *slog.Logger, w http.ResponseWriter, err error) {
	if err != nil {
		failWithLogger(logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func fail(w http.ResponseWriter, err error) {
	failWithLogger(slog.Default(), w, err)
}

func failWithLogger(logger *slog.Logger, w http.ResponseWriter, err error) {
	var p *Problem
	if errors.As(err, &p) {
		if p.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(p.RetryAfter))
		}
		writeJSON(w, p.Status, map[string]string{"error": p.Msg})
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger.Error("internal error", "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
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
