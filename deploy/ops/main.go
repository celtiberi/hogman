package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFS embed.FS

const (
	defaultListenAddr = "127.0.0.1:8080"
	defaultSnapDir    = "/run/hogman-ops"
	snapshotFileName  = "snapshot.json"
	maxSnapshotBytes  = 2 << 20 // 2 MiB
	allowedAuditTTL   = 15 * time.Minute
	maxAuditKeys      = 256
)

// Snapshot is the strict v1 single-host read-only schema written by the host
// collector to /run/hogman-ops/snapshot.json. Decoding into this typed struct
// ensures unexpected fields (such as raw waiting-list emails or notes) are
// never forwarded even if something ever placed them in the file.
type Snapshot struct {
	GeneratedAt string           `json:"generated_at"`
	Host        HostSnapshot     `json:"host"`
	Pens        []PenSnapshot    `json:"pens"`
	Waitlist    WaitlistSnapshot `json:"waitlist"`
}

type HostSnapshot struct {
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	UptimeSec     int64             `json:"uptime_sec"`
	Load          [3]float64        `json:"load"`
	RAMUsedBytes  uint64            `json:"ram_used_bytes"`
	RAMTotalBytes uint64            `json:"ram_total_bytes"`
	SwapUsedBytes uint64            `json:"swap_used_bytes"`
	SwapTotalBytes uint64           `json:"swap_total_bytes"`
	DiskUsedBytes uint64            `json:"disk_used_bytes"`
	DiskTotalBytes uint64           `json:"disk_total_bytes"`
	Capacity      CapacitySnapshot  `json:"capacity"`
	Services      map[string]string `json:"services"`
	LastBackupAt  string            `json:"last_backup_at,omitempty"`
}

type CapacitySnapshot struct {
	Live         int `json:"live"`
	Max          int `json:"max"`
	Sleeping     int `json:"sleeping"`
	RenewOnly    int `json:"renew_only"`
	RenewReserve int `json:"renew_reserve"`
}

type PenSnapshot struct {
	Name            string `json:"name"`
	PublicHost      string `json:"public_host,omitempty"`
	Plan            string `json:"plan"`
	Theme           string `json:"theme"`
	State           string `json:"state"`
	PaidUntil       string `json:"paid_until,omitempty"`
	DeleteAfter     string `json:"delete_after,omitempty"`
	ContainersUp    int    `json:"containers_up"`
	ContainersTotal int    `json:"containers_total"`
	RAMBytes        uint64 `json:"ram_bytes"`
}

type WaitlistSnapshot struct {
	Waiting             int   `json:"waiting"`
	Invited             int   `json:"invited"`
	OldestWaitingAgeSec int64 `json:"oldest_waiting_age_sec,omitempty"`
}

type snapshotResponse struct {
	Snapshot
	Viewer string `json:"viewer"`
}

type auditEvent struct {
	TS     string `json:"ts"`
	Event  string `json:"event"`
	Actor  string `json:"actor,omitempty"`
	Node   string `json:"node,omitempty"`
	IP     string `json:"ip,omitempty"`
	Tags   string `json:"tags,omitempty"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type opsConfig struct {
	SnapshotDir    string
	AllowedHandles map[string]bool
	AuditOut       io.Writer
	Now            func() time.Time
}

type opsServer struct {
	cfg      opsConfig
	auditMu  sync.Mutex
	lastSeen map[string]time.Time
	web      http.Handler
}

func parseAllowedHandles(raw string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		h := strings.ToLower(strings.TrimSpace(part))
		if h != "" {
			out[h] = true
		}
	}
	return out
}

func newOpsServer(cfg opsConfig) (*opsServer, error) {
	if cfg.SnapshotDir == "" {
		cfg.SnapshotDir = defaultSnapDir
	}
	if cfg.AuditOut == nil {
		cfg.AuditOut = os.Stdout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, err
	}
	return &opsServer{
		cfg:      cfg,
		lastSeen: map[string]time.Time{},
		web:      http.FileServer(http.FS(sub)),
	}, nil
}

func (s *opsServer) emitAudit(ev auditEvent) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	b = append(b, '\n')
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	_, _ = s.cfg.AuditOut.Write(b)
}

// shouldLogAllowed suppresses repetitive allowed-call audit lines from 60s
// background polling while still recording page loads and periodic direct API
// reads (at most one allowed line per (actor, node) within allowedAuditTTL,
// plus page loads on "/").
func (s *opsServer) shouldLogAllowed(actor, node, path string, now time.Time) bool {
	key := actor + "|" + node
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if path == "/" || path == "/index.html" {
		s.recordAuditKeyLocked(key, now)
		return true
	}
	if path != "/api/ops/snapshot" {
		// Static assets (/ops.css, /ops.js) accompany a page load and are not logged separately.
		return false
	}
	if prev, ok := s.lastSeen[key]; ok && now.Sub(prev) < allowedAuditTTL {
		return false
	}
	s.recordAuditKeyLocked(key, now)
	return true
}

func (s *opsServer) recordAuditKeyLocked(key string, now time.Time) {
	if len(s.lastSeen) >= maxAuditKeys {
		for k, ts := range s.lastSeen {
			if now.Sub(ts) >= allowedAuditTTL {
				delete(s.lastSeen, k)
			}
		}
		if len(s.lastSeen) >= maxAuditKeys {
			var oldestKey string
			var oldestTS time.Time
			first := true
			for k, ts := range s.lastSeen {
				if first || ts.Before(oldestTS) {
					first = false
					oldestKey = k
					oldestTS = ts
				}
			}
			if !first {
				delete(s.lastSeen, oldestKey)
			}
		}
	}
	s.lastSeen[key] = now
}

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *opsServer) readSnapshot() (*Snapshot, error) {
	// Open through os.OpenRoot on every request so atomic renames on the host
	// immediately take effect and symlinks escaping the directory are refused.
	root, err := os.OpenRoot(s.cfg.SnapshotDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	f, err := root.Open(snapshotFileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxSnapshotBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSnapshotBytes {
		return nil, errors.New("snapshot exceeds size limit")
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	if snap.Pens == nil {
		snap.Pens = []PenSnapshot{}
	}
	if snap.Host.Services == nil {
		snap.Host.Services = map[string]string{}
	}
	return &snap, nil
}

func (s *opsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	now := s.cfg.Now().UTC()

	handle := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Hogman-Handle")))
	node := strings.TrimSpace(r.Header.Get("X-Hogman-Node"))
	ip := strings.TrimSpace(r.Header.Get("X-Hogman-IP"))
	tags := strings.TrimSpace(r.Header.Get("X-Hogman-Tags"))

	deny := func(status int, reason, msg string) {
		s.emitAudit(auditEvent{
			TS:     now.Format(time.RFC3339),
			Event:  "denied",
			Actor:  handle,
			Node:   node,
			IP:     ip,
			Tags:   tags,
			Method: r.Method,
			Path:   r.URL.Path,
			Status: status,
			Reason: reason,
		})
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, status, map[string]string{"error": msg})
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		fmt.Fprintln(w, msg)
	}

	// Strictly read-only in v1.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		deny(http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	// Fail closed unless hogman-sidecar --identity-headers supplied a verified
	// personal-device handle on the OPS_HANDLES allowlist.
	if handle == "" {
		deny(http.StatusForbidden, "missing_handle", "access denied: missing caller identity")
		return
	}
	if tags != "" {
		deny(http.StatusForbidden, "tagged_peer", "access denied: personal devices only")
		return
	}
	if !s.cfg.AllowedHandles[handle] {
		deny(http.StatusForbidden, "handle_not_allowed", "access denied")
		return
	}

	if strings.HasPrefix(r.URL.Path, "/api/") {
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
			deny(http.StatusForbidden, "cross_origin", "cross-origin request refused")
			return
		}
		if r.URL.Path != "/api/ops/snapshot" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		snap, err := s.readSnapshot()
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "host snapshot unavailable"})
			return
		}
		if s.shouldLogAllowed(handle, node, r.URL.Path, now) {
			s.emitAudit(auditEvent{
				TS:     now.Format(time.RFC3339),
				Event:  "allowed",
				Actor:  handle,
				Node:   node,
				IP:     ip,
				Method: r.Method,
				Path:   r.URL.Path,
				Status: http.StatusOK,
			})
		}
		writeJSON(w, http.StatusOK, snapshotResponse{Snapshot: *snap, Viewer: handle})
		return
	}

	if s.shouldLogAllowed(handle, node, r.URL.Path, now) {
		s.emitAudit(auditEvent{
			TS:     now.Format(time.RFC3339),
			Event:  "allowed",
			Actor:  handle,
			Node:   node,
			IP:     ip,
			Method: r.Method,
			Path:   r.URL.Path,
			Status: http.StatusOK,
		})
	}
	s.web.ServeHTTP(w, r)
}

func main() {
	addr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if addr == "" {
		addr = defaultListenAddr
	}
	snapDir := strings.TrimSpace(os.Getenv("SNAPSHOT_DIR"))
	if snapDir == "" {
		snapDir = defaultSnapDir
	}
	handles := parseAllowedHandles(os.Getenv("OPS_HANDLES"))
	if len(handles) == 0 {
		log.Printf("warning: OPS_HANDLES is empty; all requests will be denied (403)")
	}
	srv, err := newOpsServer(opsConfig{
		SnapshotDir:    snapDir,
		AllowedHandles: handles,
	})
	if err != nil {
		log.Fatalf("init ops server: %v", err)
	}
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	log.Printf("hogman-ops listening on %s (snapshot_dir=%s, allowed_handles=%d)", addr, snapDir, len(handles))
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
