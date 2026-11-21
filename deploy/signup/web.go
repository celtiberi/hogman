package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"
)

//go:embed web
var webFiles embed.FS

type web struct {
	brokerURL   string
	token       string
	domain      string
	client      *http.Client
	checks      *limiter // name checks while typing
	creates     *limiter // sign-up attempts, which also bounds guessing codes
	jobPolls    *limiter // status polls for /api/job
	waits       *limiter // waiting-list joins
	globalWaits *limiter // server-wide cap on waiting-list joins
	leaves      *limiter // taking yourself off the list (its own allowance)
	jobs        *jobStore
}

func runWeb() {
	wb := newWeb(env("BROKER_URL", "http://broker:9090"), readToken(), env("PENS_DOMAIN", ""))
	addr := env("LISTEN", ":8080")
	log.Printf("sign-up page on %s", addr)
	srv := &http.Server{Addr: addr, Handler: wb.handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func newWeb(brokerURL, token, domain string) *web {
	return &web{
		brokerURL:   strings.TrimRight(brokerURL, "/"),
		token:       token,
		domain:      domain,
		client:      &http.Client{Timeout: 16 * time.Minute},
		checks:      newLimiter(60, time.Minute),
		creates:     newLimiter(5, time.Hour),
		jobPolls:    newLimiter(120, time.Minute),
		waits:       newLimiter(5, time.Hour),
		globalWaits: newLimiterWithCap(30, time.Hour, 4),
		leaves:      newLimiter(5, time.Hour),
		jobs:        newJobStore(defaultMaxOpenJobs, defaultMaxStoredJobs, defaultJobTTL, defaultDeliveredTTL),
	}
}

func (wb *web) handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFiles, "web")
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/status", wb.status)
	mux.HandleFunc("GET /api/check", wb.check)
	mux.HandleFunc("POST /api/create", wb.create)
	mux.HandleFunc("GET /api/job", wb.job)
	mux.HandleFunc("POST /api/waitlist", wb.waitlist)
	mux.HandleFunc("POST /api/waitlist/leave", wb.leaveWaitlist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Origin-Agent-Cluster", "?1")
		mux.ServeHTTP(w, r)
	})
}

// ask calls the broker and passes its status and JSON back.
func (wb *web) ask(ctx context.Context, method, path string, body any) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, wb.brokerURL+path, rd)
	req.Header.Set("Authorization", "Bearer "+wb.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := wb.client.Do(req)
	if err != nil {
		log.Printf("broker: %v", err)
		return 502, map[string]any{"error": "the sign-up service is down; try again later"}
	}
	defer resp.Body.Close()
	out := map[string]any{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return 502, map[string]any{"error": "the sign-up service is down; try again later"}
	}
	return resp.StatusCode, out
}

func (wb *web) status(w http.ResponseWriter, r *http.Request) {
	code, out := wb.ask(r.Context(), "GET", "/capacity", nil)
	if code != 200 {
		jsonOut(w, code, out)
		return
	}
	jsonOut(w, 200, map[string]any{"open": out["open"], "pens_domain": wb.domain})
}

func (wb *web) check(w http.ResponseWriter, r *http.Request) {
	if !wb.checks.allow(rateLimitKey(clientIP(r)), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "slow down a little"})
		return
	}
	pen := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("pen")))
	if why, ok := validPen(pen); !ok {
		jsonOut(w, 200, map[string]any{"free": false, "reason": why})
		return
	}
	code, out := wb.ask(r.Context(), "GET", "/check?pen="+pen, nil)
	jsonOut(w, code, out)
}

func (wb *web) create(w http.ResponseWriter, r *http.Request) {
	if !wb.creates.allow(rateLimitKey(clientIP(r)), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "too many tries from here; wait an hour"})
		return
	}
	var in struct {
		Code   string `json:"code"`
		Pen    string `json:"pen"`
		Handle string `json:"handle"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	in.Pen = strings.ToLower(strings.TrimSpace(in.Pen))
	in.Handle = strings.ToLower(strings.TrimSpace(in.Handle))
	in.Code = normCode(in.Code)
	if why, ok := validPen(in.Pen); !ok {
		jsonOut(w, 400, map[string]string{"error": "pen name: " + why})
		return
	}
	if why, ok := validHandle(in.Handle); !ok {
		jsonOut(w, 400, map[string]string{"error": "your name: " + why})
		return
	}
	if !codeRE.MatchString(in.Code) {
		jsonOut(w, 403, map[string]string{"error": "that sign-up code isn't right"})
		return
	}
	code, out := wb.ask(r.Context(), "POST", "/validate", map[string]string{"code": in.Code, "pen": in.Pen, "owner": in.Handle})
	if code != 200 {
		jsonOut(w, code, out)
		return
	}
	// Raising a pen takes a minute or so. It runs as a job the page checks on,
	// so no single request has to survive that long (proxies and browsers drop
	// them) and a reload picks up where it left off.
	id, ok := wb.jobs.start(func() (int, map[string]any) {
		ctx, cancel := context.WithTimeout(context.Background(), 16*time.Minute)
		defer cancel()
		code, out := wb.ask(ctx, "POST", "/provision", map[string]string{"code": in.Code, "pen": in.Pen, "owner": in.Handle})
		if code == 201 {
			if link, _ := out["join_link"].(string); link != "" {
				if svg, err := qrSVG(link); err == nil {
					out["join_qr_svg"] = svg
				}
			}
		}
		return code, out
	})
	if !ok {
		jsonOut(w, 503, map[string]string{"error": "sign-up is busy right now; try again in a minute"})
		return
	}
	jsonOut(w, 202, map[string]string{"job": id})
}

// job reports on a sign-up: working, or its terminal result (re-readable for
// 5 minutes after first delivery within the 30-minute unread TTL, to whoever
// holds the job's id, which only the page that started it knows).
func (wb *web) job(w http.ResponseWriter, r *http.Request) {
	if !wb.jobPolls.allow(rateLimitKey(clientIP(r)), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "slow down a little"})
		return
	}
	j, ok := wb.jobs.take(r.URL.Query().Get("id"))
	if !ok {
		jsonOut(w, 404, map[string]string{"error": "we lost track of that sign-up; if it finished, your code is used and the pen exists. Ask whoever gave you the code."})
		return
	}
	if !j.done {
		jsonOut(w, 200, map[string]any{"state": "working", "seconds": int(time.Since(j.started).Seconds())})
		return
	}
	if j.status == 201 {
		jsonOut(w, 200, map[string]any{"state": "done", "result": j.out})
		return
	}
	msg, _ := j.out["error"].(string)
	if msg == "" {
		msg = "raising your pen failed"
	}
	jsonOut(w, 200, map[string]any{"state": "failed", "status": j.status, "error": msg})
}

const (
	defaultMaxOpenJobs   = 4
	defaultMaxStoredJobs = 32
	defaultJobTTL        = 30 * time.Minute
	defaultDeliveredTTL  = 5 * time.Minute
)

type job struct {
	started   time.Time
	finished  time.Time
	delivered time.Time
	done      bool
	status    int
	out       map[string]any
}

type jobStore struct {
	mu           sync.Mutex
	maxOpen      int
	maxStored    int
	ttl          time.Duration
	deliveredTTL time.Duration
	now          func() time.Time
	jobs         map[string]*job
}

func newJobStore(maxOpen, maxStored int, ttl, deliveredTTL time.Duration) *jobStore {
	return &jobStore{
		maxOpen:      maxOpen,
		maxStored:    maxStored,
		ttl:          ttl,
		deliveredTTL: deliveredTTL,
		now:          time.Now,
		jobs:         map[string]*job{},
	}
}

func (s *jobStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *jobStore) expired(j *job, now time.Time) bool {
	if !j.done {
		return false
	}
	ttl := s.ttl
	if ttl <= 0 {
		ttl = defaultJobTTL
	}
	if now.Sub(j.finished) > ttl {
		return true
	}
	if !j.delivered.IsZero() {
		dttl := s.deliveredTTL
		if dttl <= 0 {
			dttl = defaultDeliveredTTL
		}
		if now.Sub(j.delivered) > dttl {
			return true
		}
	}
	return false
}

func (s *jobStore) start(run func() (int, map[string]any)) (string, bool) {
	s.mu.Lock()
	maxOpen := s.maxOpen
	if maxOpen <= 0 {
		maxOpen = defaultMaxOpenJobs
	}
	maxStored := s.maxStored
	if maxStored <= 0 {
		maxStored = defaultMaxStoredJobs
	}
	now := s.clock()
	open := 0
	for k, j := range s.jobs {
		if s.expired(j, now) {
			delete(s.jobs, k)
			continue
		}
		if !j.done {
			open++
		}
	}
	if open >= maxOpen {
		s.mu.Unlock()
		return "", false
	}
	for len(s.jobs) >= maxStored {
		var oldestID string
		var oldestAt time.Time
		found := false
		for k, j := range s.jobs {
			if !j.done {
				continue
			}
			if !found || j.finished.Before(oldestAt) {
				found = true
				oldestID = k
				oldestAt = j.finished
			}
		}
		if !found {
			s.mu.Unlock()
			return "", false
		}
		delete(s.jobs, oldestID)
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	j := &job{started: now}
	s.jobs[id] = j
	s.mu.Unlock()
	go func() {
		status, out := run()
		s.mu.Lock()
		j.done, j.finished, j.status, j.out = true, s.clock(), status, out
		s.mu.Unlock()
	}()
	return id, true
}

func (s *jobStore) take(id string) (job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return job{}, false
	}
	now := s.clock()
	if s.expired(j, now) {
		delete(s.jobs, id)
		return job{}, false
	}
	if j.done && j.delivered.IsZero() {
		j.delivered = now
	}
	return *j, true
}

// clientIP: the front door sets X-Forwarded-For to the real client, and is
// the only thing that can reach this page.
func clientIP(r *http.Request) string {
	if x := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); x != "" {
		parts := strings.Split(x, ",")
		if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
			return a.Unmap().String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if a, perr := netip.ParseAddr(host); perr == nil {
			return a.Unmap().String()
		}
		return host
	}
	return r.RemoteAddr
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

type limitBucket struct {
	hits []time.Time
	last time.Time
}

type limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	maxKeys int
	seen    map[string]*limitBucket
}

func newLimiter(limit int, window time.Duration) *limiter {
	return newLimiterWithCap(limit, window, 4096)
}

func newLimiterWithCap(limit int, window time.Duration, maxKeys int) *limiter {
	if maxKeys <= 0 {
		maxKeys = 4096
	}
	return &limiter{limit: limit, window: window, maxKeys: maxKeys, seen: map[string]*limitBucket{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, exists := l.seen[key]; exists {
		keep := b.hits[:0]
		for _, t := range b.hits {
			if now.Sub(t) < l.window {
				keep = append(keep, t)
			}
		}
		b.last = now
		if len(keep) >= l.limit {
			b.hits = keep
			return false
		}
		b.hits = append(keep, now)
		return true
	}
	maxKeys := l.maxKeys
	if maxKeys <= 0 {
		maxKeys = 4096
	}
	if len(l.seen) >= maxKeys {
		for k, b := range l.seen {
			if len(b.hits) == 0 || now.Sub(b.hits[len(b.hits)-1]) >= l.window {
				delete(l.seen, k)
			}
		}
	}
	if len(l.seen) >= maxKeys {
		var oldestKey string
		var oldestAt time.Time
		first := true
		for k, b := range l.seen {
			if first || b.last.Before(oldestAt) {
				first = false
				oldestKey = k
				oldestAt = b.last
			}
		}
		if !first {
			delete(l.seen, oldestKey)
		}
	}
	l.seen[key] = &limitBucket{hits: []time.Time{now}, last: now}
	return true
}

// qrSVG draws a QR code as an SVG of black squares.
func qrSVG(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := code.Size
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 `)
	b.WriteString(itoa(n + 2*quiet))
	b.WriteString(" ")
	b.WriteString(itoa(n + 2*quiet))
	b.WriteString(`" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="`)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if code.Black(x, y) {
				b.WriteString("M" + itoa(x+quiet) + " " + itoa(y+quiet) + "h1v1h-1z")
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}

func itoa(i int) string { return strconv.Itoa(i) }

func (wb *web) waitlist(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	if !wb.waits.allow(rateLimitKey(clientIP(r)), now) || !wb.globalWaits.allow("*", now) {
		jsonOut(w, 429, map[string]string{"error": "too many tries right now; try again later"})
		return
	}
	var in struct {
		Email string `json:"email"`
		Pen   string `json:"pen"`
		Note  string `json:"note"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if !validEmail(in.Email) {
		jsonOut(w, 400, map[string]string{"error": "that doesn't look like an email address"})
		return
	}
	code, out := wb.ask(r.Context(), "POST", "/waitlist", map[string]string{
		"email": in.Email, "pen": strings.ToLower(strings.TrimSpace(in.Pen)), "note": cleanField(in.Note, 280)})
	jsonOut(w, code, out)
}

func (wb *web) leaveWaitlist(w http.ResponseWriter, r *http.Request) {
	if !wb.leaves.allow(rateLimitKey(clientIP(r)), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "too many tries from here; wait an hour"})
		return
	}
	var in struct {
		Email string `json:"email"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if !validEmail(in.Email) {
		jsonOut(w, 400, map[string]string{"error": "that doesn't look like an email address"})
		return
	}
	code, out := wb.ask(r.Context(), "POST", "/waitlist/leave", map[string]string{"email": in.Email})
	jsonOut(w, code, out)
}
