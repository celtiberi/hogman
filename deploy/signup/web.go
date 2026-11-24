package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"
)

//go:embed web
var webFiles embed.FS

type web struct {
	brokerURL       string
	token           string
	domain          string
	sitesDomain     string // what pens' names end in: the pens zone (e.g. pens.hogman.network)
	client          *http.Client
	statuses        *limiter // /api/status checks
	checks          *limiter // name checks while typing
	creates         *limiter // sign-up attempts, which also bounds guessing codes
	jobPolls        *limiter // status polls for /api/job
	waits           *limiter // waiting-list joins
	globalWaits     *limiter // server-wide cap on waiting-list joins
	leaves          *limiter // taking yourself off the list (its own allowance)
	checkouts       *limiter // starting a payment
	globalCheckouts *limiter // server-wide cap on Stripe Checkout session creation
	wakes           *limiter // public sleeping-pen renew-only wakes (I-7 Part 2)
	deletes         *limiter // self-service owner pen deletion (I-24)
	webhooks        *limiter // Stripe's calls (it retries what we refuse)
	jobs            *jobStore
	stripe          *stripeCheckout // nil: pens aren't for sale
	cancelMu        sync.Mutex      // serializes pending Stripe subscription cancellations (I-6)
	workHost        string          // optional secondary sign-up host (e.g. get.work.hogman.network)
	trustedProxies  []netip.Prefix
	turnstile       *turnstileVerifier
}

func runWeb() {
	wb := newWeb(env("BROKER_URL", "http://broker:9090"), readToken(), env("PENS_DOMAIN", ""))
	wb.sitesDomain = env("SITES_DOMAIN", "pens.hogman.network")
	wb.workHost = stripHostPort(env("WORK_SIGNUP_HOST", ""))
	wb.stripe = loadStripeCheckout()
	proxies, err := trustedProxiesFromEnv()
	if err != nil {
		log.Fatalf("trusted proxies: %v", err)
	}
	wb.trustedProxies = proxies
	tv, err := turnstileFromEnv()
	if err != nil {
		log.Fatalf("turnstile: %v", err)
	}
	wb.turnstile = tv
	if wb.workHost != "" {
		log.Printf("work sign-up host enabled: %s", wb.workHost)
	}
	if len(wb.trustedProxies) > 0 {
		log.Printf("trusting CF-Connecting-IP from %d proxy CIDRs", len(wb.trustedProxies))
	}
	if wb.turnstile != nil {
		log.Printf("Cloudflare Turnstile enabled (expected hosts: %v)", wb.turnstile.expectedHosts)
	}
	if wb.stripe != nil {
		go wb.runPendingSubCancelLoop()
	}
	addr := env("LISTEN", ":8080")
	log.Printf("sign-up page on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           wb.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func newWeb(brokerURL, token, domain string) *web {
	return &web{
		brokerURL:       strings.TrimRight(brokerURL, "/"),
		token:           token,
		domain:          domain,
		sitesDomain:     "pens.hogman.network",
		client:          &http.Client{Timeout: 16 * time.Minute},
		statuses:        newLimiter(120, time.Minute),
		checks:          newLimiter(60, time.Minute),
		creates:         newLimiter(5, time.Hour),
		jobPolls:        newLimiter(120, time.Minute),
		waits:           newLimiter(5, time.Hour),
		globalWaits:     newLimiterWithCap(30, time.Hour, 4),
		leaves:          newLimiter(5, time.Hour),
		checkouts:       newLimiter(10, time.Hour),
		globalCheckouts: newLimiterWithCap(300, time.Hour, 4),
		wakes:           newLimiter(5, time.Hour),
		deletes:         newLimiter(5, time.Hour),
		webhooks:        newLimiter(120, time.Minute),
		jobs:            newJobStore(defaultMaxOpenJobs, defaultMaxStoredJobs, defaultJobTTL, defaultDeliveredTTL),
	}
}

func webAssetTag(static fs.FS, name string) string {
	b, err := fs.ReadFile(static, name)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}

func versionedHTML(static fs.FS, page string, assets map[string]string) []byte {
	b, err := fs.ReadFile(static, page)
	if err != nil {
		return nil
	}
	s := string(b)
	for path, tag := range assets {
		if tag == "" {
			continue
		}
		s = strings.ReplaceAll(s, `"`+path+`"`, `"`+path+`?v=`+tag+`"`)
	}
	return []byte(s)
}

func serveHTMLBytes(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
}

func (wb *web) handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFiles, "web")
	assetTags := map[string]string{
		"/signup.css": webAssetTag(static, "signup.css"),
		"/signup.js":  webAssetTag(static, "signup.js"),
		"/paid.js":    webAssetTag(static, "paid.js"),
	}
	indexHTML := versionedHTML(static, "index.html", assetTags)
	paidHTML := versionedHTML(static, "paid.html", assetTags)
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /{$}", serveHTMLBytes(indexHTML))
	mux.HandleFunc("GET /index.html", serveHTMLBytes(indexHTML))
	mux.HandleFunc("GET /paid.html", serveHTMLBytes(paidHTML))
	mux.HandleFunc("GET /api/status", wb.status)
	mux.HandleFunc("GET /api/check", wb.check)
	mux.HandleFunc("POST /api/create", wb.create)
	mux.HandleFunc("GET /api/job", wb.job)
	mux.HandleFunc("POST /api/waitlist", wb.waitlist)
	mux.HandleFunc("POST /api/waitlist/leave", wb.leaveWaitlist)
	mux.HandleFunc("POST /api/checkout", wb.checkout)
	mux.HandleFunc("POST /api/renew", wb.renew)
	mux.HandleFunc("POST /api/wake", wb.wake)
	mux.HandleFunc("POST /api/delete", wb.penDelete)
	mux.HandleFunc("POST /api/stripe/webhook", wb.stripeWebhook)
	mux.HandleFunc("GET /api/paid", wb.paid)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		csp := "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
		if wb.turnstile != nil {
			csp = "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
		}
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Origin-Agent-Cluster", "?1")
		p := r.URL.Path
		if p == "/" || strings.HasSuffix(p, ".html") || strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".css") {
			h.Set("Cache-Control", "no-store")
		}
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

func (wb *web) isWorkHost(r *http.Request) bool {
	return wb.workHost != "" && stripHostPort(r.Host) == wb.workHost
}

// requireSameOriginJSON blocks cross-site simple POSTs (CSRF) against endpoints
// that do not require a Turnstile token (such as /api/checkout and /api/waitlist/leave).
func (wb *web) requireSameOriginJSON(w http.ResponseWriter, r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
		jsonOut(w, 403, map[string]string{"error": "cross-origin request refused"})
		return false
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || stripHostPort(u.Host) != stripHostPort(r.Host) {
			jsonOut(w, 403, map[string]string{"error": "cross-origin request refused"})
			return false
		}
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		jsonOut(w, 415, map[string]string{"error": "Content-Type must be application/json"})
		return false
	}
	return true
}

func (wb *web) status(w http.ResponseWriter, r *http.Request) {
	if wb.statuses != nil && !wb.statuses.allow(rateLimitKey(wb.clientIP(r)), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "slow down a little"})
		return
	}
	code, out := wb.ask(r.Context(), "GET", "/capacity", nil)
	if code != 200 {
		jsonOut(w, code, out)
		return
	}
	res := map[string]any{"open": out["open"], "pens_domain": wb.domain, "sites_domain": wb.sitesDomain, "for_sale": wb.forSaleForRequest(r)}
	if wb.isWorkHost(r) {
		res["theme"] = "work"
	}
	if wb.turnstile != nil {
		res["turnstile_site_key"] = wb.turnstile.siteKey
	}
	jsonOut(w, 200, res)
}

func (wb *web) verifyTurnstile(w http.ResponseWriter, r *http.Request, token, ip string) bool {
	if wb.turnstile == nil {
		return true
	}
	err := wb.turnstile.verify(r.Context(), token, ip)
	if err == nil {
		return true
	}
	if err == errTurnstileDown {
		jsonOut(w, 503, map[string]string{"error": err.Error()})
		return false
	}
	jsonOut(w, 403, map[string]string{"error": err.Error()})
	return false
}

func (wb *web) check(w http.ResponseWriter, r *http.Request) {
	if !wb.checks.allow(rateLimitKey(wb.clientIP(r)), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "slow down a little"})
		return
	}
	pen := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("pen")))
	vanity := r.URL.Query().Get("vanity") == "1"
	if vanity {
		if why, ok := validPen(pen); !ok {
			jsonOut(w, 200, map[string]any{"free": false, "vanity": true, "reason": why})
			return
		}
		code, out := wb.ask(r.Context(), "GET", "/check?pen="+pen+"&vanity=1", nil)
		jsonOut(w, code, out)
		return
	}
	if why, ok := validPenPrefix(pen); !ok {
		jsonOut(w, 200, map[string]any{"free": false, "vanity": false, "reason": why})
		return
	}
	code, out := wb.ask(r.Context(), "GET", "/check?pen="+pen, nil)
	jsonOut(w, code, out)
}

func (wb *web) create(w http.ResponseWriter, r *http.Request) {
	if !wb.requireSameOriginJSON(w, r) {
		return
	}
	ip := wb.clientIP(r)
	if !wb.creates.allow(rateLimitKey(ip), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "too many tries from here; wait an hour"})
		return
	}
	var in struct {
		Code           string `json:"code"`
		Pen            string `json:"pen"`
		Handle         string `json:"handle"`
		Theme          string `json:"theme"`
		TurnstileToken string `json:"turnstile_token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	in.Pen = strings.ToLower(strings.TrimSpace(in.Pen))
	in.Handle = strings.ToLower(strings.TrimSpace(in.Handle))
	in.Code = normCode(in.Code)
	rawTheme := strings.TrimSpace(in.Theme)
	theme, ok := normaliseTheme(rawTheme)
	if !ok {
		jsonOut(w, 400, map[string]string{"error": "unknown theme"})
		return
	}
	if rawTheme == "" && wb.isWorkHost(r) {
		theme = "work"
	}
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
	if !wb.verifyTurnstile(w, r, in.TurnstileToken, ip) {
		return
	}
	brokerReq := map[string]string{"code": in.Code, "pen": in.Pen, "owner": in.Handle}
	if theme != "" {
		brokerReq["theme"] = theme
	}
	if wb.isWorkHost(r) {
		brokerReq["want_plan"] = planWork
	}
	code, out := wb.ask(r.Context(), "POST", "/validate", brokerReq)
	if code != 200 {
		jsonOut(w, code, out)
		return
	}
	// Raising a pen takes a minute or so. It runs as a job the page checks on,
	// so no single request has to survive that long (proxies and browsers drop
	// them) and a reload picks up where it left off. Deduplicate in-flight jobs
	// per code so one code cannot fill all open job slots.
	id, res := wb.jobs.startForCode(in.Code, func() (int, map[string]any) {
		ctx, cancel := context.WithTimeout(context.Background(), 16*time.Minute)
		defer cancel()
		code, out := wb.ask(ctx, "POST", "/provision", brokerReq)
		if code == 201 {
			if link, _ := out["join_link"].(string); link != "" {
				if svg, err := qrSVG(link); err == nil {
					out["join_qr_svg"] = svg
				}
			}
		}
		return code, out
	})
	switch res {
	case jobStartDup:
		jsonOut(w, 409, map[string]string{"error": "a sign-up with this code is already running"})
		return
	case jobStartBusy:
		jsonOut(w, 503, map[string]string{"error": "sign-up is busy right now; try again in a minute"})
		return
	}
	jsonOut(w, 202, map[string]string{"job": id})
}

// job reports on a sign-up: working, or its terminal result (re-readable for
// 5 minutes after first delivery within the 30-minute unread TTL, to whoever
// holds the job's id, which only the page that started it knows).
func (wb *web) job(w http.ResponseWriter, r *http.Request) {
	if !wb.jobPolls.allow(rateLimitKey(wb.clientIP(r)), time.Now()) {
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

type jobStartResult int

const (
	jobStartOK jobStartResult = iota
	jobStartBusy
	jobStartDup
)

type job struct {
	started   time.Time
	finished  time.Time
	delivered time.Time
	done      bool
	status    int
	out       map[string]any
	code      string
}

type jobStore struct {
	mu           sync.Mutex
	maxOpen      int
	maxStored    int
	ttl          time.Duration
	deliveredTTL time.Duration
	now          func() time.Time
	jobs         map[string]*job
	activeCodes  map[string]string
}

func newJobStore(maxOpen, maxStored int, ttl, deliveredTTL time.Duration) *jobStore {
	return &jobStore{
		maxOpen:      maxOpen,
		maxStored:    maxStored,
		ttl:          ttl,
		deliveredTTL: deliveredTTL,
		now:          time.Now,
		jobs:         map[string]*job{},
		activeCodes:  map[string]string{},
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
	id, res := s.startForCode("", run)
	return id, res == jobStartOK
}

func (s *jobStore) startForCode(code string, run func() (int, map[string]any)) (string, jobStartResult) {
	s.mu.Lock()
	if s.activeCodes == nil {
		s.activeCodes = map[string]string{}
	}
	if code != "" {
		if _, dup := s.activeCodes[code]; dup {
			s.mu.Unlock()
			return "", jobStartDup
		}
	}
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
		return "", jobStartBusy
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
			return "", jobStartBusy
		}
		delete(s.jobs, oldestID)
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	j := &job{started: now, code: code}
	s.jobs[id] = j
	if code != "" {
		s.activeCodes[code] = id
	}
	s.mu.Unlock()
	go func() {
		status, out := run()
		s.mu.Lock()
		j.done, j.finished, j.status, j.out = true, s.clock(), status, out
		if code != "" && s.activeCodes[code] == id {
			delete(s.activeCodes, code)
		}
		s.mu.Unlock()
	}()
	return id, jobStartOK
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

// clientIP returns the immediate peer IP set by Caddy (X-Forwarded-For),
// unwrapping CF-Connecting-IP only when the immediate peer is inside a
// configured trusted proxy CIDR (Cloudflare's edge ranges).
func (wb *web) clientIP(r *http.Request) string {
	peer := clientIP(r)
	if len(wb.trustedProxies) > 0 {
		if peerAddr, err := netip.ParseAddr(peer); err == nil && ipInPrefixes(peerAddr, wb.trustedProxies) {
			if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
				if a, err := netip.ParseAddr(cf); err == nil {
					return a.Unmap().String()
				}
			}
		}
	}
	return peer
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
	if !wb.requireSameOriginJSON(w, r) {
		return
	}
	now := time.Now()
	ip := wb.clientIP(r)
	if !wb.waits.allow(rateLimitKey(ip), now) {
		jsonOut(w, 429, map[string]string{"error": "too many tries right now; try again later"})
		return
	}
	var in struct {
		Email          string `json:"email"`
		Pen            string `json:"pen"`
		Note           string `json:"note"`
		TurnstileToken string `json:"turnstile_token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if !validEmail(in.Email) {
		jsonOut(w, 400, map[string]string{"error": "that doesn't look like an email address"})
		return
	}
	// Verify Turnstile before consuming the global waitlist quota so bots
	// cannot exhaust globalWaits and lock out legitimate visitors.
	if !wb.verifyTurnstile(w, r, in.TurnstileToken, ip) {
		return
	}
	if !wb.globalWaits.allow("*", now) {
		jsonOut(w, 429, map[string]string{"error": "too many tries right now; try again later"})
		return
	}
	reqBody := map[string]string{
		"email": in.Email,
		"pen":   strings.ToLower(strings.TrimSpace(in.Pen)),
		"note":  cleanField(in.Note, 280),
	}
	if wb.isWorkHost(r) {
		reqBody["theme"] = "work"
	}
	code, out := wb.ask(r.Context(), "POST", "/waitlist", reqBody)
	// L2: strip the "already" membership oracle from the public response so
	// callers cannot probe whether a third party's email is on the waiting list.
	if code == 200 {
		delete(out, "already")
	}
	jsonOut(w, code, out)
}

func (wb *web) leaveWaitlist(w http.ResponseWriter, r *http.Request) {
	if !wb.requireSameOriginJSON(w, r) {
		return
	}
	ip := wb.clientIP(r)
	if !wb.leaves.allow(rateLimitKey(ip), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "too many tries from here; wait an hour"})
		return
	}
	var in struct {
		Email          string `json:"email"`
		TurnstileToken string `json:"turnstile_token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if !validEmail(in.Email) {
		jsonOut(w, 400, map[string]string{"error": "that doesn't look like an email address"})
		return
	}
	if !wb.verifyTurnstile(w, r, in.TurnstileToken, ip) {
		return
	}
	code, out := wb.ask(r.Context(), "POST", "/waitlist/leave", map[string]string{"email": in.Email})
	jsonOut(w, code, out)
}

const uniformWakeMessage = "If this pen is asleep and eligible to wake, it will open for renewal for 10 minutes once its certificate is ready (usually 1–2 minutes). Open your pen's home page from a joined owner or admin device to renew. If it does not open after a few minutes — or if daily wake limits or host capacity were reached — contact your host operator."

// wake handles public sleeping-pen renewal wake requests (I-7 Part 2).
// Protected by same-origin JSON check, per-IP rate limit (5/hr), and Turnstile.
// Answers 202 immediately with a uniform message and performs the wake
// asynchronously in the broker so responses reveal nothing about pen existence,
// state, plan, dates, or caps.
func (wb *web) wake(w http.ResponseWriter, r *http.Request) {
	if !wb.requireSameOriginJSON(w, r) {
		return
	}
	ip := wb.clientIP(r)
	if wb.wakes != nil && !wb.wakes.allow(rateLimitKey(ip), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "too many wake attempts from here; try again in an hour or contact your host operator"})
		return
	}
	var in struct {
		Pen            string `json:"pen"`
		TurnstileToken string `json:"turnstile_token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	pen := strings.ToLower(strings.TrimSpace(in.Pen))
	if why, ok := validPen(pen); !ok {
		jsonOut(w, 400, map[string]string{"error": why})
		return
	}
	if !wb.verifyTurnstile(w, r, in.TurnstileToken, ip) {
		return
	}
	code, _ := wb.ask(r.Context(), "POST", "/lifecycle/wake", map[string]string{"pen": pen})
	if code >= 500 {
		jsonOut(w, 502, map[string]string{"error": "the wake service is temporarily unavailable; try again or contact your host operator"})
		return
	}
	jsonOut(w, 202, map[string]any{"ok": true, "message": uniformWakeMessage})
}
