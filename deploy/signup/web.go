package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"
)

//go:embed web
var webFiles embed.FS

type web struct {
	brokerURL string
	token     string
	domain    string
	client    *http.Client
	checks    *limiter // name checks while typing
	creates   *limiter // sign-up attempts, which also bounds guessing codes
}

func runWeb() {
	wb := newWeb(env("BROKER_URL", "http://broker:9090"), readToken(), env("PENS_DOMAIN", ""))
	addr := env("LISTEN", ":8080")
	log.Printf("sign-up page on %s", addr)
	srv := &http.Server{Addr: addr, Handler: wb.handler(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func newWeb(brokerURL, token, domain string) *web {
	return &web{
		brokerURL: strings.TrimRight(brokerURL, "/"), token: token, domain: domain,
		client:  &http.Client{Timeout: 16 * time.Minute},
		checks:  newLimiter(60, time.Minute),
		creates: newLimiter(5, time.Hour),
	}
}

func (wb *web) handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFiles, "web")
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/status", wb.status)
	mux.HandleFunc("GET /api/check", wb.check)
	mux.HandleFunc("POST /api/create", wb.create)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
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
	if !wb.checks.allow(clientIP(r), time.Now()) {
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
	if !wb.creates.allow(clientIP(r), time.Now()) {
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
	// Raising a pen takes a minute or two; finish it even if the browser goes away.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 16*time.Minute)
	defer cancel()
	code, out := wb.ask(ctx, "POST", "/provision", map[string]string{"code": in.Code, "pen": in.Pen, "owner": in.Handle})
	if code == 201 {
		if link, _ := out["join_link"].(string); link != "" {
			if svg, err := qrSVG(link); err == nil {
				out["join_qr_svg"] = svg
			}
		}
	}
	jsonOut(w, code, out)
}

// clientIP: the front door sets X-Forwarded-For to the real client, and is
// the only thing that can reach this page.
func clientIP(r *http.Request) string {
	if x := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); x != "" {
		parts := strings.Split(x, ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
			return ip.String()
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

type limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	seen   map[string][]time.Time
}

func newLimiter(limit int, window time.Duration) *limiter {
	return &limiter{limit: limit, window: window, seen: map[string][]time.Time{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seen) > 4096 {
		l.seen = map[string][]time.Time{}
	}
	keep := l.seen[key][:0]
	for _, t := range l.seen[key] {
		if now.Sub(t) < l.window {
			keep = append(keep, t)
		}
	}
	if len(keep) >= l.limit {
		l.seen[key] = keep
		return false
	}
	l.seen[key] = append(keep, now)
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
