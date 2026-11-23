package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// broker raises pens. One at a time: a small server should not build two
// pens at once, and it makes a sign-up code impossible to use twice.
type broker struct {
	home        string // HOGMAN_HOME
	tool        string // hogman-host
	token       string
	ntfy        string // optional: ntfy topic URL for the operator's pushes
	mu          sync.Mutex
	limitMu     sync.Mutex
	waitJoins   *limiter
	waitNotify  *limiter
	raiseNotify *limiter
	ntfySem     chan struct{}
	suffixFn    func() (string, error) // nil uses randomPenSuffix (tests override)
}

func (b *broker) nextSuffix() (string, error) {
	if b.suffixFn != nil {
		return b.suffixFn()
	}
	return randomPenSuffix()
}

func runBroker() {
	b := &broker{
		home:  env("HOGMAN_HOME", "/opt/hogman"),
		tool:  env("HOGMAN_HOST_TOOL", "hogman-host"),
		token: readToken(),
		ntfy:  env("NTFY_URL", ""),
	}
	addr := env("BROKER_ADDR", ":9090")
	log.Printf("broker on %s", addr)
	srv := &http.Server{Addr: addr, Handler: b.handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func (b *broker) ensureLimits() {
	b.limitMu.Lock()
	defer b.limitMu.Unlock()
	if b.waitJoins == nil {
		b.waitJoins = newLimiterWithCap(30, time.Hour, 4)
	}
	if b.waitNotify == nil {
		b.waitNotify = newLimiterWithCap(10, time.Hour, 4)
	}
	if b.raiseNotify == nil {
		b.raiseNotify = newLimiterWithCap(20, time.Hour, 4)
	}
	if b.ntfySem == nil {
		b.ntfySem = make(chan struct{}, 4)
	}
}

func (b *broker) allowWaitlistJoin(now time.Time) bool {
	b.ensureLimits()
	return b.waitJoins.allow("*", now)
}

func (b *broker) notifyLimiter(kind string) *limiter {
	b.ensureLimits()
	if kind == "waitlist" {
		return b.waitNotify
	}
	return b.raiseNotify
}

func (b *broker) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /capacity", b.capacity)
	mux.HandleFunc("GET /check", b.check)
	mux.HandleFunc("POST /validate", b.validate)
	mux.HandleFunc("POST /provision", b.provision)
	mux.HandleFunc("POST /waitlist", b.waitlist)
	mux.HandleFunc("POST /waitlist/leave", b.leaveWaitlist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(b.token)) != 1 {
			jsonOut(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

type capacity struct {
	Pens int  `json:"pens"`
	Max  int  `json:"max"`
	Open bool `json:"open"`
}

func (b *broker) run(ctx context.Context, args ...string) (stdout []byte, code int, stderr string) {
	cmd := exec.CommandContext(ctx, b.tool, args...)
	cmd.Env = append(os.Environ(), "HOGMAN_HOME="+b.home)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code = 0
	if err != nil {
		code = -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
	}
	return out.Bytes(), code, errb.String()
}

func (b *broker) readCapacity(ctx context.Context) (*capacity, error) {
	out, code, stderr := b.run(ctx, "capacity")
	if code != 0 {
		return nil, fmt.Errorf("capacity: exit %d: %s", code, lastLine(stderr))
	}
	var c capacity
	if err := json.Unmarshal(out, &c); err != nil {
		return nil, fmt.Errorf("capacity: %v", err)
	}
	return &c, nil
}

func (b *broker) capacity(w http.ResponseWriter, r *http.Request) {
	c, err := b.readCapacity(r.Context())
	if err != nil {
		log.Print(err)
		jsonOut(w, 500, map[string]string{"error": "internal error"})
		return
	}
	jsonOut(w, 200, c)
}

// taken: a pen here has the name, or (public pens) it was ever used (D-21).
// hogman-host name-free answers 0 free, 2 taken; anything else counts as
// taken, so a name is never offered when we can't tell.
func (b *broker) taken(ctx context.Context, pen string) bool {
	if _, err := os.Stat(filepath.Join(b.home, "pens", pen)); err == nil {
		return true
	}
	_, code, stderr := b.run(ctx, "name-free", pen)
	if code != 0 && code != 2 {
		log.Printf("name-free %s: exit %d: %s", pen, code, lastLine(stderr))
	}
	return code != 0
}

func (b *broker) check(w http.ResponseWriter, r *http.Request) {
	pen := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("pen")))
	vanity := r.URL.Query().Get("vanity") == "1"
	if !vanity {
		if why, ok := validPenPrefix(pen); !ok {
			jsonOut(w, 200, map[string]any{"free": false, "vanity": false, "reason": why})
			return
		}
		jsonOut(w, 200, map[string]any{"free": true, "vanity": false})
		return
	}
	if why, ok := validPen(pen); !ok {
		jsonOut(w, 200, map[string]any{"free": false, "vanity": true, "reason": why})
		return
	}
	if b.taken(r.Context(), pen) {
		jsonOut(w, 200, map[string]any{"free": false, "vanity": true, "reason": "that name is taken"})
		return
	}
	jsonOut(w, 200, map[string]any{"free": true, "vanity": true})
}

type signupInput struct {
	Code  string `json:"code"`
	Pen   string `json:"pen"`
	Owner string `json:"owner"`
}

func decodeSignupInput(w http.ResponseWriter, r *http.Request) (signupInput, bool) {
	var in signupInput
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return signupInput{}, false
	}
	in.Code = normCode(in.Code)
	in.Pen = strings.ToLower(strings.TrimSpace(in.Pen))
	in.Owner = strings.ToLower(strings.TrimSpace(in.Owner))
	if why, ok := validPen(in.Pen); !ok {
		jsonOut(w, 400, map[string]string{"error": "pen name: " + why})
		return signupInput{}, false
	}
	if why, ok := validHandle(in.Owner); !ok {
		jsonOut(w, 400, map[string]string{"error": "your name: " + why})
		return signupInput{}, false
	}
	if !codeRE.MatchString(in.Code) {
		jsonOut(w, 403, map[string]string{"error": "that sign-up code isn't right"})
		return signupInput{}, false
	}
	return in, true
}

// validate checks code, pen availability, and capacity synchronously before
// queueing a background provision job.
func (b *broker) validate(w http.ResponseWriter, r *http.Request) {
	in, valid := decodeSignupInput(w, r)
	if !valid {
		return
	}
	rawNote, ok, err := b.findCode(in.Code)
	if err != nil {
		log.Print(err)
		jsonOut(w, 500, map[string]string{"error": "internal error"})
		return
	}
	if !ok {
		jsonOut(w, 403, map[string]string{"error": "that sign-up code isn't right, or it was already used"})
		return
	}
	vanity, _ := parseCodeMeta(rawNote)
	if vanity {
		if b.taken(r.Context(), in.Pen) {
			jsonOut(w, 409, map[string]string{"error": "that name is taken"})
			return
		}
	} else {
		if why, ok := validPenPrefix(in.Pen); !ok {
			jsonOut(w, 400, map[string]string{"error": "pen name: " + why})
			return
		}
	}
	cap, err := b.readCapacity(r.Context())
	if err != nil {
		log.Print(err)
		jsonOut(w, 500, map[string]string{"error": "internal error"})
		return
	}
	if !cap.Open {
		jsonOut(w, 503, map[string]string{"error": "this server is full right now"})
		return
	}
	jsonOut(w, 200, map[string]any{"ok": true, "vanity": vanity})
}

func (b *broker) pickSuffixedPen(ctx context.Context, prefix string) (string, error) {
	const maxTries = 16
	for i := 0; i < maxTries; i++ {
		sfx, err := b.nextSuffix()
		if err != nil {
			return "", err
		}
		cand := prefix + "-" + sfx
		if !b.taken(ctx, cand) {
			return cand, nil
		}
	}
	return "", errors.New("could not pick a free ending; try again")
}

func (b *broker) provision(w http.ResponseWriter, r *http.Request) {
	in, valid := decodeSignupInput(w, r)
	if !valid {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	rawNote, ok, err := b.findCode(in.Code)
	if err != nil {
		log.Print(err)
		jsonOut(w, 500, map[string]string{"error": "internal error"})
		return
	}
	if !ok {
		jsonOut(w, 403, map[string]string{"error": "that sign-up code isn't right, or it was already used"})
		return
	}
	vanity, note := parseCodeMeta(rawNote)
	targetPen := in.Pen
	if vanity {
		if b.taken(r.Context(), targetPen) {
			jsonOut(w, 409, map[string]string{"error": "that name is taken"})
			return
		}
	} else {
		if why, ok := validPenPrefix(in.Pen); !ok {
			jsonOut(w, 400, map[string]string{"error": "pen name: " + why})
			return
		}
		targetPen, err = b.pickSuffixedPen(r.Context(), in.Pen)
		if err != nil {
			log.Printf("pickSuffixedPen %s: %v", in.Pen, err)
			jsonOut(w, 500, map[string]string{"error": "could not pick a free ending; try again"})
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	start := time.Now()
	out, code, stderr := b.run(ctx, "provision", targetPen, in.Owner)
	switch code {
	case 0:
	case 2:
		if vanity {
			jsonOut(w, 409, map[string]string{"error": "that name is taken"})
		} else {
			jsonOut(w, 409, map[string]string{"error": "that name was just taken; try again"})
		}
		return
	case 3:
		jsonOut(w, 503, map[string]string{"error": "this server is full right now"})
		return
	default:
		log.Printf("provision %s for %s failed (exit %d): %s", targetPen, in.Owner, code, strings.TrimSpace(stderr))
		if vanity {
			jsonOut(w, 500, map[string]string{"error": "raising your pen failed. Your code still works — pick another pen name and try again."})
		} else {
			jsonOut(w, 500, map[string]string{"error": "raising your pen failed. Your code still works — try again."})
		}
		return
	}
	var res map[string]string
	if err := json.Unmarshal(lastJSONLine(out), &res); err != nil || res["join_link"] == "" {
		log.Printf("provision %s: unreadable result %q", targetPen, out)
		jsonOut(w, 500, map[string]string{"error": "internal error"})
		return
	}
	if err := b.useCode(in.Code); err != nil {
		log.Printf("could not mark code used: %v", err) // the pen exists; say so anyway
	}
	if err := b.dropInvited(in.Code); err != nil {
		log.Printf("could not clear the waiting list entry: %v", err)
	}
	tag := ""
	if vanity {
		tag = " [vanity]"
	}
	b.ledger(fmt.Sprintf("%s raised %s for %s with %s (%s)%s in %s",
		time.Now().UTC().Format(time.RFC3339), targetPen, in.Owner, in.Code, note, tag, time.Since(start).Round(time.Second)))
	b.notifyKind("raised", fmt.Sprintf("New pen raised: %s", res["zone"]))
	jsonOut(w, 201, res)
}

// --- sign-up codes: $HOGMAN_HOME/signup/codes, one "CODE note" per line ---

func (b *broker) codesPath() string { return filepath.Join(b.home, "signup", "codes") }

func (b *broker) lockCodes() (func(), error) { return b.lock(b.codesPath() + ".lock") }

// lock takes an exclusive flock on path; hogman-host takes the same locks.
func (b *broker) lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func (b *broker) findCode(code string) (note string, ok bool, err error) {
	unlock, err := b.lockCodes()
	if err != nil {
		return "", false, err
	}
	defer unlock()
	f, err := os.Open(b.codesPath())
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		c, n, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			return n, true, nil
		}
	}
	return "", false, sc.Err()
}

func (b *broker) useCode(code string) error {
	unlock, err := b.lockCodes()
	if err != nil {
		return err
	}
	defer unlock()
	data, err := os.ReadFile(b.codesPath())
	if err != nil {
		return err
	}
	var keep []string
	for _, line := range strings.Split(string(data), "\n") {
		if c, _, _ := strings.Cut(strings.TrimSpace(line), " "); c != "" && c != code {
			keep = append(keep, line)
		}
	}
	tmp := b.codesPath() + ".new"
	out := strings.Join(keep, "\n")
	if out != "" {
		out += "\n"
	}
	if err := os.WriteFile(tmp, []byte(out), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.codesPath())
}

func (b *broker) ledger(line string) {
	f, err := os.OpenFile(filepath.Join(b.home, "signup", "raised.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Print(err)
		return
	}
	defer f.Close()
	fmt.Fprintln(f, line)
	log.Print(line)
}

// --- helpers ---

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func lastJSONLine(b []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		if l := bytes.TrimSpace(lines[i]); len(l) > 0 && l[0] == '{' {
			return l
		}
	}
	return nil
}
