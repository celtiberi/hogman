package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "0123456789abcdef0123456789abcdef"

// fakeHost stands in for hogman-host: capacity from $FAKE_MAX, and provision
// makes the pen's folder unless the pen is called "explode".
const fakeHost = `#!/bin/sh
case "$1" in
  capacity) n=$(ls "$HOGMAN_HOME/pens" | wc -l); echo "{\"pens\":$n,\"max\":${FAKE_MAX:-3},\"open\":$([ $n -lt ${FAKE_MAX:-3} ] && echo true || echo false)}" ;;
  provision)
    [ "$2" = explode ] && { echo boom >&2; exit 1; }
    [ -e "$HOGMAN_HOME/pens/$2" ] && exit 2
    [ $(ls "$HOGMAN_HOME/pens" | wc -l) -ge ${FAKE_MAX:-3} ] && exit 3
    mkdir "$HOGMAN_HOME/pens/$2"
    echo "==> lots of progress" >&2
    echo "{\"pen\":\"$2\",\"zone\":\"$2.hogman\",\"host\":\"$2.pens.test\",\"owner\":\"$3\",\"join_link\":\"https://$2.pens.test/join#k=abc&fp=AA\",\"valid_until\":\"x\"}" ;;
  *) exit 9 ;;
esac
`

func newTestBroker(t *testing.T, codes string) (*broker, string) {
	t.Helper()
	home := t.TempDir()
	for _, d := range []string{"pens", "signup"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tool := filepath.Join(t.TempDir(), "hogman-host")
	if err := os.WriteFile(tool, []byte(fakeHost), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "signup", "codes"), []byte(codes), 0o600); err != nil {
		t.Fatal(err)
	}
	return &broker{home: home, tool: tool, token: testToken}, home
}

func call(h http.Handler, method, path, body string, hdr map[string]string) (int, map[string]any) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

var auth = map[string]string{"Authorization": "Bearer " + testToken}

func TestBrokerNeedsToken(t *testing.T) {
	b, _ := newTestBroker(t, "")
	if code, _ := call(b.handler(), "GET", "/capacity", "", nil); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := call(b.handler(), "GET", "/capacity", "", map[string]string{"Authorization": "Bearer nope"}); code != 401 {
		t.Fatalf("wrong token: %d", code)
	}
	if code, out := call(b.handler(), "GET", "/capacity", "", auth); code != 200 || out["open"] != true {
		t.Fatalf("capacity: %d %v", code, out)
	}
}

func TestBrokerProvisionUsesCodeOnce(t *testing.T) {
	b, home := newTestBroker(t, "PIG-AAAA-BBBB for alice\nPIG-CCCC-DDDD other\n")
	h := b.handler()
	body := func(code, pen, owner string) string {
		j, _ := json.Marshal(map[string]string{"code": code, "pen": pen, "owner": owner})
		return string(j)
	}
	if code, out := call(h, "POST", "/provision", body("PIG-ZZZZ-ZZZZ", "smith", "alice"), auth); code != 403 {
		t.Fatalf("unknown code: %d %v", code, out)
	}
	code, out := call(h, "POST", "/provision", body("pig-aaaa-bbbb", "smith", "alice"), auth)
	if code != 201 || out["zone"] != "smith.hogman" || !strings.Contains(out["join_link"].(string), "#k=") {
		t.Fatalf("provision: %d %v", code, out)
	}
	if code, _ := call(h, "POST", "/provision", body("PIG-AAAA-BBBB", "jones", "alice"), auth); code != 403 {
		t.Fatalf("a used code worked again: %d", code)
	}
	codes, _ := os.ReadFile(filepath.Join(home, "signup", "codes"))
	if strings.Contains(string(codes), "AAAA") || !strings.Contains(string(codes), "PIG-CCCC-DDDD other") {
		t.Fatalf("codes file after use: %q", codes)
	}
	if code, _ := call(h, "POST", "/provision", body("PIG-CCCC-DDDD", "smith", "bob"), auth); code != 409 {
		t.Fatalf("a taken name: %d", code)
	}
	ledger, _ := os.ReadFile(filepath.Join(home, "signup", "raised.log"))
	if !strings.Contains(string(ledger), "raised smith for alice with PIG-AAAA-BBBB (for alice)") {
		t.Fatalf("ledger: %q", ledger)
	}
}

func TestBrokerFailureKeepsCode(t *testing.T) {
	b, home := newTestBroker(t, "PIG-AAAA-BBBB x\n")
	j := `{"code":"PIG-AAAA-BBBB","pen":"explode","owner":"alice"}`
	if code, _ := call(b.handler(), "POST", "/provision", j, auth); code != 500 {
		t.Fatalf("a failed provision: %d", code)
	}
	codes, _ := os.ReadFile(filepath.Join(home, "signup", "codes"))
	if !strings.Contains(string(codes), "PIG-AAAA-BBBB") {
		t.Fatal("a failed sign-up used up the code")
	}
}

func TestBrokerFull(t *testing.T) {
	b, _ := newTestBroker(t, "PIG-AAAA-BBBB x\n")
	t.Setenv("FAKE_MAX", "0")
	if code, _ := call(b.handler(), "POST", "/provision", `{"code":"PIG-AAAA-BBBB","pen":"smith","owner":"alice"}`, auth); code != 503 {
		t.Fatalf("a full server: %d", code)
	}
}

func TestBrokerRefusesBadInput(t *testing.T) {
	b, home := newTestBroker(t, "PIG-AAAA-BBBB x\n")
	for _, j := range []string{
		`{"code":"PIG-AAAA-BBBB","pen":"../front","owner":"alice"}`,
		`{"code":"PIG-AAAA-BBBB","pen":"www","owner":"alice"}`,
		`{"code":"PIG-AAAA-BBBB","pen":"smith","owner":"Alice; rm -rf /"}`,
		`{"code":"PIG-AAAA-BBBB","pen":"smith","owner":"alice","extra":1}`,
		`{"code":"PIG-AAAA-BBBB","pen":"a","owner":"alice"}`,
	} {
		if code, _ := call(b.handler(), "POST", "/provision", j, auth); code != 400 {
			t.Fatalf("%s: %d", j, code)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(home, "pens")); len(entries) != 0 {
		t.Fatalf("a pen was made from bad input: %v", entries)
	}
}

func TestWebForwardsAndDrawsQR(t *testing.T) {
	b, _ := newTestBroker(t, "PIG-AAAA-BBBB x\n")
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	wb := newWeb(srv.URL, testToken, "pens.test")
	h := wb.handler()

	if code, out := call(h, "GET", "/api/status", "", nil); code != 200 || out["open"] != true || out["pens_domain"] != "pens.test" {
		t.Fatalf("status: %d %v", code, out)
	}
	if code, out := call(h, "GET", "/api/check?pen=Smith", "", nil); code != 200 || out["free"] != true {
		t.Fatalf("check: %d %v", code, out)
	}
	if _, out := call(h, "GET", "/api/check?pen=x", "", nil); out["free"] != false {
		t.Fatalf("a one-letter name is free? %v", out)
	}
	code, out := call(h, "POST", "/api/create", `{"code":" pig-aaaa-bbbb ","pen":"Smith","handle":"Alice"}`, map[string]string{"Content-Type": "application/json"})
	id, _ := out["job"].(string)
	if code != 202 || len(id) != 32 {
		t.Fatalf("create: %d %v", code, out)
	}
	var res map[string]any
	for i := 0; i < 100; i++ {
		_, j := call(h, "GET", "/api/job?id="+id, "", nil)
		if j["state"] == "done" {
			res, _ = j["result"].(map[string]any)
			break
		}
		if j["state"] != "working" {
			t.Fatalf("job: %v", j)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if res == nil || res["owner"] != "alice" || !strings.HasPrefix(res["join_qr_svg"].(string), "<svg") {
		t.Fatalf("job result: %v", res)
	}
	// Completed results stay re-readable during the post-delivery grace window.
	code, again := call(h, "GET", "/api/job?id="+id, "", nil)
	againRes, _ := again["result"].(map[string]any)
	if code != 200 || again["state"] != "done" || againRes == nil || againRes["join_qr_svg"] != res["join_qr_svg"] {
		t.Fatalf("second read of completed job: %d %v, want 200 done with matching QR", code, again)
	}
	if code, _ := call(h, "GET", "/api/job?id=nope", "", nil); code != 404 {
		t.Fatalf("an unknown job: %d", code)
	}
	// A wrong code is refused synchronously before creating a job.
	code, out = call(h, "POST", "/api/create", `{"code":"PIG-ZZZZ-ZZZZ","pen":"jones","handle":"bob"}`, map[string]string{"Content-Type": "application/json"})
	if code != 403 || out["job"] != nil {
		t.Fatalf("wrong code: %d %v, want 403 without job", code, out)
	}
	if _, out := call(h, "GET", "/api/check?pen=smith", "", nil); out["free"] != false {
		t.Fatalf("smith still free after it was raised: %v", out)
	}
}

func TestWebPageAndHeaders(t *testing.T) {
	h := newWeb("http://127.0.0.1:1", testToken, "pens.test").handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "Get a pen") {
		t.Fatalf("page: %d", rec.Code)
	}
	for _, want := range []string{
		`id="done-home"`,
		`treat it like a password`,
		`Network name (your pen)`,
		`Your personal name in it`,
		`Back up your keeper access`,
		`only way back in`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("page missing %q", want)
		}
	}
	if strings.Contains(body, `class="penname">smith<`) {
		t.Fatal("page still uses smith in field suffix")
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("CSP: %q", csp)
	}
	if code, _ := call(h, "GET", "/api/status", "", nil); code != 502 {
		t.Fatalf("broker down should be 502, got %d", code)
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(2, time.Minute)
	now := time.Now()
	if !l.allow("a", now) || !l.allow("a", now) || l.allow("a", now) {
		t.Fatal("limit of 2 not kept")
	}
	if !l.allow("b", now) {
		t.Fatal("limits are per client")
	}
	if !l.allow("a", now.Add(61*time.Second)) {
		t.Fatal("the window should pass")
	}
}

func TestWaitlist(t *testing.T) {
	b, home := newTestBroker(t, "")
	h := b.handler()
	join := func(j string) (int, map[string]any) { return call(h, "POST", "/waitlist", j, auth) }

	code, out := join(`{"email":"Alice@Example.com","pen":"smith","note":"for my band\tand\nfriends"}`)
	if code != 200 || out["place"] != float64(1) || out["already"] != false {
		t.Fatalf("join: %d %v", code, out)
	}
	if code, out := join(`{"email":"alice@example.com"}`); code != 200 || out["already"] != true {
		t.Fatalf("a second join should be recognised: %d %v", code, out)
	}
	if code, out := join(`{"email":"bob@example.org"}`); code != 200 || out["place"] != float64(2) {
		t.Fatalf("bob: %d %v", code, out)
	}
	for _, bad := range []string{
		`{"email":"not-an-email"}`,
		`{"email":"a@b"}`,
		`{"email":"x\"y@example.com"}`,
		`{"email":"ok@example.com","pen":"www"}`,
		`{"email":"ok@example.com","extra":1}`,
	} {
		if code, _ := join(bad); code != 400 {
			t.Fatalf("%s: %d, want 400", bad, code)
		}
	}
	data, _ := os.ReadFile(filepath.Join(home, "signup", "waitlist"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("waitlist file: %q", data)
	}
	f := strings.Split(lines[0], "\t")
	if len(f) != 6 || f[0] != "1" || f[2] != "waiting" || f[3] != "alice@example.com" || f[4] != "smith" || f[5] != "for my band and friends" {
		t.Fatalf("first entry: %q", f)
	}
}

func TestWaitlistThroughThePage(t *testing.T) {
	b, _ := newTestBroker(t, "")
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	h := newWeb(srv.URL, testToken, "pens.test").handler()
	js := map[string]string{"Content-Type": "application/json"}
	if code, out := call(h, "POST", "/api/waitlist", `{"email":" Carol@Example.com ","pen":"","note":"hi"}`, js); code != 200 || out["place"] != float64(1) {
		t.Fatalf("join through the page: %d %v", code, out)
	}
	if code, _ := call(h, "POST", "/api/waitlist", `{"email":"nope"}`, js); code != 400 {
		t.Fatalf("bad email through the page: %d", code)
	}
}

func TestSignupClearsWaitlistEntry(t *testing.T) {
	b, home := newTestBroker(t, "PIG-AAAA-BBBB waitlist #1\n")
	w := filepath.Join(home, "signup", "waitlist")
	os.WriteFile(w, []byte("1\tt\tinvited PIG-AAAA-BBBB\tdan@example.com\t\t\n2\tt\twaiting\terin@example.com\t\t\n"), 0o600)
	if code, out := call(b.handler(), "POST", "/provision", `{"code":"PIG-AAAA-BBBB","pen":"dans","owner":"dan"}`, auth); code != 201 {
		t.Fatalf("provision: %d %v", code, out)
	}
	data, _ := os.ReadFile(w)
	if strings.Contains(string(data), "dan@example.com") || !strings.Contains(string(data), "erin@example.com") {
		t.Fatalf("after dan signed up, the waiting list is %q", data)
	}
}

func TestWaitlistLeave(t *testing.T) {
	b, home := newTestBroker(t, "")
	h := b.handler()
	call(h, "POST", "/waitlist", `{"email":"a@example.com"}`, auth)
	call(h, "POST", "/waitlist", `{"email":"b@example.com"}`, auth)
	for _, e := range []string{`{"email":"A@example.com"}`, `{"email":"nobody@example.com"}`} {
		if code, out := call(h, "POST", "/waitlist/leave", e, auth); code != 200 || out["ok"] != true {
			t.Fatalf("leave %s: %d %v", e, code, out)
		}
	}
	data, _ := os.ReadFile(filepath.Join(home, "signup", "waitlist"))
	if strings.Contains(string(data), "a@example.com") || !strings.Contains(string(data), "b@example.com") {
		t.Fatalf("after a left: %q", data)
	}
}

func TestLimiterIPv6AndEvictOldest(t *testing.T) {
	if a, b := rateLimitKey("2001:db8:1:2::10"), rateLimitKey("2001:db8:1:2:abcd::99"); a != b {
		t.Fatalf("same /64 should share bucket: %q != %q", a, b)
	}
	if a, b := rateLimitKey("2001:db8:1:2::10"), rateLimitKey("2001:db8:1:3::10"); a == b {
		t.Fatalf("different /64 should differ: %q == %q", a, b)
	}
	if a, b := rateLimitKey("::ffff:203.0.113.5"), rateLimitKey("203.0.113.5"); a != b {
		t.Fatalf("v4-mapped IPv6 should match IPv4: %q != %q", a, b)
	}

	l := newLimiterWithCap(2, time.Minute, 3)
	t0 := time.Now()
	if !l.allow("abuser", t0) || !l.allow("abuser", t0.Add(time.Second)) || l.allow("abuser", t0.Add(2*time.Second)) {
		t.Fatal("abuser should hit limit at 2")
	}
	if !l.allow("idle", t0.Add(3*time.Second)) {
		t.Fatal("idle should be allowed")
	}
	if !l.allow("recent", t0.Add(4*time.Second)) {
		t.Fatal("recent should be allowed")
	}
	// Touch abuser so "idle" is the oldest-seen key when a 4th key arrives.
	if l.allow("abuser", t0.Add(5*time.Second)) {
		t.Fatal("abuser should still be blocked")
	}
	if !l.allow("newcomer", t0.Add(6*time.Second)) {
		t.Fatal("newcomer should be allowed")
	}
	if len(l.seen) > 3 {
		t.Fatalf("limiter grew past cap: %d", len(l.seen))
	}
	if l.allow("abuser", t0.Add(7*time.Second)) {
		t.Fatal("active abuser must not be flushed by key churn")
	}
}

func TestWebCreateValidatesCodeAndCapsJobs(t *testing.T) {
	b, _ := newTestBroker(t, "PIG-AAAA-BBBB x\n")
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	wb := newWeb(srv.URL, testToken, "pens.test")
	h := wb.handler()
	js := map[string]string{"Content-Type": "application/json"}

	// Wrong code, full capacity, and taken pen fail synchronously with zero jobs created.
	if code, _ := call(h, "POST", "/api/create", `{"code":"PIG-ZZZZ-ZZZZ","pen":"smith","handle":"alice"}`, js); code != 403 {
		t.Fatalf("bad code status = %d, want 403", code)
	}
	t.Setenv("FAKE_MAX", "0")
	if code, _ := call(h, "POST", "/api/create", `{"code":"PIG-AAAA-BBBB","pen":"smith","handle":"alice"}`, js); code != 503 {
		t.Fatalf("full server status = %d, want 503", code)
	}
	t.Setenv("FAKE_MAX", "3")
	if len(wb.jobs.jobs) != 0 {
		t.Fatalf("synchronous failures created %d jobs, want 0", len(wb.jobs.jobs))
	}

	// Open job cap: mock broker validates synchronously and blocks provision on a gate.
	gate := make(chan struct{})
	gateClosed := false
	defer func() {
		if !gateClosed {
			close(gate)
		}
	}()
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/validate":
			jsonOut(w, 200, map[string]bool{"ok": true})
		case "/provision":
			<-gate
			jsonOut(w, 500, map[string]string{"error": "boom"})
		default:
			jsonOut(w, 404, map[string]string{"error": "nope"})
		}
	}))
	defer mock.Close()

	wb2 := newWeb(mock.URL, testToken, "pens.test")
	h2 := wb2.handler()
	var ids []string
	for i := 1; i <= defaultMaxOpenJobs; i++ {
		code, out := call(h2, "POST", "/api/create", `{"code":"PIG-AAAA-BBBB","pen":"pen`+strconv.Itoa(i)+`","handle":"alice"}`, map[string]string{
			"Content-Type": "application/json", "X-Forwarded-For": "198.51.100." + strconv.Itoa(i),
		})
		if code != 202 {
			t.Fatalf("job %d create = %d %v, want 202", i, code, out)
		}
		ids = append(ids, out["job"].(string))
	}
	if code, _ := call(h2, "POST", "/api/create", `{"code":"PIG-AAAA-BBBB","pen":"extra","handle":"alice"}`, map[string]string{
		"Content-Type": "application/json", "X-Forwarded-For": "198.51.100.99",
	}); code != 503 {
		t.Fatalf("over open-job cap status = %d, want 503", code)
	}

	close(gate)
	gateClosed = true
	// Failed terminal job stays re-readable within the post-delivery window.
	var gotFailed bool
	for i := 0; i < 100; i++ {
		code, j := call(h2, "GET", "/api/job?id="+ids[0], "", nil)
		if code == 200 && j["state"] == "failed" {
			gotFailed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !gotFailed {
		t.Fatal("did not observe failed state for blocked job")
	}
	if code, j := call(h2, "GET", "/api/job?id="+ids[0], "", nil); code != 200 || j["state"] != "failed" {
		t.Fatalf("second read after failure = %d %v, want 200 failed", code, j)
	}
}

func TestWaitlistGlobalCapAndNotifyCap(t *testing.T) {
	var pushes atomic.Int32
	ntfySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushes.Add(1)
		w.WriteHeader(200)
	}))
	defer ntfySrv.Close()

	b, _ := newTestBroker(t, "")
	b.ntfy = ntfySrv.URL
	b.waitJoins = newLimiterWithCap(3, time.Hour, 4)
	b.waitNotify = newLimiterWithCap(2, time.Hour, 4)
	b.raiseNotify = newLimiterWithCap(2, time.Hour, 4)
	b.ntfySem = make(chan struct{}, 4)

	h := b.handler()
	for i, em := range []string{"u1@example.com", "u2@example.com", "u3@example.com"} {
		if code, out := call(h, "POST", "/waitlist", `{"email":"`+em+`"}`, auth); code != 200 {
			t.Fatalf("waitlist join %d: %d %v", i, code, out)
		}
	}
	// Already-waiting duplicate still succeeds without hitting the new-join cap.
	if code, out := call(h, "POST", "/waitlist", `{"email":"u1@example.com"}`, auth); code != 200 || out["already"] != true {
		t.Fatalf("duplicate check under global cap: %d %v", code, out)
	}
	// A 4th brand-new email hits the global join cap (429).
	if code, _ := call(h, "POST", "/waitlist", `{"email":"u4@example.com"}`, auth); code != 429 {
		t.Fatalf("4th new waitlist join = %d, want 429", code)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for pushes.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got := pushes.Load(); got != 2 {
		t.Fatalf("ntfy pushes = %d, want 2 (capped)", got)
	}
}

func TestJobStoreDeliveryWindow(t *testing.T) {
	wb := newWeb("http://127.0.0.1:0", testToken, "example.com")
	var clockMu sync.Mutex
	cur := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	wb.jobs.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return cur
	}
	setNow := func(ts time.Time) {
		clockMu.Lock()
		cur = ts
		clockMu.Unlock()
	}
	h := wb.handler()

	startDone := func(status int, out map[string]any) string {
		t.Helper()
		id, ok := wb.jobs.start(func() (int, map[string]any) { return status, out })
		if !ok {
			t.Fatal("expected job start to succeed")
		}
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			wb.jobs.mu.Lock()
			done := wb.jobs.jobs[id] != nil && wb.jobs.jobs[id].done
			wb.jobs.mu.Unlock()
			if done {
				return id
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("job %s did not finish in time", id)
		return ""
	}
	exists := func(id string) bool {
		wb.jobs.mu.Lock()
		defer wb.jobs.mu.Unlock()
		_, ok := wb.jobs.jobs[id]
		return ok
	}

	// 1. Delivered job stays re-readable for 5 minutes from first read, then expires.
	t0 := cur
	id1 := startDone(201, map[string]any{"owner": "alice"})
	if code, j := call(h, "GET", "/api/job?id="+id1, "", nil); code != 200 || j["state"] != "done" {
		t.Fatalf("first terminal read = %d %v, want 200 done", code, j)
	}
	setNow(t0.Add(4*time.Minute + 59*time.Second))
	if code, j := call(h, "GET", "/api/job?id="+id1, "", nil); code != 200 || j["state"] != "done" {
		t.Fatalf("re-read at +4m59s = %d %v, want 200 done", code, j)
	}
	setNow(t0.Add(5*time.Minute + 1*time.Second))
	if code, _ := call(h, "GET", "/api/job?id="+id1, "", nil); code != 404 {
		t.Fatalf("read at +5m01s = %d, want 404", code)
	}
	if exists(id1) {
		t.Fatalf("job %s still in store after delivery window expired", id1)
	}

	// 2. Unread finished job expires after the 30-minute ceiling.
	setNow(t0)
	id2 := startDone(500, map[string]any{"error": "boom"})
	setNow(t0.Add(30*time.Minute + 1*time.Second))
	if code, _ := call(h, "GET", "/api/job?id="+id2, "", nil); code != 404 {
		t.Fatalf("unread read at +30m01s = %d, want 404", code)
	}
	if exists(id2) {
		t.Fatalf("unread job %s still in store after 30m TTL", id2)
	}

	// 3. First delivery late in the 30m window still obeys the 30m hard ceiling.
	setNow(t0)
	id3 := startDone(201, map[string]any{"owner": "bob"})
	setNow(t0.Add(28 * time.Minute))
	if code, j := call(h, "GET", "/api/job?id="+id3, "", nil); code != 200 || j["state"] != "done" {
		t.Fatalf("first read at +28m = %d %v, want 200 done", code, j)
	}
	setNow(t0.Add(30*time.Minute + 1*time.Second))
	if code, _ := call(h, "GET", "/api/job?id="+id3, "", nil); code != 404 {
		t.Fatalf("re-read past 30m ceiling = %d, want 404", code)
	}
	if exists(id3) {
		t.Fatalf("late-delivered job %s still in store past 30m ceiling", id3)
	}
}
