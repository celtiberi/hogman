package main

import (
	"context"
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
// makes the pen's folder unless the pen is called "explode" (or "explode-*").
const fakeHost = `#!/bin/sh
case "$1" in
  capacity) n=$(ls "$HOGMAN_HOME/pens" | wc -l); echo "{\"pens\":$n,\"max\":${FAKE_MAX:-3},\"open\":$([ $n -lt ${FAKE_MAX:-3} ] && echo true || echo false)}" ;;
  provision)
    case "$2" in explode|explode-*) echo boom >&2; exit 1 ;; esac
    [ -e "$HOGMAN_HOME/pens/$2" ] && exit 2
    [ $(ls "$HOGMAN_HOME/pens" | wc -l) -ge ${FAKE_MAX:-3} ] && exit 3
    mkdir "$HOGMAN_HOME/pens/$2"
    pen="$2"; owner="$3"; shift 3
    theme=""; plan=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --theme) theme="$2"; shift 2 ;;
        --plan)  plan="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    echo "==> lots of progress" >&2
    extra=""
    [ -n "$theme" ] && extra="$extra,\"theme\":\"$theme\""
    [ -n "$plan" ] && extra="$extra,\"plan\":\"$plan\""
    echo "{\"pen\":\"$pen\",\"zone\":\"$pen.pens.example.com\",\"host\":\"$pen.gate.example.com\",\"owner\":\"$owner\",\"join_link\":\"https://$pen.gate.example.com/join#k=abc\",\"valid_until\":\"x\"$extra}" ;;
  name-free) [ "${FAKE_CDNS_DOWN:-}" = 1 ] && { echo "admin.sock: no such file" >&2; exit 1; }; [ -e "$HOGMAN_HOME/pens/$2" ] && exit 2; [ "$2" = burned ] && exit 2; exit 0 ;;
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
	b, home := newTestBroker(t, "PIG-AAAA-BBBB vanity for alice\nPIG-CCCC-DDDD vanity other\n")
	h := b.handler()
	body := func(code, pen, owner string) string {
		j, _ := json.Marshal(map[string]string{"code": code, "pen": pen, "owner": owner})
		return string(j)
	}
	if code, out := call(h, "POST", "/provision", body("PIG-ZZZZ-ZZZZ", "smith", "alice"), auth); code != 403 {
		t.Fatalf("unknown code: %d %v", code, out)
	}
	code, out := call(h, "POST", "/provision", body("pig-aaaa-bbbb", "smith", "alice"), auth)
	if code != 201 || out["zone"] != "smith.pens.example.com" || !strings.Contains(out["join_link"].(string), "#k=") || strings.Contains(out["join_link"].(string), "fp=") {
		t.Fatalf("provision: %d %v", code, out)
	}
	if code, _ := call(h, "POST", "/provision", body("PIG-AAAA-BBBB", "jones", "alice"), auth); code != 403 {
		t.Fatalf("a used code worked again: %d", code)
	}
	codes, _ := os.ReadFile(filepath.Join(home, "signup", "codes"))
	if strings.Contains(string(codes), "AAAA") || !strings.Contains(string(codes), "PIG-CCCC-DDDD vanity other") {
		t.Fatalf("codes file after use: %q", codes)
	}
	if code, _ := call(h, "POST", "/provision", body("PIG-CCCC-DDDD", "smith", "bob"), auth); code != 409 {
		t.Fatalf("a taken name: %d", code)
	}
	ledger, _ := os.ReadFile(filepath.Join(home, "signup", "raised.log"))
	if !strings.Contains(string(ledger), "raised smith for alice with PIG-AAAA-BBBB (for alice) [vanity]") {
		t.Fatalf("ledger: %q", ledger)
	}
}

func TestBrokerSuffixedFreePensAndVanityTag(t *testing.T) {
	// Standard codes (and notes like "vanity-project" without a space) get a
	// server-assigned 4-char random suffix; only "vanity" / "vanity ..." gets bare names.
	b, home := newTestBroker(t, "PIG-AAAA-BBBB for alice\nPIG-CCCC-DDDD vanity-project\nPIG-EEEE-FFFF vanity\n")
	if v, p, n := parseCodeMeta("vanity"); !v || p != planPersonal || n != "" {
		t.Fatalf("parseCodeMeta(vanity) = (%v, %q, %q)", v, p, n)
	}
	if v, p, n := parseCodeMeta("vanity for vip"); !v || p != planPersonal || n != "for vip" {
		t.Fatalf("parseCodeMeta(vanity for vip) = (%v, %q, %q)", v, p, n)
	}
	if v, p, n := parseCodeMeta("vanity-project"); v || p != planPersonal || n != "vanity-project" {
		t.Fatalf("parseCodeMeta(vanity-project) = (%v, %q, %q)", v, p, n)
	}
	if v, p, n := parseCodeMeta("vanity work paid cs_test_1"); !v || p != planWork || n != "paid cs_test_1" {
		t.Fatalf("parseCodeMeta(vanity work paid) = (%v, %q, %q)", v, p, n)
	}
	if v, p, n := parseCodeMeta("work vanity vip"); !v || p != planWork || n != "vip" {
		t.Fatalf("parseCodeMeta(work vanity vip) = (%v, %q, %q)", v, p, n)
	}
	if v, p, n := parseCodeMeta("workshop for bob"); v || p != planPersonal || n != "workshop for bob" {
		t.Fatalf("parseCodeMeta(workshop) = (%v, %q, %q)", v, p, n)
	}

	h := b.handler()
	body := func(code, pen, owner string) string {
		j, _ := json.Marshal(map[string]string{"code": code, "pen": pen, "owner": owner})
		return string(j)
	}

	// Prefix > 25 chars is rejected for standard codes (validate + provision), allowed for vanity.
	long26 := strings.Repeat("a", 26)
	if code, _ := call(h, "POST", "/validate", body("PIG-AAAA-BBBB", long26, "alice"), auth); code != 400 {
		t.Fatalf("26-char prefix on standard validate: %d, want 400", code)
	}
	if code, _ := call(h, "POST", "/provision", body("PIG-AAAA-BBBB", long26, "alice"), auth); code != 400 {
		t.Fatalf("26-char prefix on standard provision: %d, want 400", code)
	}
	if code, out := call(h, "POST", "/validate", body("PIG-EEEE-FFFF", long26, "alice"), auth); code != 200 || out["vanity"] != true {
		t.Fatalf("26-char bare name on vanity validate: %d %v, want 200 vanity=true", code, out)
	}

	// First standard signup gets "coffee-<4chars>".
	code, out := call(h, "POST", "/provision", body("PIG-AAAA-BBBB", "coffee", "alice"), auth)
	if code != 201 {
		t.Fatalf("standard provision 1: %d %v", code, out)
	}
	pen1, _ := out["pen"].(string)
	if !strings.HasPrefix(pen1, "coffee-") || len(pen1) != len("coffee-")+penSuffixLen {
		t.Fatalf("pen1 = %q, want coffee-<4chars>", pen1)
	}
	for _, ch := range pen1[len("coffee-"):] {
		if !strings.ContainsRune(penSuffixAlphabet, ch) {
			t.Fatalf("suffix char %q outside alphabet %q", ch, penSuffixAlphabet)
		}
	}

	// Collision retry: if the first generated suffix collides with pen1, broker retries and picks a free one.
	takenSuffix := pen1[len("coffee-"):]
	seq := []string{takenSuffix, "k7m2"}
	if takenSuffix == "k7m2" {
		seq[1] = "p9n3"
	}
	idx := 0
	b.suffixFn = func() (string, error) {
		s := seq[idx]
		idx++
		return s, nil
	}
	code, out = call(h, "POST", "/provision", body("PIG-CCCC-DDDD", "coffee", "bob"), auth)
	if code != 201 {
		t.Fatalf("standard provision 2 with collision retry: %d %v", code, out)
	}
	pen2, _ := out["pen"].(string)
	if pen2 != "coffee-"+seq[1] || idx != 2 {
		t.Fatalf("pen2 = %q (idx=%d), want coffee-%s (idx=2)", pen2, idx, seq[1])
	}

	// Bare "coffee" is still free for a vanity code!
	code, out = call(h, "POST", "/provision", body("PIG-EEEE-FFFF", "coffee", "carol"), auth)
	if code != 201 || out["pen"] != "coffee" || out["zone"] != "coffee.pens.example.com" {
		t.Fatalf("vanity provision bare coffee: %d %v", code, out)
	}

	// Verify raised.log recorded actual suffixed and vanity names.
	ledger, _ := os.ReadFile(filepath.Join(home, "signup", "raised.log"))
	if !strings.Contains(string(ledger), "raised "+pen1+" for alice with PIG-AAAA-BBBB (for alice) in ") ||
		!strings.Contains(string(ledger), "raised coffee for carol with PIG-EEEE-FFFF () [vanity]") {
		t.Fatalf("ledger mismatch: %q", ledger)
	}
}

func TestBrokerFailureKeepsCode(t *testing.T) {
	b, home := newTestBroker(t, "PIG-AAAA-BBBB vanity x\nPIG-CCCC-DDDD y\n")
	j := `{"code":"PIG-AAAA-BBBB","pen":"explode","owner":"alice"}`
	code, out := call(b.handler(), "POST", "/provision", j, auth)
	if code != 500 {
		t.Fatalf("a failed vanity provision: %d", code)
	}
	errMsg, _ := out["error"].(string)
	if !strings.Contains(errMsg, "pick another pen name") {
		t.Fatalf("failed vanity provision error = %q, want guidance to pick another pen name", errMsg)
	}
	j2 := `{"code":"PIG-CCCC-DDDD","pen":"explode","owner":"bob"}`
	code, _ = call(b.handler(), "POST", "/provision", j2, auth)
	if code != 500 {
		t.Fatalf("a failed suffixed provision: %d", code)
	}
	codes, _ := os.ReadFile(filepath.Join(home, "signup", "codes"))
	if !strings.Contains(string(codes), "PIG-AAAA-BBBB") || !strings.Contains(string(codes), "PIG-CCCC-DDDD") {
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
	b, _ := newTestBroker(t, "PIG-AAAA-BBBB x\nPIG-CCCC-DDDD vanity y\n")
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	wb := newWeb(srv.URL, testToken, "pens.test")
	h := wb.handler()

	if code, out := call(h, "GET", "/api/status", "", nil); code != 200 || out["open"] != true || out["pens_domain"] != "pens.test" {
		t.Fatalf("status: %d %v", code, out)
	}
	if code, out := call(h, "GET", "/api/check?pen=Smith", "", nil); code != 200 || out["free"] != true || out["vanity"] != false {
		t.Fatalf("standard check: %d %v", code, out)
	}
	if _, out := call(h, "GET", "/api/check?pen="+strings.Repeat("a", 26), "", nil); out["free"] != false {
		t.Fatalf("26-char standard prefix should be rejected: %v", out)
	}
	if code, out := call(h, "GET", "/api/check?pen="+strings.Repeat("a", 26)+"&vanity=1", "", nil); code != 200 || out["free"] != true || out["vanity"] != true {
		t.Fatalf("26-char vanity check: %d %v", code, out)
	}
	if _, out := call(h, "GET", "/api/check?pen=x", "", nil); out["free"] != false {
		t.Fatalf("a one-letter name is free? %v", out)
	}
	// Standard code creates a suffixed pen ("smith-xxxx").
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
	if res == nil || res["owner"] != "alice" || !strings.HasPrefix(res["pen"].(string), "smith-") || !strings.HasPrefix(res["join_qr_svg"].(string), "<svg") {
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
	// Vanity code creates bare "smith"; then vanity check reports taken while standard prefix check stays free.
	code, out = call(h, "POST", "/api/create", `{"code":"PIG-CCCC-DDDD","pen":"Smith","handle":"Bob"}`, map[string]string{"Content-Type": "application/json"})
	if code != 202 {
		t.Fatalf("vanity create: %d %v", code, out)
	}
	vid, _ := out["job"].(string)
	for i := 0; i < 100; i++ {
		_, j := call(h, "GET", "/api/job?id="+vid, "", nil)
		if j["state"] == "done" {
			if r, _ := j["result"].(map[string]any); r["pen"] != "smith" {
				t.Fatalf("vanity result pen = %v, want smith", r["pen"])
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, out := call(h, "GET", "/api/check?pen=smith&vanity=1", "", nil); out["free"] != false {
		t.Fatalf("bare smith still free for vanity after it was raised: %v", out)
	}
	if _, out := call(h, "GET", "/api/check?pen=smith", "", nil); out["free"] != true {
		t.Fatalf("standard prefix smith should remain free even when bare smith is taken: %v", out)
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
		`id="done-cmd"`,
		`id="copy-cmd"`,
		`id="done-home-step"`,
		`id="open-setup"`,
		`treat them like a password`,
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
	if oac := rec.Header().Get("Origin-Agent-Cluster"); oac != "?1" {
		t.Fatalf("Origin-Agent-Cluster: %q, want ?1", oac)
	}
	if code, _ := call(h, "GET", "/api/status", "", nil); code != 502 {
		t.Fatalf("broker down should be 502, got %d", code)
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(2, time.Minute)
	now := time.Now()
	first, second, third := l.allow("a", now), l.allow("a", now), l.allow("a", now)
	if !first || !second || third {
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
	defer func() {
		if !gateClosed {
			close(gate)
		}
	}()

	wb2 := newWeb(mock.URL, testToken, "pens.test")
	h2 := wb2.handler()
	var ids []string
	for i := 1; i <= defaultMaxOpenJobs; i++ {
		codeVal := "PIG-AAAA-BBB" + string(rune('A'+i-1))
		code, out := call(h2, "POST", "/api/create", `{"code":"`+codeVal+`","pen":"pen`+strconv.Itoa(i)+`","handle":"alice"}`, map[string]string{
			"Content-Type": "application/json", "X-Forwarded-For": "198.51.100." + strconv.Itoa(i),
		})
		if code != 202 {
			t.Fatalf("job %d create = %d %v, want 202", i, code, out)
		}
		ids = append(ids, out["job"].(string))
	}
	// Reusing an in-flight code is rejected immediately with 409.
	if code, _ := call(h2, "POST", "/api/create", `{"code":"PIG-AAAA-BBBA","pen":"dup","handle":"alice"}`, map[string]string{
		"Content-Type": "application/json", "X-Forwarded-For": "198.51.100.98",
	}); code != 409 {
		t.Fatalf("duplicate in-flight code status = %d, want 409", code)
	}
	if code, _ := call(h2, "POST", "/api/create", `{"code":"PIG-AAAA-BBZZ","pen":"extra","handle":"alice"}`, map[string]string{
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

func TestCloudflareTrustedProxyAndAntiSpoofing(t *testing.T) {
	prefixes, err := parseCIDRs(defaultCloudflareCIDRs)
	if err != nil || len(prefixes) < 20 {
		t.Fatalf("defaultCloudflareCIDRs failed: len=%d err=%v", len(prefixes), err)
	}
	wb := newWeb("http://127.0.0.1:0", testToken, "pens.test")
	wb.trustedProxies = prefixes

	// 1. Request arriving from a real Cloudflare edge IP: trusts CF-Connecting-IP.
	reqCF := httptest.NewRequest("GET", "/api/check?pen=coffee", nil)
	reqCF.Header.Set("X-Forwarded-For", "172.70.1.5")
	reqCF.Header.Set("CF-Connecting-IP", "203.0.113.42")
	if got := wb.clientIP(reqCF); got != "203.0.113.42" {
		t.Fatalf("from Cloudflare IP: got %q, want 203.0.113.42", got)
	}

	// 2. Request arriving directly from an attacker bypassing Cloudflare with forged CF-Connecting-IP: IGNORED.
	reqDirect := httptest.NewRequest("GET", "/api/check?pen=coffee", nil)
	reqDirect.Header.Set("X-Forwarded-For", "198.51.100.77")
	reqDirect.Header.Set("CF-Connecting-IP", "203.0.113.42")
	if got := wb.clientIP(reqDirect); got != "198.51.100.77" {
		t.Fatalf("forged CF-Connecting-IP from non-CF peer: got %q, want 198.51.100.77", got)
	}

	// 3. When trustedProxies is empty (default), CF-Connecting-IP is NEVER trusted even from Cloudflare IPs.
	wbOff := newWeb("http://127.0.0.1:0", testToken, "pens.test")
	if got := wbOff.clientIP(reqCF); got != "172.70.1.5" {
		t.Fatalf("with trustedProxies off: got %q, want 172.70.1.5", got)
	}

	// 4. Two different visitors behind the same Cloudflare edge IP get separate rate-limit buckets.
	wb.creates = newLimiter(1, time.Hour)
	b, _ := newTestBroker(t, "PIG-AAAA-BBBB x\n")
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	wb.brokerURL = srv.URL
	h := wb.handler()
	hdr1 := map[string]string{"Content-Type": "application/json", "X-Forwarded-For": "172.70.1.5", "CF-Connecting-IP": "203.0.113.1"}
	hdr2 := map[string]string{"Content-Type": "application/json", "X-Forwarded-For": "172.70.1.5", "CF-Connecting-IP": "203.0.113.2"}
	if code, _ := call(h, "POST", "/api/create", `{"code":"PIG-ZZZZ-ZZZZ","pen":"coffee","handle":"alice"}`, hdr1); code != 403 {
		t.Fatalf("visitor 1 first try: %d, want 403", code)
	}
	if code, _ := call(h, "POST", "/api/create", `{"code":"PIG-ZZZZ-ZZZZ","pen":"coffee","handle":"alice"}`, hdr1); code != 429 {
		t.Fatalf("visitor 1 second try: %d, want 429", code)
	}
	if code, _ := call(h, "POST", "/api/create", `{"code":"PIG-ZZZZ-ZZZZ","pen":"coffee","handle":"bob"}`, hdr2); code != 403 {
		t.Fatalf("visitor 2 behind same CF IP was rate-limited: %d, want 403", code)
	}
}

func TestTurnstileVerificationCSPAndGlobalWaitlistProtection(t *testing.T) {
	b, _ := newTestBroker(t, "PIG-AAAA-BBBB x\n")
	brokerSrv := httptest.NewServer(b.handler())
	defer brokerSrv.Close()

	var lastRemoteIP string
	var down atomic.Bool
	tsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(502)
			return
		}
		_ = r.ParseForm()
		lastRemoteIP = r.FormValue("remoteip")
		switch r.FormValue("response") {
		case "good-token":
			jsonOut(w, 200, map[string]any{"success": true, "hostname": "get.example"})
		case "wrong-host-token":
			jsonOut(w, 200, map[string]any{"success": true, "hostname": "evil.example"})
		default:
			jsonOut(w, 200, map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}})
		}
	}))
	defer tsSrv.Close()

	wb := newWeb(brokerSrv.URL, testToken, "pens.test")
	wb.turnstile = newTurnstileVerifier("0x4AAAAAAATESTKEY", "secret-key", tsSrv.URL, "get.example")
	wb.globalWaits = newLimiterWithCap(1, time.Hour, 4)
	h := wb.handler()

	// 1. CSP widens minimally to challenges.cloudflare.com only when Turnstile is enabled,
	//    and /api/status advertises turnstile_site_key.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "https://challenges.cloudflare.com") {
		t.Fatalf("CSP missing Turnstile origin: %q", csp)
	}
	if code, out := call(h, "GET", "/api/status", "", nil); code != 200 || out["turnstile_site_key"] != "0x4AAAAAAATESTKEY" {
		t.Fatalf("status missing turnstile_site_key: %d %v", code, out)
	}

	// 2. Bots without valid Turnstile tokens are rejected (403) and NEVER consume globalWaits!
	for i := 0; i < 3; i++ {
		hdr := map[string]string{"Content-Type": "application/json", "X-Forwarded-For": "198.51.100." + strconv.Itoa(i+1)}
		if code, _ := call(h, "POST", "/api/waitlist", `{"email":"bot@example.com"}`, hdr); code != 403 {
			t.Fatalf("missing token waitlist %d: %d, want 403", i, code)
		}
		if code, _ := call(h, "POST", "/api/waitlist", `{"email":"bot@example.com","turnstile_token":"wrong-host-token"}`, hdr); code != 403 {
			t.Fatalf("wrong-host token waitlist %d: %d, want 403", i, code)
		}
	}
	// Real human with valid token still succeeds because bots didn't burn globalWaits (limit=1)!
	humanHdr := map[string]string{"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.9"}
	if code, out := call(h, "POST", "/api/waitlist", `{"email":"human@example.com","turnstile_token":"good-token"}`, humanHdr); code != 200 || out["place"] != float64(1) {
		t.Fatalf("human waitlist after bot attempts: %d %v, want 200 place=1", code, out)
	}
	if lastRemoteIP != "203.0.113.9" {
		t.Fatalf("remoteip passed to Turnstile = %q, want 203.0.113.9", lastRemoteIP)
	}

	// 3. /api/create enforces Turnstile (403 on missing/bad, 503 fail-closed when Turnstile is down, 202 on good).
	if code, _ := call(h, "POST", "/api/create", `{"code":"PIG-AAAA-BBBB","pen":"coffee","handle":"alice"}`, humanHdr); code != 403 {
		t.Fatalf("create without token: %d, want 403", code)
	}
	down.Store(true)
	if code, _ := call(h, "POST", "/api/create", `{"code":"PIG-AAAA-BBBB","pen":"coffee","handle":"alice","turnstile_token":"good-token"}`, humanHdr); code != 503 {
		t.Fatalf("create when Turnstile down: %d, want 503", code)
	}
	down.Store(false)
	if code, out := call(h, "POST", "/api/create", `{"code":"PIG-AAAA-BBBB","pen":"coffee","handle":"alice","turnstile_token":"good-token"}`, humanHdr); code != 202 || out["job"] == nil {
		t.Fatalf("create with good token: %d %v, want 202", code, out)
	}
}

func TestWorkHostThemeAndMultiHostTurnstile(t *testing.T) {
	b, home := newTestBroker(t, "PIG-AAAA-BBBB vanity work work1\nPIG-CCCC-DDDD vanity work work2\nPIG-EEEE-FFFF vanity pers1\n")
	brokerSrv := httptest.NewServer(b.handler())
	defer brokerSrv.Close()

	tsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.Form.Get("response") {
		case "tok-main":
			jsonOut(w, 200, map[string]any{"success": true, "hostname": "get.example.com"})
		case "tok-work":
			jsonOut(w, 200, map[string]any{"success": true, "hostname": "get.work.example.com"})
		default:
			jsonOut(w, 200, map[string]any{"success": true, "hostname": "evil.example.net"})
		}
	}))
	defer tsSrv.Close()

	wb := newWeb(brokerSrv.URL, testToken, "pens.test")
	wb.creates = newLimiter(20, time.Hour)
	wb.workHost = "get.work.example.com"
	wb.turnstile = newTurnstileVerifier("0x4TEST", "secret", tsSrv.URL, "get.example.com,get.work.example.com")
	h := wb.handler()

	callHost := func(host, method, path, body string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	// 1. /api/status advertises theme="work" only on the Work host (case/port insensitive).
	if code, out := callHost("get.example.com", "GET", "/api/status", ""); code != 200 || out["theme"] != nil {
		t.Fatalf("default host status: %d %v", code, out)
	}
	if code, out := callHost("GET.WORK.EXAMPLE.COM:443", "GET", "/api/status", ""); code != 200 || out["theme"] != "work" {
		t.Fatalf("work host status: %d %v", code, out)
	}

	// 2. Invalid theme is rejected with 400 on both web and broker.
	if code, _ := callHost("get.example.com", "POST", "/api/create", `{"code":"PIG-AAAA-BBBB","pen":"acme","handle":"alice","theme":"neon","turnstile_token":"tok-main"}`); code != 400 {
		t.Fatalf("invalid theme on web: %d, want 400", code)
	}
	if code, _ := call(b.handler(), "POST", "/validate", `{"code":"PIG-AAAA-BBBB","pen":"acme","owner":"alice","theme":"neon"}`, auth); code != 400 {
		t.Fatalf("invalid theme on broker: %d, want 400", code)
	}

	// 3. Turnstile rejects foreign hostname even when multiple signup hosts are allowed.
	if code, _ := callHost("get.work.example.com", "POST", "/api/create", `{"code":"PIG-AAAA-BBBB","pen":"acme","handle":"alice","turnstile_token":"tok-evil"}`); code != 403 {
		t.Fatalf("foreign Turnstile host: %d, want 403", code)
	}

	// 4. D-30: Personal code cannot raise a pen on the Work host (403 on both web and broker).
	if code, out := callHost("get.work.example.com", "POST", "/api/create", `{"code":"PIG-EEEE-FFFF","pen":"gamma","handle":"carol","turnstile_token":"tok-work"}`); code != 403 {
		t.Fatalf("personal code on work host: %d %v, want 403", code, out)
	}
	if code, out := call(b.handler(), "POST", "/provision", `{"code":"PIG-EEEE-FFFF","pen":"gamma","owner":"carol","want_plan":"work"}`, auth); code != 403 {
		t.Fatalf("personal code direct broker provision with want_plan=work: %d %v, want 403", code, out)
	}

	waitDone := func(jobID string) map[string]any {
		t.Helper()
		for i := 0; i < 100; i++ {
			code, j := callHost("get.work.example.com", "GET", "/api/job?id="+jobID, "")
			if code == 200 && j["state"] == "done" {
				return j["result"].(map[string]any)
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("job %s did not finish", jobID)
		return nil
	}

	// 5. Work code on Work host raises a Work pen (plan=work, theme=work) and accepts work-host Turnstile token.
	code, out := callHost("get.work.example.com", "POST", "/api/create", `{"code":"PIG-AAAA-BBBB","pen":"acme","handle":"alice","turnstile_token":"tok-work"}`)
	if code != 202 {
		t.Fatalf("work host create: %d %v", code, out)
	}
	if res := waitDone(out["job"].(string)); res["theme"] != "work" || res["plan"] != "work" {
		t.Fatalf("work host create result = %v, want theme=work plan=work", res)
	}

	// 6. D-30: Work code redeemed on the primary host ALSO raises a Work pen (plan=work, theme=work).
	code, out = callHost("get.example.com", "POST", "/api/create", `{"code":"PIG-CCCC-DDDD","pen":"beta","handle":"bob","turnstile_token":"tok-main"}`)
	if code != 202 {
		t.Fatalf("work code on default host create: %d %v", code, out)
	}
	if res := waitDone(out["job"].(string)); res["theme"] != "work" || res["plan"] != "work" {
		t.Fatalf("work code on default host result = %v, want theme=work plan=work", res)
	}

	// 7. Personal code on default host with explicit theme="work" keeps Personal plan (THEME != PLAN).
	code, out = callHost("get.example.com", "POST", "/api/create", `{"code":"PIG-EEEE-FFFF","pen":"gamma","handle":"carol","theme":"work","turnstile_token":"tok-main"}`)
	if code != 202 {
		t.Fatalf("personal code with work theme on default host: %d %v", code, out)
	}
	if res := waitDone(out["job"].(string)); res["theme"] != "work" || res["plan"] != nil {
		t.Fatalf("personal code with work theme result = %v, want theme=work and no plan=work", res)
	}

	ledger, _ := os.ReadFile(filepath.Join(home, "signup", "raised.log"))
	if !strings.Contains(string(ledger), "raised acme for alice with PIG-AAAA-BBBB (work1) [vanity] [plan=work] [theme=work]") {
		t.Fatalf("ledger missing [plan=work] [theme=work] for acme:\n%s", ledger)
	}
	if !strings.Contains(string(ledger), "raised beta for bob with PIG-CCCC-DDDD (work2) [vanity] [plan=work] [theme=work]") {
		t.Fatalf("ledger missing [plan=work] [theme=work] for beta:\n%s", ledger)
	}
	if strings.Contains(string(ledger), "raised gamma for carol") && strings.Contains(strings.Split(string(ledger), "raised gamma for carol")[1], "[plan=work]") {
		t.Fatalf("ledger unexpectedly tagged personal pen gamma with [plan=work]:\n%s", ledger)
	}
}

func TestBrokerHealthAndChallengeDNSOutage(t *testing.T) {
	// Verify loopback URL normalization for the `hogman-signup health` probe.
	for in, want := range map[string]string{
		":9090":          "http://127.0.0.1:9090/health",
		"0.0.0.0:9090":   "http://127.0.0.1:9090/health",
		"[::]:9090":      "http://127.0.0.1:9090/health",
		"127.0.0.1:9091": "http://127.0.0.1:9091/health",
		"[::1]:9092":     "http://[::1]:9092/health",
	} {
		if got := brokerHealthURL(in); got != want {
			t.Fatalf("brokerHealthURL(%q) = %q, want %q", in, got, want)
		}
	}

	var pushes atomic.Int32
	var lastPushMu sync.Mutex
	var lastPush string
	ntfySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf [512]byte
		n, _ := r.Body.Read(buf[:])
		lastPushMu.Lock()
		lastPush = string(buf[:n])
		lastPushMu.Unlock()
		pushes.Add(1)
		w.WriteHeader(200)
	}))
	defer ntfySrv.Close()

	b, home := newTestBroker(t, "PIG-AAAA-BBBB vanity for alice\nPIG-CCCC-DDDD for bob\n")
	b.ntfy = ntfySrv.URL
	h := b.handler()

	srv := httptest.NewServer(h)
	defer srv.Close()

	// Auth required on /health.
	if code, _ := call(h, "GET", "/health", "", nil); code != 401 {
		t.Fatalf("unauthenticated /health: %d, want 401", code)
	}
	if err := checkBrokerHealth(t.Context(), srv.URL+"/health", "wrong-token"); err == nil {
		t.Fatalf("checkBrokerHealth accepted wrong token")
	}

	// Healthy state: /health returns 200 ok=true, CLI helper succeeds, zero ntfy pushes.
	if code, out := call(h, "GET", "/health", "", auth); code != 200 || out["ok"] != true {
		t.Fatalf("healthy /health: %d %v", code, out)
	}
	if err := checkBrokerHealth(t.Context(), srv.URL+"/health", testToken); err != nil {
		t.Fatalf("healthy checkBrokerHealth: %v", err)
	}
	if got := pushes.Load(); got != 0 {
		t.Fatalf("healthy /health triggered %d ntfy pushes, want 0", got)
	}

	// Simulate stale challenge-dns bind-mount / unreachable admin socket.
	t.Setenv("FAKE_CDNS_DOWN", "1")

	// /health fails with 503, checkBrokerHealth returns an error, and ntfy alerts at most 1/hour.
	code, out := call(h, "GET", "/health", "", auth)
	if code != 503 || out["ok"] != false || !strings.Contains(out["error"].(string), "admin.sock") {
		t.Fatalf("down /health: %d %v, want 503 mentioning admin.sock", code, out)
	}
	if err := checkBrokerHealth(t.Context(), srv.URL+"/health", testToken); err == nil {
		t.Fatalf("down checkBrokerHealth succeeded, want error")
	}
	for i := 0; i < 3; i++ {
		if code, _ := call(h, "GET", "/health", "", auth); code != 503 {
			t.Fatalf("repeated down /health #%d: %d, want 503", i, code)
		}
	}

	// Wait briefly for the async ntfy goroutine to complete and verify hourly cap = 1.
	deadline := time.Now().Add(2 * time.Second)
	for pushes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got := pushes.Load(); got != 1 {
		t.Fatalf("health ntfy pushes = %d, want 1 (rate-limited to 1/hour)", got)
	}
	lastPushMu.Lock()
	msg := lastPush
	lastPushMu.Unlock()
	if !strings.Contains(msg, "challenge-dns") || !strings.Contains(msg, "admin.sock") {
		t.Fatalf("health ntfy message = %q, want mention of challenge-dns and admin.sock", msg)
	}

	// /check, /validate, and /provision (vanity) must return 503 instead of claiming "that name is taken".
	if code, out := call(h, "GET", "/check?pen=fresh&vanity=1", "", auth); code != 503 || out["error"] != nameCheckUnavailableMsg {
		t.Fatalf("down /check: %d %v, want 503 %q", code, out, nameCheckUnavailableMsg)
	}
	vanityBody := `{"code":"PIG-AAAA-BBBB","pen":"fresh","owner":"alice"}`
	if code, out := call(h, "POST", "/validate", vanityBody, auth); code != 503 || out["error"] != nameCheckUnavailableMsg {
		t.Fatalf("down /validate vanity: %d %v, want 503 %q", code, out, nameCheckUnavailableMsg)
	}
	if code, out := call(h, "POST", "/provision", vanityBody, auth); code != 503 || out["error"] != nameCheckUnavailableMsg {
		t.Fatalf("down /provision vanity: %d %v, want 503 %q", code, out, nameCheckUnavailableMsg)
	}

	// Suffixed /provision must fail fast on the first suffix attempt with 503 (not retry 16 times).
	suffixCalls := 0
	b.suffixFn = func() (string, error) {
		suffixCalls++
		return "k7m2", nil
	}
	suffixedBody := `{"code":"PIG-CCCC-DDDD","pen":"coffee","owner":"bob"}`
	if code, out := call(h, "POST", "/provision", suffixedBody, auth); code != 503 || out["error"] != nameCheckUnavailableMsg {
		t.Fatalf("down /provision suffixed: %d %v, want 503 %q", code, out, nameCheckUnavailableMsg)
	}
	if suffixCalls != 1 {
		t.Fatalf("pickSuffixedPen tried %d suffixes during challenge-dns outage, want 1 (fail fast)", suffixCalls)
	}

	// Both codes must remain unspent in signup/codes.
	codesBytes, err := os.ReadFile(filepath.Join(home, "signup", "codes"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(codesBytes), "PIG-AAAA-BBBB") || !strings.Contains(string(codesBytes), "PIG-CCCC-DDDD") {
		t.Fatalf("codes were consumed during outage: %q", codesBytes)
	}

	// Public web layer forwards 503 cleanly on /api/check and /api/create.
	wb := newWeb(srv.URL, testToken, "gate.example.com")
	wh := wb.handler()
	if code, out := call(wh, "GET", "/api/check?pen=fresh&vanity=1", "", nil); code != 503 || out["error"] != nameCheckUnavailableMsg {
		t.Fatalf("web down /api/check: %d %v, want 503 %q", code, out, nameCheckUnavailableMsg)
	}
	if code, out := call(wh, "POST", "/api/create", `{"code":"PIG-AAAA-BBBB","pen":"fresh","handle":"alice"}`, map[string]string{"Content-Type": "application/json"}); code != 503 || out["error"] != nameCheckUnavailableMsg {
		t.Fatalf("web down /api/create: %d %v, want 503 %q", code, out, nameCheckUnavailableMsg)
	}
}

func TestWaitlistAckEmailPersonalWorkDedupAndNoNoteReflection(t *testing.T) {
	b, _ := newTestBroker(t, "")
	b.publicURL = "https://get.example.com"
	b.workSignupHost = "get.work.example.com"
	b.waitAckMail = newLimiterWithCap(2, time.Hour, 4)

	type sentMail struct {
		to      []string
		subject string
		text    string
	}
	sentCh := make(chan sentMail, 8)
	b.alertSendFn = func(_ context.Context, to []string, subject, text string) error {
		sentCh <- sentMail{to: append([]string(nil), to...), subject: subject, text: text}
		return nil
	}

	brokerSrv := httptest.NewServer(b.handler())
	defer brokerSrv.Close()

	wb := newWeb(brokerSrv.URL, testToken, "pens.test")
	wb.workHost = "get.work.example.com"
	wb.waits = newLimiter(20, time.Hour)
	wb.globalWaits = newLimiter(20, time.Hour)
	wb.leaves = newLimiter(20, time.Hour)
	wh := wb.handler()

	postJSON := func(host, path, body string) (int, map[string]any) {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Host = host
		req.Header.Set("Origin", "https://"+host)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		wh.ServeHTTP(rec, req)
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	postWait := func(host, body string) (int, map[string]any) {
		return postJSON(host, "/api/waitlist", body)
	}

	// 1. Personal host join sends a Hogman ack email without echoing the free-form note.
	if code, out := postWait("get.example.com", `{"email":"alice@example.com","pen":"lab","note":"CLICK PHISH LINK https://evil.example"}`); code != 200 || out["place"] != float64(1) {
		t.Fatalf("personal waitlist join = %d %v", code, out)
	}
	select {
	case m := <-sentCh:
		if len(m.to) != 1 || m.to[0] != "alice@example.com" {
			t.Fatalf("personal ack to = %v", m.to)
		}
		if m.subject != "You're on the Hogman waiting list" {
			t.Fatalf("personal ack subject = %q", m.subject)
		}
		if !strings.Contains(m.text, "spot #1") || !strings.Contains(m.text, "https://get.example.com/#wait") || !strings.Contains(m.text, `"Take me off the list"`) {
			t.Fatalf("personal ack body missing expected details:\n%s", m.text)
		}
		if strings.Contains(m.text, "Requested pen name") {
			t.Fatalf("ack email must not imply bare pen-name reservation for free waitlist:\n%s", m.text)
		}
		if strings.Contains(m.text, "PHISH") || strings.Contains(m.text, "evil.example") {
			t.Fatalf("ack email MUST NOT reflect untrusted note text:\n%s", m.text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for personal waitlist ack email")
	}

	// 2. Duplicate submit for alice@example.com MUST NOT send another email.
	if code, out := postWait("get.example.com", `{"email":"ALICE@example.com"}`); code != 200 || out["place"] != float64(1) {
		t.Fatalf("duplicate waitlist join = %d %v", code, out)
	}
	select {
	case m := <-sentCh:
		t.Fatalf("duplicate waitlist submit should not re-send ack email: %+v", m)
	case <-time.After(150 * time.Millisecond):
	}

	// 2b. Join -> leave -> join again for the same address MUST NOT send a second
	//     email within 24h AND must NOT burn global waitAckMail budget (limit is 2,
	//     so bob below must still receive his email).
	if code, _ := postJSON("get.example.com", "/api/waitlist/leave", `{"email":"alice@example.com"}`); code != 200 {
		t.Fatalf("waitlist leave = %d, want 200", code)
	}
	if code, out := postWait("get.example.com", `{"email":"ALICE@example.com"}`); code != 200 || out["place"] != float64(1) {
		t.Fatalf("re-join after leave = %d %v", code, out)
	}
	select {
	case m := <-sentCh:
		t.Fatalf("join->leave->join within 24h should not re-send ack email: %+v", m)
	case <-time.After(150 * time.Millisecond):
	}

	// 3. Work host join sends a Hogman Work ack email linking to get.work.example.com/#wait
	//    (proving alice's suppressed join->leave->join did not spend global waitAckMail budget).
	if code, out := postWait("get.work.example.com", `{"email":"bob@example.com","pen":"acme"}`); code != 200 || out["place"] != float64(2) {
		t.Fatalf("work waitlist join = %d %v", code, out)
	}
	select {
	case m := <-sentCh:
		if len(m.to) != 1 || m.to[0] != "bob@example.com" {
			t.Fatalf("work ack to = %v", m.to)
		}
		if m.subject != "You're on the Hogman for Work waiting list" {
			t.Fatalf("work ack subject = %q", m.subject)
		}
		if !strings.Contains(m.text, "Hogman for Work waiting list (spot #2)") || !strings.Contains(m.text, "https://get.work.example.com/#wait") || !strings.Contains(m.text, `"Remove my email"`) {
			t.Fatalf("work ack body missing Work branding/URL/button label:\n%s", m.text)
		}
		if strings.Contains(m.text, "proton.me") {
			t.Fatalf("ack email must not hardcode an operator support inbox:\n%s", m.text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for work waitlist ack email")
	}

	// 4. Rate cap hit (limit was 2): 3rd new email still joins the waitlist (200) without sending extra mail.
	if code, out := postWait("get.work.example.com", `{"email":"carol@example.com"}`); code != 200 || out["place"] != float64(3) {
		t.Fatalf("rate-capped waitlist join = %d %v", code, out)
	}
	select {
	case m := <-sentCh:
		t.Fatalf("waitAckMail rate cap should suppress 3rd email: %+v", m)
	case <-time.After(150 * time.Millisecond):
	}

	// 5. Full mailSem skips without burning per-address or global rate-limit budget.
	b.waitAckMail = newLimiterWithCap(1, time.Hour, 4)
	b.mailSem = make(chan struct{}, 1)
	b.mailSem <- struct{}{} // occupy only slot
	b.sendWaitlistAckAsync("dave@example.com", 4, false)
	<-b.mailSem // free slot; dave's per-address + global budget must still be unspent
	b.sendWaitlistAckAsync("dave@example.com", 4, false)
	select {
	case m := <-sentCh:
		if len(m.to) != 1 || m.to[0] != "dave@example.com" {
			t.Fatalf("expected dave@example.com ack after mailSem freed, got %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("full mailSem burned rate-limit budget for unsent email")
	}
}

func TestSignupPageCodeGateAndWaitlistMarkup(t *testing.T) {
	b, _ := newTestBroker(t, "")
	bsrv := httptest.NewServer(b.handler())
	t.Cleanup(bsrv.Close)

	wb := newWeb(bsrv.URL, testToken, "pens.test")
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	wb.handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	html := rec.Body.String()
	if strings.Contains(html, `id="w-pen"`) {
		t.Fatal("waitlist form must not ask for a bare vanity pen name (id=\"w-pen\")")
	}
	codeFieldsIdx := strings.Index(html, `<div id="code-fields" hidden>`)
	tsFormIdx := strings.Index(html, `<div class="turnstile" id="ts-form" hidden>`)
	formActionsIdx := strings.Index(html, `<div class="actions" id="form-actions" hidden>`)
	if codeFieldsIdx < 0 || tsFormIdx < 0 || formActionsIdx < 0 {
		t.Fatalf("missing expected code-gate markup: code-fields=%d ts-form=%d form-actions=%d", codeFieldsIdx, tsFormIdx, formActionsIdx)
	}
	if !(codeFieldsIdx < tsFormIdx && tsFormIdx < formActionsIdx) {
		t.Fatalf("expected #ts-form between #code-fields and #form-actions so Buy a pen works without a code")
	}
	if strings.Contains(html, `id="done-home"`) {
		t.Fatal("post-signup intro must not display the unresolvable home URL ahead of Step 1")
	}
	if !strings.Contains(html, `id="done-cmd"`) || !strings.Contains(html, `id="copy-cmd"`) {
		t.Fatal("post-signup Step 1 must display the direct terminal join command with a Copy command button")
	}
	if !strings.Contains(html, `id="open-setup" target="_blank" rel="noopener noreferrer"`) {
		t.Fatal("post-signup fallback must include a safe clickable Open setup page link button")
	}
}
