package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	if code, _ := call(h, "GET", "/api/job?id=nope", "", nil); code != 404 {
		t.Fatalf("an unknown job: %d", code)
	}
	// A failed sign-up reports its reason through the job.
	_, out = call(h, "POST", "/api/create", `{"code":"PIG-ZZZZ-ZZZZ","pen":"jones","handle":"bob"}`, map[string]string{"Content-Type": "application/json"})
	for i := 0; i < 100; i++ {
		_, j := call(h, "GET", "/api/job?id="+out["job"].(string), "", nil)
		if j["state"] == "failed" {
			if j["status"] != float64(403) || !strings.Contains(j["error"].(string), "code") {
				t.Fatalf("failed job: %v", j)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
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
		`never recover a pen on request`,
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
