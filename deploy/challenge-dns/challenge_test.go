package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var testZones = Zones{Pens: "pens.hogman.network", Gate: "_acme-challenge.gate.hogman.network"}

const (
	penA = "abcdefghijk2"
	penB = "zyxwvutsrq77"
	val1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 43 chars, like a real key authorization digest
	val2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	val3 = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

func newTestStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "state.json"), testZones)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	return s, &now
}

func mustCred(t *testing.T, s *Store, kind, pen string) (Cred, string) {
	t.Helper()
	c, tok, err := s.AddCred(kind, pen)
	if err != nil {
		t.Fatal(err)
	}
	return c, tok
}

func ch(site, pen string) string {
	return "_acme-challenge." + site + "." + pen + ".pens.hogman.network"
}

func TestScope(t *testing.T) {
	s, _ := newTestStore(t)
	a, _ := mustCred(t, s, "pen", penA)
	host, _ := mustCred(t, s, "host", "")
	cases := []struct {
		c    Cred
		fqdn string
		ok   bool
	}{
		{a, ch("photos", penA), true},
		{a, ch("home", penA), true},
		{a, ch("a.b.c.d", penA), true},
		{a, "_ACME-Challenge.Photos." + strings.ToUpper(penA) + ".PENS.hogman.network.", true}, // case and trailing dot
		{a, ch("a.b.c.d.e", penA), false},                              // deeper than pen names go
		{a, ch("photos", penB), false},                                 // another pen
		{a, "_acme-challenge." + penA + ".pens.hogman.network", false}, // the pen apex itself
		{a, "photos." + penA + ".pens.hogman.network", false},          // not a challenge name
		{a, "_acme-challenge.photos." + penA + ".pens.hogman.network.evil.com", false},
		{a, ch("bad_label", penA), false},
		{a, testZones.Gate, false}, // the front door's name
		{host, testZones.Gate, true},
		{host, ch("photos", penA), false}, // host can't write pens
	}
	for _, tc := range cases {
		if got := s.InScope(tc.c, tc.fqdn); got != tc.ok {
			t.Errorf("InScope(%s, %q) = %v, want %v", tc.c.Kind, tc.fqdn, got, tc.ok)
		}
	}
	for _, bad := range []string{"ab", "-bad", "Bad", "has.dot", "has_underscore", strings.Repeat("a", 31)} {
		if _, _, err := s.AddCred("pen", bad); err == nil {
			t.Errorf("accepted the malformed pen name %q", bad)
		}
	}
	if _, _, err := s.AddCred("pen", penA); err == nil {
		t.Error("allowed a second credential for the same pen")
	}
}

func TestTXTLifecycleAndLimits(t *testing.T) {
	s, now := newTestStore(t)
	a, _ := mustCred(t, s, "pen", penA)
	n := ch("photos", penA)

	if err := s.PutTXT(a, n, "short"); err != errValue {
		t.Fatalf("bad value: %v, want errValue", err)
	}
	if err := s.PutTXT(a, n, val1); err != nil {
		t.Fatal(err)
	}
	if err := s.PutTXT(a, n, val1); err != nil { // idempotent
		t.Fatalf("repeat put: %v", err)
	}
	if err := s.PutTXT(a, n, val2); err != nil {
		t.Fatal(err)
	}
	if err := s.PutTXT(a, n, val3); err != errFull {
		t.Fatalf("third live value: %v, want errFull", err)
	}
	if got := s.TXT(strings.ToUpper(n)); len(got) != 2 {
		t.Fatalf("TXT: %v", got)
	}
	if err := s.DeleteTXT(a, n, val1); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTXT(a, n, val1); err != nil { // absent is still fine
		t.Fatalf("delete absent: %v", err)
	}
	if err := s.DeleteTXT(a, ch("photos", penB), val1); err != errScope {
		t.Fatalf("delete out of scope: %v", err)
	}
	*now = now.Add(txtTTL + time.Second)
	if got := s.TXT(n); len(got) != 0 {
		t.Fatalf("expired values still served: %v", got)
	}
}

func TestWeeklyCapCountsDistinctNames(t *testing.T) {
	s, now := newTestStore(t)
	a, _ := mustCred(t, s, "pen", penA)
	for i := 0; i < defaultCapNames; i++ {
		if err := s.PutTXT(a, ch(fmt.Sprintf("site%d", i), penA), val1); err != nil {
			t.Fatalf("name %d: %v", i, err)
		}
	}
	if err := s.PutTXT(a, ch("one-more", penA), val1); err != errCap {
		t.Fatalf("%dth new name: %v, want errCap", defaultCapNames+1, err)
	}
	// A name already counted is free (a retry, or two values for one order).
	*now = now.Add(txtTTL + time.Second)
	if err := s.PutTXT(a, ch("site3", penA), val2); err != nil {
		t.Fatalf("re-writing a counted name: %v", err)
	}
	// The cap survives a restart.
	s2, err := OpenStore(s.path, testZones)
	if err != nil {
		t.Fatal(err)
	}
	s2.now = s.now
	if err := s2.PutTXT(a, ch("one-more", penA), val1); err != errCap {
		t.Fatalf("after restart: %v, want errCap", err)
	}
	// A week later the window has moved on.
	*now = now.Add(capWindow)
	if err := s2.PutTXT(a, ch("one-more", penA), val1); err != nil {
		t.Fatalf("a week later: %v", err)
	}
}

func TestWeeklyCapOverrideAndParse(t *testing.T) {
	if got, err := parseWeeklyCap(""); err != nil || got != defaultCapNames {
		t.Fatalf("parseWeeklyCap empty = (%d, %v), want (%d, nil)", got, err, defaultCapNames)
	}
	if got, err := parseWeeklyCap("12"); err != nil || got != 12 {
		t.Fatalf("parseWeeklyCap 12 = (%d, %v), want (12, nil)", got, err)
	}
	for _, bad := range []string{"0", "-1", "1001", "abc"} {
		if _, err := parseWeeklyCap(bad); err == nil {
			t.Fatalf("parseWeeklyCap(%q) succeeded, want error", bad)
		}
	}
	s, _ := newTestStore(t)
	s.capNames = 2
	a, _ := mustCred(t, s, "pen", penA)
	for i := 0; i < 2; i++ {
		if err := s.PutTXT(a, ch(fmt.Sprintf("custom%d", i), penA), val1); err != nil {
			t.Fatalf("name %d: %v", i, err)
		}
	}
	if err := s.PutTXT(a, ch("custom-third", penA), val1); err != errCap {
		t.Fatalf("3rd name with cap=2: %v, want errCap", err)
	}
}

func TestAuthUsesHashes(t *testing.T) {
	s, _ := newTestStore(t)
	c, tok := mustCred(t, s, "pen", penA)
	if got, ok := s.Auth(tok); !ok || got.ID != c.ID {
		t.Fatal("token not accepted")
	}
	if _, ok := s.Auth(tok + "x"); ok {
		t.Fatal("wrong token accepted")
	}
	b, _ := json.Marshal(s.st)
	if bytes.Contains(b, []byte(tok)) {
		t.Fatal("the token itself was stored")
	}
}

// --- DNS ---------------------------------------------------------------------

func startDNS(t *testing.T, s *Store) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &DNS{store: s, zones: testZones, ns: "ns1.hogman.network", mbox: "hostmaster.hogman.network", caa: defaultCAA()}
	srv := &dns.Server{PacketConn: pc, Handler: d}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func ask(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	r, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return r
}

func TestDNSAnswers(t *testing.T) {
	s, _ := newTestStore(t)
	a, _ := mustCred(t, s, "pen", penA)
	host, _ := mustCred(t, s, "host", "")
	_ = s.PutTXT(a, ch("photos", penA), val1)
	_ = s.PutTXT(host, testZones.Gate, val2)
	addr := startDNS(t, s)

	// The challenge record, asked in mixed case: answered, and echoed in that case.
	q := "_ACME-challenge.Photos." + penA + ".PENS.Hogman.Network."
	r := ask(t, addr, q, dns.TypeTXT)
	if r.Rcode != dns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 1 {
		t.Fatalf("TXT: %v", r)
	}
	if r.Answer[0].Header().Name != q || r.Question[0].Name != q {
		t.Fatalf("case not echoed: %q", r.Answer[0].Header().Name)
	}
	if txt := r.Answer[0].(*dns.TXT).Txt[0]; txt != val1 {
		t.Fatalf("TXT value %q", txt)
	}
	// The front door's challenge.
	if r := ask(t, addr, testZones.Gate+".", dns.TypeTXT); len(r.Answer) != 1 {
		t.Fatalf("gate TXT: %v", r)
	}

	// RFC 8020: names under the zone are never NXDOMAIN. CAs ask CAA at the
	// issuing name and climb; resolvers minimise QNAMEs. Both must see NOERROR.
	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{"photos." + penA + ".pens.hogman.network.", dns.TypeCAA},
		{penA + ".pens.hogman.network.", dns.TypeCAA},
		{"photos." + penA + ".pens.hogman.network.", dns.TypeA}, // never an address
		{"nothing-here." + penA + ".pens.hogman.network.", dns.TypeAAAA},
		{"_acme-challenge.none." + penA + ".pens.hogman.network.", dns.TypeTXT},
		{testZones.Gate + ".", dns.TypeA},
	} {
		r := ask(t, addr, tc.name, tc.qtype)
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || len(r.Ns) != 1 || r.Ns[0].Header().Rrtype != dns.TypeSOA {
			t.Errorf("%s %s: want NOERROR/NODATA with SOA, got rcode=%d answers=%d ns=%v",
				tc.name, dns.TypeToString[tc.qtype], r.Rcode, len(r.Answer), r.Ns)
		}
	}

	// Apex: SOA, NS and the CAA policy.
	if r := ask(t, addr, "pens.hogman.network.", dns.TypeNS); len(r.Answer) != 1 || r.Answer[0].(*dns.NS).Ns != "ns1.hogman.network." {
		t.Fatalf("NS: %v", r)
	}
	if r := ask(t, addr, "pens.hogman.network.", dns.TypeSOA); len(r.Answer) != 1 {
		t.Fatalf("SOA: %v", r)
	}
	r = ask(t, addr, "pens.hogman.network.", dns.TypeCAA)
	var caa []string
	for _, rr := range r.Answer {
		c := rr.(*dns.CAA)
		caa = append(caa, c.Tag+" "+c.Value)
	}
	want := "issue letsencrypt.org; validationmethods=dns-01|issue pki.goog; validationmethods=dns-01|issuewild ;"
	if strings.Join(caa, "|") != want {
		t.Fatalf("CAA: %q", caa)
	}

	// Outside our zones: refused.
	for _, n := range []string{"hogman.network.", "gate.hogman.network.", "www.google.com.", "evilpens.hogman.network."} {
		if r := ask(t, addr, n, dns.TypeA); r.Rcode != dns.RcodeRefused {
			t.Errorf("%s: rcode %d, want REFUSED", n, r.Rcode)
		}
	}
}

// --- API ---------------------------------------------------------------------

type eabFunc func() (string, string, error)

func (f eabFunc) Mint(context.Context) (string, string, error) { return f() }

func doAPI(t *testing.T, h http.Handler, method, path, tok string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAPIStatusCodes(t *testing.T) {
	s, _ := newTestStore(t)
	_, tokA := mustCred(t, s, "pen", penA)
	api := &API{store: s, global: &windowLimiter{perMin: 20, perHour: 90}}
	h := api.Handler()
	n := ch("photos", penA)
	for _, tc := range []struct {
		name, method, path, tok string
		body                    any
		want                    int
	}{
		{"no token", "POST", "/v1/txt", "", txtReq{n, val1}, 401},
		{"bad token", "POST", "/v1/txt", "hcd_nope", txtReq{n, val1}, 401},
		{"put", "POST", "/v1/txt", tokA, txtReq{n, val1}, 201},
		{"put again", "POST", "/v1/txt", tokA, txtReq{n, val1}, 201},
		{"other pen", "POST", "/v1/txt", tokA, txtReq{ch("photos", penB), val1}, 403},
		{"bad value", "POST", "/v1/txt", tokA, txtReq{n, "x"}, 400},
		{"unknown field", "POST", "/v1/txt", tokA, map[string]string{"fqdn": n, "value": val1, "type": "A"}, 400},
		{"delete", "DELETE", "/v1/txt", tokA, txtReq{n, val1}, 204},
		{"delete absent", "DELETE", "/v1/txt", tokA, txtReq{n, val1}, 204},
		{"delete other pen", "DELETE", "/v1/txt", tokA, txtReq{ch("x", penB), val1}, 403},
		{"eab unconfigured", "POST", "/v1/eab", tokA, nil, 503},
	} {
		if got := doAPI(t, h, tc.method, tc.path, tc.tok, tc.body).Code; got != tc.want {
			t.Errorf("%s: HTTP %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestAPIEABAllowances(t *testing.T) {
	s, _ := newTestStore(t)
	_, tokA := mustCred(t, s, "pen", penA)
	minted := 0
	api := &API{store: s, global: &windowLimiter{perMin: 20, perHour: 90},
		eab: eabFunc(func() (string, string, error) { minted++; return fmt.Sprintf("kid-%d", minted), "bWFjLWtleQ", nil })}
	h := api.Handler()
	for i := 0; i < eabPerDay; i++ {
		rec := doAPI(t, h, "POST", "/v1/eab", tokA, nil)
		if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"hmac_b64url":"bWFjLWtleQ"`) {
			t.Fatalf("mint %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := doAPI(t, h, "POST", "/v1/eab", tokA, nil); rec.Code != 429 {
		t.Fatalf("over the daily allowance: %d", rec.Code)
	}
}

func TestParseEABDoubleEncoding(t *testing.T) {
	// Google's b64MacKey is a protobuf bytes field holding the base64url text,
	// so the JSON carries base64(base64url(hmac)).
	inner := "c2VjcmV0LWhtYWMta2V5LWJ5dGVz" // what ACME wants
	body := fmt.Sprintf(`{"name":"projects/p/locations/global/externalAccountKeys/k","keyId":"kid123","b64MacKey":%q}`,
		base64.StdEncoding.EncodeToString([]byte(inner)))
	kid, hmac, err := parseEAB([]byte(body))
	if err != nil || kid != "kid123" || hmac != inner {
		t.Fatalf("parseEAB = %q, %q, %v; want kid123, %q", kid, hmac, err, inner)
	}
	if _, _, err := parseEAB([]byte(`{"keyId":"k"}`)); err == nil {
		t.Fatal("accepted a reply with no key")
	}
}

func TestWindowLimiter(t *testing.T) {
	l := &windowLimiter{perMin: 2, perHour: 3}
	now := time.Now()
	if !l.allow(now) || !l.allow(now) || l.allow(now) {
		t.Fatal("per-minute limit")
	}
	now = now.Add(2 * time.Minute)
	if !l.allow(now) || l.allow(now) {
		t.Fatal("per-hour limit")
	}
}

// D-21: a pen name is used once, ever. Removing a pen's credential forgets
// everything about it except that its name was used.
func TestPenNamesAreNeverReused(t *testing.T) {
	s, _ := newTestStore(t)
	c, _ := mustCred(t, s, "pen", penA)
	_ = s.PutTXT(c, ch("photos", penA), val1)
	if !s.NameUsed(penA) || s.NameUsed(penB) {
		t.Fatal("NameUsed wrong before removal")
	}
	if err := s.RemoveCred(c.ID); err != nil {
		t.Fatal(err)
	}
	if !s.NameUsed(strings.ToUpper(penA)) {
		t.Fatal("removing the pen freed its name")
	}
	if _, _, err := s.AddCred("pen", penA); err == nil {
		t.Fatal("a removed pen's name was given out again")
	}
	// Nothing else about the removed pen is kept: no credential, no cap
	// history, no fallback-key history.
	s2, err := OpenStore(s.path, testZones)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.st.Creds) != 0 || len(s2.st.Seen) != 0 || len(s2.st.EAB) != 0 || !s2.NameUsed(penA) {
		t.Fatalf("after removal and restart, kept: %+v", s2.st)
	}
}
