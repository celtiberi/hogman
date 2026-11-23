package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
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
	t0 := *now
	// Write defaultCapNames (20) distinct names across rolling 1-hour windows.
	for i := 0; i < defaultCapNames; i++ {
		if i > 0 && i%defaultHourlyCap == 0 {
			*now = now.Add(hourlyWindow)
		}
		if err := s.PutTXT(a, ch(fmt.Sprintf("site%d", i), penA), val1); err != nil {
			t.Fatalf("name %d: %v", i, err)
		}
	}
	err := s.PutTXT(a, ch("one-more", penA), val1)
	if !errors.Is(err, errCap) {
		t.Fatalf("%dth new name: %v, want errCap", defaultCapNames+1, err)
	}
	var rle *rateLimitError
	if !errors.As(err, &rle) || rle.retryAfter != t0.Add(capWindow).Sub(*now) {
		t.Fatalf("weekly Retry-After: err=%v, want %v", err, t0.Add(capWindow).Sub(*now))
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
	if err := s2.PutTXT(a, ch("one-more", penA), val1); !errors.Is(err, errCap) {
		t.Fatalf("after restart: %v, want errCap", err)
	}
	// A week after the first batch, those slots roll off.
	*now = t0.Add(capWindow)
	if err := s2.PutTXT(a, ch("one-more", penA), val1); err != nil {
		t.Fatalf("a week later: %v", err)
	}
}

func TestHourlyCapAndRollingWindow(t *testing.T) {
	s, now := newTestStore(t)
	a, _ := mustCred(t, s, "pen", penA)

	// First name at t=0; next 4 names at t=+10m.
	if err := s.PutTXT(a, ch("h0", penA), val1); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(10 * time.Minute)
	for i := 1; i < defaultHourlyCap; i++ {
		if err := s.PutTXT(a, ch(fmt.Sprintf("h%d", i), penA), val1); err != nil {
			t.Fatalf("name %d: %v", i, err)
		}
	}

	// At t=+15m, a 6th distinct name hits the per-pen hourly cap with 45m remaining.
	*now = now.Add(5 * time.Minute)
	err := s.PutTXT(a, ch("h-extra", penA), val1)
	if !errors.Is(err, errHourlyCap) {
		t.Fatalf("6th name in hour: %v, want errHourlyCap", err)
	}
	var rle *rateLimitError
	if !errors.As(err, &rle) || rle.retryAfter != 45*time.Minute {
		t.Fatalf("hourly Retry-After = %v, want 45m", rle)
	}

	// Retrying an already-seen name is still free while the hourly cap is full.
	if err := s.PutTXT(a, ch("h0", penA), val2); err != nil {
		t.Fatalf("retry seen name while hourly full: %v", err)
	}

	// Advance 45m (t=+60m): h0 leaves the 1h window (while remaining in the 7d window).
	*now = now.Add(45 * time.Minute)
	if err := s.PutTXT(a, ch("h-extra", penA), val1); err != nil {
		t.Fatalf("after 1h slot freed: %v", err)
	}
	// One more immediately hits hourly cap again, waiting 10m for h1..h4.
	err = s.PutTXT(a, ch("h-extra-2", penA), val1)
	if !errors.Is(err, errHourlyCap) {
		t.Fatalf("7th name: %v, want errHourlyCap", err)
	}
	if !errors.As(err, &rle) || rle.retryAfter != 10*time.Minute {
		t.Fatalf("second hourly Retry-After = %v, want 10m", rle)
	}
}

func TestGlobalHourlyCapAcrossPens(t *testing.T) {
	s, now := newTestStore(t)
	s.hourlyCapNames = 3
	s.capNames = 10
	s.globalHourlyCapNames = 4
	a, _ := mustCred(t, s, "pen", penA)
	b, _ := mustCred(t, s, "pen", penB)
	host, _ := mustCred(t, s, "host", "")

	// penA uses 3 names at t=0, +5m, +10m.
	for i := 0; i < 3; i++ {
		if err := s.PutTXT(a, ch(fmt.Sprintf("a%d", i), penA), val1); err != nil {
			t.Fatalf("penA %d: %v", i, err)
		}
		if i < 2 {
			*now = now.Add(5 * time.Minute)
		}
	}
	// penB uses 1 name at t=+15m -> succeeds (global = 4).
	*now = now.Add(5 * time.Minute)
	if err := s.PutTXT(b, ch("b0", penB), val1); err != nil {
		t.Fatalf("penB 0: %v", err)
	}
	// At t=+20m, penB's 2nd name hits the global hourly cap (40m until a0 rolls off).
	*now = now.Add(5 * time.Minute)
	err := s.PutTXT(b, ch("b1", penB), val1)
	if !errors.Is(err, errGlobalHourlyCap) {
		t.Fatalf("penB 1 under global cap: %v, want errGlobalHourlyCap", err)
	}
	var rle *rateLimitError
	if !errors.As(err, &rle) || rle.retryAfter != 40*time.Minute {
		t.Fatalf("global Retry-After = %v, want 40m", rle)
	}
	// Existing names and the host gate wildcard are unaffected by the global pen cap.
	if err := s.PutTXT(a, ch("a0", penA), val2); err != nil {
		t.Fatalf("penA retry while global full: %v", err)
	}
	if err := s.PutTXT(host, testZones.Gate, val1); err != nil {
		t.Fatalf("host gate TXT while global full: %v", err)
	}
	// At t=+60m, a0 rolls out of the global 1h window and penB succeeds.
	*now = now.Add(40 * time.Minute)
	if err := s.PutTXT(b, ch("b1", penB), val1); err != nil {
		t.Fatalf("penB 1 after global slot freed: %v", err)
	}
}

func TestGlobalSoftHardReservedQuietPenFloor(t *testing.T) {
	s, now := newTestStore(t)
	s.hourlyCapNames = 4
	s.capNames = 10
	s.globalHourlyCapNames = 4
	s.globalHardHourlyCapNames = 6
	a, _ := mustCred(t, s, "pen", penA)
	b, _ := mustCred(t, s, "pen", penB)
	c, _ := mustCred(t, s, "pen", "penc-quiet")
	d, _ := mustCred(t, s, "pen", "pend-quiet")

	// penA writes 2 names (t=0, +5m) and penB writes 2 names (+10m, +15m) -> global=4 (soft).
	if err := s.PutTXT(a, ch("a0", penA), val1); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(5 * time.Minute)
	if err := s.PutTXT(a, ch("a1", penA), val1); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(5 * time.Minute)
	if err := s.PutTXT(b, ch("b0", penB), val1); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(5 * time.Minute)
	if err := s.PutTXT(b, ch("b1", penB), val1); err != nil {
		t.Fatal(err)
	}

	// At t=+20m, bursty penA (penHourly=2 >= 2) is shed at the soft cap (40m until a0 rolls off).
	*now = now.Add(5 * time.Minute)
	err := s.PutTXT(a, ch("a2", penA), val1)
	if !errors.Is(err, errGlobalHourlyCap) {
		t.Fatalf("bursty penA above soft cap: %v, want errGlobalHourlyCap", err)
	}
	var rle *rateLimitError
	if !errors.As(err, &rle) || rle.retryAfter != 40*time.Minute {
		t.Fatalf("soft cap Retry-After = %v, want 40m", rle)
	}

	// Meanwhile, quiet/new penC (penHourly < 2) uses the reserved soft..hard headroom for its first 2 names.
	if err := s.PutTXT(c, ch("home", "penc-quiet"), val1); err != nil {
		t.Fatalf("quiet penC 1st name should use reserved headroom: %v", err)
	}
	if err := s.PutTXT(c, ch("vault", "penc-quiet"), val1); err != nil {
		t.Fatalf("quiet penC 2nd name should use reserved headroom: %v", err)
	}

	// Now global == hard (6): even quiet penD is stopped at the hard ceiling.
	err = s.PutTXT(d, ch("home", "pend-quiet"), val1)
	if !errors.Is(err, errGlobalHourlyCap) {
		t.Fatalf("penD at hard cap: %v, want errGlobalHourlyCap", err)
	}
	if !errors.As(err, &rle) || rle.retryAfter != 40*time.Minute {
		t.Fatalf("hard cap Retry-After = %v, want 40m", rle)
	}

	// At t=+60m, a0 rolls off (global=5, still >= soft=4): bursty penB stays shed,
	// while quiet penD immediately gets priority in the reserved headroom.
	*now = now.Add(40 * time.Minute)
	if err := s.PutTXT(b, ch("b2", penB), val1); !errors.Is(err, errGlobalHourlyCap) {
		t.Fatalf("bursty penB during recovery (global=5 >= soft=4): %v, want errGlobalHourlyCap", err)
	}
	if err := s.PutTXT(d, ch("home", "pend-quiet"), val1); err != nil {
		t.Fatalf("quiet penD should win priority during recovery: %v", err)
	}
}

func TestCapsOverrideAndParse(t *testing.T) {
	h, w, g, gh, err := parseCapsFromEnv("", "", "", "")
	if err != nil || h != defaultHourlyCap || w != defaultCapNames || g != defaultGlobalHourlyCap || gh != defaultGlobalHardHourlyCap {
		t.Fatalf("defaults = (%d,%d,%d,%d,%v), want (%d,%d,%d,%d,nil)",
			h, w, g, gh, err, defaultHourlyCap, defaultCapNames, defaultGlobalHourlyCap, defaultGlobalHardHourlyCap)
	}
	h, w, g, gh, err = parseCapsFromEnv("3", "12", "30", "45")
	if err != nil || h != 3 || w != 12 || g != 30 || gh != 45 {
		t.Fatalf("overrides = (%d,%d,%d,%d,%v), want (3,12,30,45,nil)", h, w, g, gh, err)
	}
	// Setting only CDNS_WEEKLY_CAP below the default hourly cap clamps hourly down cleanly.
	h, w, g, gh, err = parseCapsFromEnv("", "3", "", "")
	if err != nil || h != 3 || w != 3 || g != defaultGlobalHourlyCap || gh != defaultGlobalHardHourlyCap {
		t.Fatalf("weekly-only clamp = (%d,%d,%d,%d,%v), want (3,3,%d,%d,nil)",
			h, w, g, gh, err, defaultGlobalHourlyCap, defaultGlobalHardHourlyCap)
	}
	// Raising CDNS_GLOBAL_HOURLY_CAP above default hard cap without setting hard lifts hard to match.
	h, w, g, gh, err = parseCapsFromEnv("", "", "80", "")
	if err != nil || h != defaultHourlyCap || w != defaultCapNames || g != 80 || gh != 80 {
		t.Fatalf("soft-above-default-hard = (%d,%d,%d,%d,%v), want (5,20,80,80,nil)", h, w, g, gh, err)
	}
	for _, tc := range []struct {
		name, h, w, g, gh string
	}{
		{"hourly > weekly", "6", "5", "40", "60"},
		{"global < hourly", "5", "20", "4", "60"},
		{"hard < soft", "5", "20", "50", "40"},
		{"zero hourly", "0", "20", "40", "60"},
		{"neg weekly", "5", "-1", "40", "60"},
		{"huge weekly", "5", "1001", "40", "60"},
		{"bad global", "5", "20", "10001", "10001"},
		{"bad hard", "5", "20", "40", "10001"},
		{"non-int", "abc", "20", "40", "60"},
	} {
		if _, _, _, _, err := parseCapsFromEnv(tc.h, tc.w, tc.g, tc.gh); err == nil {
			t.Errorf("parseCapsFromEnv(%s: %q,%q,%q,%q) succeeded, want error", tc.name, tc.h, tc.w, tc.g, tc.gh)
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
	if err := s.PutTXT(a, ch("custom-third", penA), val1); !errors.Is(err, errCap) {
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

func TestAPIRateLimitRetryAfterHeader(t *testing.T) {
	s, now := newTestStore(t)
	s.hourlyCapNames = 2
	s.capNames = 4
	s.globalHourlyCapNames = 3
	_, tokA := mustCred(t, s, "pen", penA)
	_, tokB := mustCred(t, s, "pen", penB)
	api := &API{store: s, global: &windowLimiter{perMin: 20, perHour: 90}}
	h := api.Handler()

	// penA fills its hourly cap (2).
	for i := 0; i < 2; i++ {
		if rec := doAPI(t, h, "POST", "/v1/txt", tokA, txtReq{ch(fmt.Sprintf("p%d", i), penA), val1}); rec.Code != 201 {
			t.Fatalf("penA put %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	*now = now.Add(15 * time.Minute)
	// penA 3rd name -> hourly cap 429 + Retry-After: 2700 (45m).
	rec := doAPI(t, h, "POST", "/v1/txt", tokA, txtReq{ch("p-extra", penA), val1})
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), errHourlyCap.Error()) {
		t.Fatalf("hourly 429: code=%d body=%s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Retry-After"); got != "2700" {
		t.Fatalf("hourly Retry-After = %q, want 2700", got)
	}

	// penB writes 1 (global=3), then 2nd hits global hourly cap 429 + Retry-After: 2700.
	if rec := doAPI(t, h, "POST", "/v1/txt", tokB, txtReq{ch("b0", penB), val1}); rec.Code != 201 {
		t.Fatalf("penB put 0: %d %s", rec.Code, rec.Body)
	}
	rec = doAPI(t, h, "POST", "/v1/txt", tokB, txtReq{ch("b1", penB), val1})
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), errGlobalHourlyCap.Error()) {
		t.Fatalf("global 429: code=%d body=%s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Retry-After"); got != "2700" {
		t.Fatalf("global Retry-After = %q, want 2700", got)
	}

	// Advance 1h so penA can write 2 more (hitting weekly cap=4), then 5th hits weekly cap.
	*now = now.Add(hourlyWindow)
	for i := 2; i < 4; i++ {
		if rec := doAPI(t, h, "POST", "/v1/txt", tokA, txtReq{ch(fmt.Sprintf("p%d", i), penA), val1}); rec.Code != 201 {
			t.Fatalf("penA put %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	rec = doAPI(t, h, "POST", "/v1/txt", tokA, txtReq{ch("p4", penA), val1})
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), errCap.Error()) {
		t.Fatalf("weekly 429: code=%d body=%s", rec.Code, rec.Body)
	}
	secs, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || secs < int((6*24*time.Hour)/time.Second) {
		t.Fatalf("weekly Retry-After = %q (err=%v), want > 6 days", rec.Header().Get("Retry-After"), err)
	}
}

func TestAPIEABAllowances(t *testing.T) {
	s, now := newTestStore(t)
	s.hourlyCapNames = 2
	s.capNames = 4
	_, tokA := mustCred(t, s, "pen", penA)
	minted := 0
	api := &API{store: s, global: &windowLimiter{perMin: 20, perHour: 90},
		eab:     eabFunc(func() (string, string, error) { minted++; return fmt.Sprintf("kid-%d", minted), "bWFjLWtleQ", nil }),
		contact: "ops@example.com"}
	h := api.Handler()
	for i := 0; i < 2; i++ {
		rec := doAPI(t, h, "POST", "/v1/eab", tokA, nil)
		if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"hmac_b64url":"bWFjLWtleQ"`) || !strings.Contains(rec.Body.String(), `"contact":"ops@example.com"`) {
			t.Fatalf("mint %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	rec := doAPI(t, h, "POST", "/v1/eab", tokA, nil)
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), errEABHourlyCap.Error()) || rec.Header().Get("Retry-After") != "3600" {
		t.Fatalf("over hourly EAB allowance: code=%d retry=%q body=%s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}
	// After 1 hour, 2 more mints succeed, filling the 7-day allowance (4).
	*now = now.Add(hourlyWindow)
	for i := 0; i < 2; i++ {
		if rec := doAPI(t, h, "POST", "/v1/eab", tokA, nil); rec.Code != 201 {
			t.Fatalf("hour-2 mint %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	rec = doAPI(t, h, "POST", "/v1/eab", tokA, nil)
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), errEABWeeklyCap.Error()) {
		t.Fatalf("over weekly EAB allowance: code=%d body=%s", rec.Code, rec.Body)
	}
	secs, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || secs < int((6*24*time.Hour)/time.Second) {
		t.Fatalf("weekly EAB Retry-After = %q (err=%v), want > 6 days", rec.Header().Get("Retry-After"), err)
	}
	// A week later the first batch rolls off and minting works again.
	*now = now.Add(capWindow)
	if rec := doAPI(t, h, "POST", "/v1/eab", tokA, nil); rec.Code != 201 {
		t.Fatalf("after 7d window: %d %s", rec.Code, rec.Body)
	}
}

// Google refuses an ACME account without a contact, so without one configured
// no key is minted: a refused registration would waste it (and the allowance).
func TestAPIEABNeedsContact(t *testing.T) {
	s, _ := newTestStore(t)
	_, tokA := mustCred(t, s, "pen", penA)
	minted := 0
	api := &API{store: s, global: &windowLimiter{perMin: 20, perHour: 90},
		eab: eabFunc(func() (string, string, error) { minted++; return "kid", "bWFjLWtleQ", nil })}
	if rec := doAPI(t, api.Handler(), "POST", "/v1/eab", tokA, nil); rec.Code != 503 || minted != 0 {
		t.Fatalf("no contact: %d, minted %d; want 503 and nothing minted", rec.Code, minted)
	}
}

func TestParseContact(t *testing.T) {
	for _, ok := range []string{"", "ops@example.com", " hogman-network@proton.me "} {
		if _, err := parseContact(ok); err != nil {
			t.Fatalf("parseContact(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"not-an-email", "Ops <ops@example.com>", "a@b.com,c@d.com", "mailto:ops@example.com"} {
		if _, err := parseContact(bad); err == nil {
			t.Fatalf("parseContact(%q) succeeded, want error", bad)
		}
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

func TestPerPlanCertCapsAndQuietPenReservation(t *testing.T) {
	s, now := newTestStore(t)
	s.hourlyCapNames = 2
	s.capNames = 4
	s.workHourlyCapNames = 5
	s.workCapNames = 10
	s.globalHourlyCapNames = 6
	s.globalHardHourlyCapNames = 8

	cPers, _ := mustCred(t, s, "pen", penA)
	cWork, _, err := s.AddCredWithPlan("pen", penB, "work")
	if err != nil || cWork.Plan != "work" {
		t.Fatalf("AddCredWithPlan work: c=%+v err=%v", cWork, err)
	}
	cQuiet, _, err := s.AddCredWithPlan("pen", "carol", "")
	if err != nil || cQuiet.Plan != "" {
		t.Fatalf("AddCredWithPlan default: c=%+v err=%v", cQuiet, err)
	}
	if _, _, err := s.AddCredWithPlan("host", "", "work"); err == nil {
		t.Fatal("host cred accepted a plan")
	}
	if _, _, err := s.AddCredWithPlan("pen", "dave", "enterprise"); err == nil {
		t.Fatal("invalid plan accepted")
	}

	// Personal pen stops at 2/hour.
	for i := 0; i < 2; i++ {
		if err := s.PutTXT(cPers, ch(fmt.Sprintf("p%d", i), penA), val1); err != nil {
			t.Fatalf("personal put %d: %v", i, err)
		}
	}
	if err := s.PutTXT(cPers, ch("p2", penA), val1); !errors.Is(err, errHourlyCap) {
		t.Fatalf("personal 3rd put = %v, want errHourlyCap", err)
	}

	// Work pen exceeds personal cap (writes 4 names, reaching global soft=6: 2+4=6),
	// then 5th name hits global soft cap (6) because work pen is bursty (>=2 names/hr).
	for i := 0; i < 4; i++ {
		if err := s.PutTXT(cWork, ch(fmt.Sprintf("w%d", i), penB), val1); err != nil {
			t.Fatalf("work put %d: %v", i, err)
		}
	}
	if err := s.PutTXT(cWork, ch("w4", penB), val1); !errors.Is(err, errGlobalHourlyCap) {
		t.Fatalf("work 5th put at global soft=6 = %v, want errGlobalHourlyCap", err)
	}

	// Quiet pen (<2 names/hr) STILL gets reserved headroom between soft(6) and hard(8)!
	for i := 0; i < 2; i++ {
		if err := s.PutTXT(cQuiet, ch(fmt.Sprintf("q%d", i), "carol"), val1); err != nil {
			t.Fatalf("quiet pen put %d in reserved headroom: %v", i, err)
		}
	}

	// Advance 1 hour: Work pen can write up to 5/hour (its full hourly cap) and EAB honors work cap.
	*now = now.Add(hourlyWindow + time.Second)
	for i := 4; i < 9; i++ {
		if err := s.PutTXT(cWork, ch(fmt.Sprintf("w%d", i), penB), val1); err != nil {
			t.Fatalf("work hour-2 put %d: %v", i, err)
		}
	}
	if err := s.PutTXT(cWork, ch("w9", penB), val1); !errors.Is(err, errHourlyCap) {
		t.Fatalf("work 6th in hour 2 = %v, want errHourlyCap", err)
	}

	// Live upgrade of personal pen to work raises its hourly cap immediately and persists.
	*now = now.Add(hourlyWindow + time.Second)
	updated, err := s.SetCredPlan(penA, "work")
	if err != nil || updated.Plan != "work" {
		t.Fatalf("SetCredPlan upgrade: %+v %v", updated, err)
	}
	for i := 2; i < 6; i++ {
		if err := s.PutTXT(updated, ch(fmt.Sprintf("p%d", i), penA), val1); err != nil {
			t.Fatalf("upgraded pen put %d: %v", i, err)
		}
	}
	// Reload from disk and verify plan persisted.
	s2, err := OpenStore(s.path, testZones)
	if err != nil {
		t.Fatal(err)
	}
	var foundWork int
	for _, c := range s2.Creds() {
		if c.Plan == "work" {
			foundWork++
		}
	}
	if foundWork != 2 {
		t.Fatalf("persisted work creds = %d, want 2", foundWork)
	}

	// Admin HTTP API: PUT /admin/creds/{id}/plan downgrades penA back to personal.
	adm := AdminHandler(s)
	req := httptest.NewRequest("PUT", "/admin/creds/"+updated.ID+"/plan", strings.NewReader(`{"plan":"personal"}`))
	rec := httptest.NewRecorder()
	adm.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"plan":"personal"`) {
		t.Fatalf("PUT plan downgrade: %d %s", rec.Code, rec.Body)
	}
}

func TestParseWorkCapsFromEnv(t *testing.T) {
	if wh, ww, err := parseWorkCapsFromEnv("", "", 40); err != nil || wh != defaultWorkHourlyCap || ww != defaultWorkWeeklyCap {
		t.Fatalf("defaults = (%d, %d, %v)", wh, ww, err)
	}
	// Clamps default work hourly cap down to small globalHourly when unset (backwards compat for tests).
	if wh, ww, err := parseWorkCapsFromEnv("", "", 6); err != nil || wh != 6 || ww != defaultWorkWeeklyCap {
		t.Fatalf("clamped = (%d, %d, %v)", wh, ww, err)
	}
	if _, _, err := parseWorkCapsFromEnv("20", "10", 40); err == nil {
		t.Fatal("work hourly > work weekly accepted")
	}
	if _, _, err := parseWorkCapsFromEnv("50", "60", 40); err == nil {
		t.Fatal("work hourly > global hourly accepted")
	}
}
