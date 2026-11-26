package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestAuditRevokedCredPurgesLiveTXTAndRejectsCalls(t *testing.T) {
	s, _ := newTestStore(t)
	cA, _ := mustCred(t, s, "pen", penA)
	cB, _ := mustCred(t, s, "pen", penB)

	fqdnA := ch("web", penA)
	fqdnB := ch("web", penB)
	if err := s.PutTXT(cA, fqdnA, val1); err != nil {
		t.Fatalf("PutTXT penA: %v", err)
	}
	if err := s.PutTXT(cB, fqdnB, val2); err != nil {
		t.Fatalf("PutTXT penB: %v", err)
	}
	if got := s.TXT(fqdnA); len(got) != 1 {
		t.Fatalf("penA TXT before revoke = %v, want 1 entry", got)
	}

	if err := s.RemoveCred(cA.ID); err != nil {
		t.Fatalf("RemoveCred: %v", err)
	}
	if got := s.TXT(fqdnA); len(got) != 0 {
		t.Fatalf("penA live TXT not purged on RemoveCred: %v", got)
	}
	if got := s.TXT(fqdnB); len(got) != 1 {
		t.Fatalf("penB live TXT unexpectedly removed: %v", got)
	}
	if err := s.PutTXT(cA, fqdnA, val1); err != errRevoked {
		t.Fatalf("PutTXT with revoked cred = %v, want errRevoked", err)
	}
	if err := s.DeleteTXT(cA, fqdnA, val1); err != errRevoked {
		t.Fatalf("DeleteTXT with revoked cred = %v, want errRevoked", err)
	}
	if err := s.AllowEAB(cA); err != errRevoked {
		t.Fatalf("AllowEAB with revoked cred = %v, want errRevoked", err)
	}
}

func TestAuditPerCredEABCheckedBeforeGlobalAndHostExempt(t *testing.T) {
	s, _ := newTestStore(t)
	s.hourlyCapNames = 1
	s.capNames = 4
	_, tokA := mustCred(t, s, "pen", penA)
	_, tokB := mustCred(t, s, "pen", penB)
	_, tokHost := mustCred(t, s, "host", "")

	minted := 0
	api := &API{
		store:  s,
		global: &windowLimiter{perMin: 2, perHour: 2},
		eab: eabFunc(func() (string, string, error) {
			minted++
			return fmt.Sprintf("kid-%d", minted), "bWFjLWtleQ", nil
		}),
		contact: "ops@example.com",
	}
	h := api.Handler()

	// penA uses its 1/hr allowance (consuming 1 of 2 global slots).
	if rec := doAPI(t, h, "POST", "/v1/eab", tokA, nil); rec.Code != 201 {
		t.Fatalf("penA first mint: %d %s", rec.Code, rec.Body)
	}
	// penA hammers /v1/eab 10 times; per-cred ReserveEAB rejects before a.global.reserve(),
	// so the second global slot remains free for penB.
	for i := 0; i < 10; i++ {
		if rec := doAPI(t, h, "POST", "/v1/eab", tokA, nil); rec.Code != 429 {
			t.Fatalf("penA spam %d: %d, want 429", i, rec.Code)
		}
	}
	if rec := doAPI(t, h, "POST", "/v1/eab", tokB, nil); rec.Code != 201 {
		t.Fatalf("penB starved by penA's rejected requests: %d %s", rec.Code, rec.Body)
	}
	// Global pen bucket (2/min) is now full, yet host cred is exempt from it.
	if rec := doAPI(t, h, "POST", "/v1/eab", tokHost, nil); rec.Code != 201 {
		t.Fatalf("host cred blocked by pen global burst limiter: %d %s", rec.Code, rec.Body)
	}
}

func TestAuditDNSClampsEDNS0UDPSize(t *testing.T) {
	s, _ := newTestStore(t)
	srv := &DNS{store: s, zones: testZones, ns: "ns1.example.com", mbox: "hostmaster.example.com"}

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(ch("web", penA)), dns.TypeTXT)
	req.SetEdns0(4096, false)

	var got *dns.Msg
	w := &captureDNSWriter{onWrite: func(m *dns.Msg) { got = m }}
	srv.ServeDNS(w, req)
	if got == nil {
		t.Fatal("no DNS response")
	}
	opt := got.IsEdns0()
	if opt == nil {
		t.Fatal("expected EDNS0 OPT in response")
	}
	if opt.UDPSize() > 1232 {
		t.Fatalf("EDNS0 UDPSize = %d, want <= 1232", opt.UDPSize())
	}

	reqSmall := new(dns.Msg)
	reqSmall.SetQuestion(dns.Fqdn(ch("web", penA)), dns.TypeTXT)
	reqSmall.SetEdns0(64, false)
	got = nil
	srv.ServeDNS(w, reqSmall)
	if opt := got.IsEdns0(); opt == nil || opt.UDPSize() < dns.MinMsgSize {
		t.Fatalf("small EDNS0 UDPSize = %v, want >= %d", opt, dns.MinMsgSize)
	}
	if !strings.HasSuffix(got.Question[0].Name, ".") {
		t.Fatalf("unexpected question name %q", got.Question[0].Name)
	}
}

type captureDNSWriter struct {
	dns.ResponseWriter
	onWrite func(*dns.Msg)
}

func (c *captureDNSWriter) WriteMsg(m *dns.Msg) error {
	c.onWrite(m)
	return nil
}

func (c *captureDNSWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53000}
}
