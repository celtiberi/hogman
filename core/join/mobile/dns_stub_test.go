package mobile

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func packQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return b
}

func TestSplitDNSStubFiltersNonPeerAndAAAAForPenZone(t *testing.T) {
	stub := NewSplitDNSStub("bobo.pens.example.com", nil)
	penDNS := netip.MustParseAddr("100.64.0.1")
	peerIP := netip.MustParseAddr("100.64.0.9")
	stub.UpdatePen(penDNS, map[netip.Addr]bool{
		penDNS: true,
		peerIP: true,
	})
	stub.UpdateUpstream([]netip.Addr{netip.MustParseAddr("1.1.1.1"), SplitDNSStubIP})

	penCalls := 0
	upstreamCalls := 0

	stub.forwardPen = func(_ context.Context, raw []byte, server netip.Addr) ([]byte, error) {
		penCalls++
		if server != penDNS {
			t.Errorf("forwardPen server = %v, want %v", server, penDNS)
		}
		var req dns.Msg
		_ = req.Unpack(raw)
		resp := new(dns.Msg)
		resp.SetReply(&req)
		resp.Answer = []dns.RR{
			// Legitimate netmap peer (must be KEPT)
			&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("100.64.0.9")},
			// Spoofed public IP (must be DROPPED)
			&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("8.8.8.8")},
			// Spoofed LAN IP (must be DROPPED)
			&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.168.1.50")},
			// Non-peer CGNAT IP (must be DROPPED)
			&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("100.64.99.99")},
			// IPv6 AAAA record (must be DROPPED)
			&dns.AAAA{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("fd7a:115c:a1e0::9")},
		}
		return resp.Pack()
	}

	stub.forwardUpstream = func(_ context.Context, raw []byte, servers []netip.Addr) ([]byte, error) {
		upstreamCalls++
		for _, s := range servers {
			if s == SplitDNSStubIP {
				t.Errorf("upstream list must never contain SplitDNSStubIP")
			}
		}
		var req dns.Msg
		_ = req.Unpack(raw)
		resp := new(dns.Msg)
		resp.SetReply(&req)
		resp.Answer = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("93.184.216.34")},
		}
		return resp.Pack()
	}

	// 1. Pen A query: only netmap peer 100.64.0.9 survives.
	out, err := stub.ResolveWire(context.Background(), packQuery(t, "photos.bobo.pens.example.com", dns.TypeA))
	if err != nil {
		t.Fatalf("ResolveWire(pen A): %v", err)
	}
	var resp dns.Msg
	if err := resp.Unpack(out); err != nil {
		t.Fatalf("Unpack pen A: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("filtered Answer count = %d, want 1 (%v)", len(resp.Answer), resp.Answer)
	}
	aRec, ok := resp.Answer[0].(*dns.A)
	if !ok || aRec.A.String() != "100.64.0.9" {
		t.Fatalf("unexpected surviving record: %v", resp.Answer[0])
	}
	if penCalls != 1 || upstreamCalls != 0 {
		t.Fatalf("calls = (pen:%d, upstream:%d), want (1, 0)", penCalls, upstreamCalls)
	}

	// 2. Pen AAAA query: answered locally with NOERROR empty answer (no wire query).
	outAAAA, err := stub.ResolveWire(context.Background(), packQuery(t, "photos.bobo.pens.example.com", dns.TypeAAAA))
	if err != nil {
		t.Fatalf("ResolveWire(pen AAAA): %v", err)
	}
	var respAAAA dns.Msg
	_ = respAAAA.Unpack(outAAAA)
	if respAAAA.Rcode != dns.RcodeSuccess || len(respAAAA.Answer) != 0 {
		t.Fatalf("pen AAAA = (rcode=%d, answers=%d), want NOERROR empty", respAAAA.Rcode, len(respAAAA.Answer))
	}
	if penCalls != 1 {
		t.Fatalf("pen AAAA should not invoke forwardPen (penCalls=%d)", penCalls)
	}

	// 3. Lookalike suffix ("evil-bobo.pens.example.com") and public domain go ONLY to upstream.
	for _, host := range []string{"example.com", "evil-bobo.pens.example.com"} {
		outPub, err := stub.ResolveWire(context.Background(), packQuery(t, host, dns.TypeA))
		if err != nil {
			t.Fatalf("ResolveWire(%s): %v", host, err)
		}
		var respPub dns.Msg
		_ = respPub.Unpack(outPub)
		if len(respPub.Answer) != 1 {
			t.Fatalf("upstream %s answers = %d, want 1", host, len(respPub.Answer))
		}
	}
	if penCalls != 1 || upstreamCalls != 2 {
		t.Fatalf("calls after public queries = (pen:%d, upstream:%d), want (1, 2)", penCalls, upstreamCalls)
	}
}
