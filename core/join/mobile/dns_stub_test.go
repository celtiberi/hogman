package mobile

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
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

func TestSplitDNSStubStrictAllowlistBlocksBypassRecords(t *testing.T) {
	stub := NewSplitDNSStub("bobo.pens.example.com", nil)
	selfIP := netip.MustParseAddr("100.64.0.12")
	penDNS := netip.MustParseAddr("100.64.0.1")
	peerIP := netip.MustParseAddr("100.64.0.9")
	stub.UpdatePen(selfIP, penDNS, map[netip.Addr]bool{
		penDNS: true,
		peerIP: true,
	}, true)
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
		qname := req.Question[0].Name
		resp := new(dns.Msg)
		resp.SetReply(&req)
		resp.Answer = []dns.RR{
			// Legitimate netmap peer for exact QNAME (must be KEPT)
			&dns.A{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("100.64.0.9")},
			// Mismatched owner name pointing at a real peer (must be DROPPED)
			&dns.A{Hdr: dns.RR_Header{Name: "other.bobo.pens.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("100.64.0.1")},
			// Spoofed public IP (must be DROPPED)
			&dns.A{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("8.8.8.8")},
			// Spoofed LAN IP (must be DROPPED)
			&dns.A{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.168.1.50")},
			// Non-peer CGNAT IP (must be DROPPED)
			&dns.A{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("100.64.99.99")},
			// IPv6 AAAA record (must be DROPPED)
			&dns.AAAA{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("fd7a:115c:a1e0::9")},
			// CNAME off-mesh redirect (must be DROPPED)
			&dns.CNAME{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "attacker.example.net."},
			// DNAME redirect (must be DROPPED)
			&dns.DNAME{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 60}, Target: "attacker.example.net."},
			// HTTPS record with off-mesh ipv4hint (must be DROPPED)
			&dns.HTTPS{
				SVCB: dns.SVCB{
					Hdr:      dns.RR_Header{Name: qname, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
					Priority: 1,
					Target:   ".",
					Value:    []dns.SVCBKeyValue{&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("93.184.216.34")}}},
				},
			},
			// SVCB record (must be DROPPED)
			&dns.SVCB{
				Hdr:      dns.RR_Header{Name: qname, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
				Priority: 1,
				Target:   "attacker.example.net.",
			},
		}
		// Authority and Additional sections must be cleared completely.
		resp.Ns = []dns.RR{
			&dns.NS{Hdr: dns.RR_Header{Name: "bobo.pens.example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.attacker.example.net."},
		}
		resp.Extra = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "ns.attacker.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("93.184.216.34")},
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

	// 1. Pen A query: ONLY exact-QNAME live-peer A record 100.64.0.9 survives; Ns/Extra cleared.
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
	if len(resp.Ns) != 0 || len(resp.Extra) != 0 {
		t.Fatalf("expected empty Ns/Extra, got Ns=%d Extra=%d", len(resp.Ns), len(resp.Extra))
	}
	if penCalls != 1 || upstreamCalls != 0 {
		t.Fatalf("calls = (pen:%d, upstream:%d), want (1, 0)", penCalls, upstreamCalls)
	}

	// 2. Every non-A Qtype for a pen name returns empty NOERROR locally without forwarding.
	for _, qt := range []uint16{
		dns.TypeAAAA,
		dns.TypeCNAME,
		dns.TypeDNAME,
		dns.TypeHTTPS,
		dns.TypeSVCB,
		dns.TypeTXT,
		dns.TypeSRV,
		dns.TypeANY,
	} {
		rawOut, err := stub.ResolveWire(context.Background(), packQuery(t, "photos.bobo.pens.example.com", qt))
		if err != nil {
			t.Fatalf("ResolveWire(qtype=%d): %v", qt, err)
		}
		var r dns.Msg
		if err := r.Unpack(rawOut); err != nil {
			t.Fatalf("Unpack(qtype=%d): %v", qt, err)
		}
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || len(r.Ns) != 0 || len(r.Extra) != 0 {
			t.Fatalf("qtype=%d returned rcode=%d ans=%d ns=%d extra=%d, want empty NOERROR",
				qt, r.Rcode, len(r.Answer), len(r.Ns), len(r.Extra))
		}
	}
	if penCalls != 1 {
		t.Fatalf("non-A pen queries must never invoke forwardPen (penCalls=%d)", penCalls)
	}

	// 3. Lookalike suffix and public domain go ONLY to upstream.
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

	// 4. Self-hosted login/control host inside or at apex of zone must resolve via upstream.
	stub.SetLoginHost("join.bobo.pens.example.com")
	if stub.InZone("join.bobo.pens.example.com") {
		t.Fatal("loginHost must be exempted from pen-internal DNS")
	}
	outLogin, err := stub.ResolveWire(context.Background(), packQuery(t, "join.bobo.pens.example.com", dns.TypeA))
	if err != nil {
		t.Fatalf("ResolveWire(loginHost): %v", err)
	}
	var respLogin dns.Msg
	_ = respLogin.Unpack(outLogin)
	if len(respLogin.Answer) != 1 || upstreamCalls != 3 || penCalls != 1 {
		t.Fatalf("loginHost routed wrongly: answers=%d pen=%d upstream=%d", len(respLogin.Answer), penCalls, upstreamCalls)
	}
}

func TestSplitDNSStubFailsClosedUntilRoutesConfirmed(t *testing.T) {
	stub := NewSplitDNSStub("bobo.pens.example.com", nil)
	selfIP := netip.MustParseAddr("100.64.0.12")
	penDNS := netip.MustParseAddr("100.64.0.1")
	stub.UpdatePen(selfIP, penDNS, map[netip.Addr]bool{penDNS: true}, false)

	called := false
	stub.forwardPen = func(_ context.Context, _ []byte, _ netip.Addr) ([]byte, error) {
		called = true
		return nil, nil
	}

	out, err := stub.ResolveWire(context.Background(), packQuery(t, "home.bobo.pens.example.com", dns.TypeA))
	if err != nil {
		t.Fatalf("ResolveWire unconfirmed: %v", err)
	}
	var resp dns.Msg
	_ = resp.Unpack(out)
	if resp.Rcode != dns.RcodeServerFailure || called {
		t.Fatalf("expected SERVFAIL without forwarding when routes unconfirmed, got rcode=%d called=%v", resp.Rcode, called)
	}

	// defaultForwardPen itself also refuses when no tunnel is attached or routes are unconfirmed.
	if _, err := stub.defaultForwardPen(context.Background(), packQuery(t, "home.bobo.pens.example.com", dns.TypeA), penDNS); err == nil {
		t.Fatal("expected defaultForwardPen to fail closed without confirmed tunnel")
	}
}

func TestSplitDNSStubHandleInboundPacketMatchesTXIDAndPeer(t *testing.T) {
	stub := NewSplitDNSStub("bobo.pens.example.com", nil)
	selfIP := netip.MustParseAddr("100.64.0.12")
	penDNS := netip.MustParseAddr("100.64.0.1")
	stub.UpdatePen(selfIP, penDNS, map[netip.Addr]bool{penDNS: true}, true)

	req := packQuery(t, "home.bobo.pens.example.com", dns.TypeA)
	txid := binary.BigEndian.Uint16(req[:2])
	port, ch, err := stub.allocPendingPort(txid, penDNS)
	if err != nil {
		t.Fatalf("allocPendingPort: %v", err)
	}
	defer stub.releasePendingPort(port)

	parseRaw := func(srcIP netip.Addr, dstPort uint16, payload []byte) *packet.Parsed {
		raw := packet.Generate(packet.UDP4Header{
			IP4Header: packet.IP4Header{
				IPProto: ipproto.UDP,
				Src:     srcIP,
				Dst:     selfIP,
			},
			SrcPort: 53,
			DstPort: dstPort,
		}, payload)
		var p packet.Parsed
		p.Decode(raw)
		return &p
	}

	// Wrong source IP must NOT match or consume the waiter.
	if stub.HandleInboundPacket(parseRaw(netip.MustParseAddr("100.64.0.99"), port, req)) {
		t.Fatal("spoofed source IP must not match pending pen DNS waiter")
	}

	// Wrong TXID must NOT match.
	badTX := append([]byte(nil), req...)
	badTX[0] ^= 0xff
	if stub.HandleInboundPacket(parseRaw(penDNS, port, badTX)) {
		t.Fatal("mismatched TXID must not match pending pen DNS waiter")
	}

	// Matching penDNS + port + TXID is captured and delivered.
	if !stub.HandleInboundPacket(parseRaw(penDNS, port, req)) {
		t.Fatal("expected legitimate pen DNS reply to be captured")
	}
	select {
	case got := <-ch:
		if len(got) != len(req) {
			t.Fatalf("captured payload len = %d, want %d", len(got), len(req))
		}
	default:
		t.Fatal("expected captured DNS reply on channel")
	}
}
