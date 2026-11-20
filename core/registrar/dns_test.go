package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func buildDNSQuery(t *testing.T, id uint16, name string, qtype dnsmessage.Type, withEDNS bool, ednsVer uint8) []byte {
	t.Helper()
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatalf("NewName(%q): %v", name, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: qname, Type: qtype, Class: dnsmessage.ClassINET})
	if withEDNS {
		_ = b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		_ = rh.SetEDNS0(4096, 0, false)
		rh.TTL |= uint32(ednsVer) << 16
		_ = b.OPTResource(rh, dnsmessage.OPTResource{})
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatalf("buildDNSQuery: %v", err)
	}
	return raw
}

func parseDNSResp(t *testing.T, raw []byte) (dnsmessage.Header, []dnsmessage.Resource, []dnsmessage.Resource, *dnsmessage.ResourceHeader) {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(raw)
	if err != nil {
		t.Fatalf("Parser.Start: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("SkipAllQuestions: %v", err)
	}
	ans, err := p.AllAnswers()
	if err != nil {
		t.Fatalf("AllAnswers: %v", err)
	}
	auth, err := p.AllAuthorities()
	if err != nil {
		t.Fatalf("AllAuthorities: %v", err)
	}
	var optHdr *dnsmessage.ResourceHeader
	for {
		ah, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if ah.Type == dnsmessage.TypeOPT {
			cp := ah
			optHdr = &cp
		}
		if err := p.SkipAdditional(); err != nil {
			break
		}
	}
	return hdr, ans, auth, optHdr
}

func mustResolveA(t *testing.T, srv *DNSServer, fqdn string) string {
	t.Helper()
	req := buildDNSQuery(t, 1, fqdn, dnsmessage.TypeA, true, 0)
	resp, ok := srv.HandlePacket(req, false)
	if !ok {
		t.Fatalf("no DNS response for %s", fqdn)
	}
	hdr, ans, _, _ := parseDNSResp(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess || !hdr.Authoritative || len(ans) != 1 {
		t.Fatalf("%s: rcode=%v aa=%v len=%d", fqdn, hdr.RCode, hdr.Authoritative, len(ans))
	}
	a, ok := ans[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("%s: expected A record, got %T", fqdn, ans[0].Body)
	}
	return netip.AddrFrom4(a.A).String()
}

func TestDNSAuthoritativeAndRefused(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, srv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.20", "fd7a:115c:a1e0::20")
	if _, err := e.svc.Claim(Actor{Member: alice}, "alice", "alice", srv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(Actor{Member: alice}, "alice", "blog.alice", srv.ID); err != nil {
		t.Fatal(err)
	}

	dnsSrv, err := NewDNSServer(e.svc)
	if err != nil {
		t.Fatal(err)
	}

	// Core service A records.
	if got := mustResolveA(t, dnsSrv, "ns.bobo.hogman."); got != "100.64.0.1" {
		t.Fatalf("ns = %s want 100.64.0.1", got)
	}
	if got := mustResolveA(t, dnsSrv, "home.bobo.hogman."); got != "100.64.0.1" {
		t.Fatalf("home = %s want 100.64.0.1", got)
	}
	if got := mustResolveA(t, dnsSrv, "ca.bobo.hogman."); got != "100.64.0.2" {
		t.Fatalf("ca = %s want 100.64.0.2", got)
	}

	// Core service AAAA and HTTPS must return NOERROR (NODATA) + SOA, never NXDOMAIN.
	for _, tc := range []struct {
		name  string
		qtype dnsmessage.Type
	}{
		{"ca.bobo.hogman.", dnsmessage.TypeAAAA},
		{"home.bobo.hogman.", dnsmessage.Type(65)}, // HTTPS
		{"bobo.hogman.", dnsmessage.TypeA},         // Apex A
	} {
		resp, ok := dnsSrv.HandlePacket(buildDNSQuery(t, 2, tc.name, tc.qtype, true, 0), false)
		if !ok {
			t.Fatalf("no response for %s %v", tc.name, tc.qtype)
		}
		hdr, ans, auth, optHdr := parseDNSResp(t, resp)
		if hdr.RCode != dnsmessage.RCodeSuccess || !hdr.Authoritative || len(ans) != 0 || len(auth) != 1 || optHdr == nil {
			t.Fatalf("%s %v: want NOERROR NODATA+SOA+OPT, got rcode=%v aa=%v ans=%d auth=%d opt=%v",
				tc.name, tc.qtype, hdr.RCode, hdr.Authoritative, len(ans), len(auth), optHdr != nil)
		}
	}

	// Zone apex SOA and NS.
	for _, qt := range []dnsmessage.Type{dnsmessage.TypeSOA, dnsmessage.TypeNS} {
		resp, ok := dnsSrv.HandlePacket(buildDNSQuery(t, 3, "bobo.hogman.", qt, false, 0), false)
		if !ok {
			t.Fatalf("no apex %v response", qt)
		}
		hdr, ans, _, _ := parseDNSResp(t, resp)
		if hdr.RCode != dnsmessage.RCodeSuccess || len(ans) != 1 {
			t.Fatalf("apex %v: rcode=%v len=%d", qt, hdr.RCode, len(ans))
		}
	}

	// Mixed-case member A, subdomain A, and dual-stack AAAA.
	if got := mustResolveA(t, dnsSrv, "AlIcE.BoBo.HoGmAn."); got != "100.64.0.20" {
		t.Fatalf("alice mixed case = %s want 100.64.0.20", got)
	}
	if got := mustResolveA(t, dnsSrv, "blog.alice.bobo.hogman."); got != "100.64.0.20" {
		t.Fatalf("blog.alice = %s want 100.64.0.20", got)
	}
	resp, _ := dnsSrv.HandlePacket(buildDNSQuery(t, 4, "alice.bobo.hogman.", dnsmessage.TypeAAAA, true, 0), false)
	hdr, ans, _, _ := parseDNSResp(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess || len(ans) != 1 {
		t.Fatalf("alice AAAA: rcode=%v len=%d", hdr.RCode, len(ans))
	}
	aaaa := ans[0].Body.(*dnsmessage.AAAAResource)
	if netip.AddrFrom16(aaaa.AAAA).String() != "fd7a:115c:a1e0::20" {
		t.Fatalf("alice AAAA = %s", netip.AddrFrom16(aaaa.AAAA))
	}

	// Empty non-terminal returns NODATA when only child exists.
	_, err = e.st.db.Exec(`DELETE FROM names WHERE name = 'alice'`)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ = dnsSrv.HandlePacket(buildDNSQuery(t, 5, "alice.bobo.hogman.", dnsmessage.TypeA, false, 0), false)
	var auth []dnsmessage.Resource
	hdr, ans, auth, _ = parseDNSResp(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess || len(ans) != 0 || len(auth) != 1 {
		t.Fatalf("empty non-terminal: rcode=%v ans=%d auth=%d", hdr.RCode, len(ans), len(auth))
	}

	// Nonexistent name in-zone returns NXDOMAIN + SOA.
	resp, _ = dnsSrv.HandlePacket(buildDNSQuery(t, 6, "missing.bobo.hogman.", dnsmessage.TypeA, true, 0), false)
	hdr, ans, auth, _ = parseDNSResp(t, resp)
	if hdr.RCode != dnsmessage.RCodeNameError || !hdr.Authoritative || len(ans) != 0 || len(auth) != 1 {
		t.Fatalf("missing name: rcode=%v aa=%v ans=%d auth=%d", hdr.RCode, hdr.Authoritative, len(ans), len(auth))
	}

	// Outside-zone queries MUST return REFUSED with AA=0.
	for _, outName := range []string{"example.com.", "other.hogman.", "notbobo.hogman."} {
		resp, _ = dnsSrv.HandlePacket(buildDNSQuery(t, 7, outName, dnsmessage.TypeA, true, 0), false)
		hdr, ans, _, _ = parseDNSResp(t, resp)
		if hdr.RCode != dnsmessage.RCodeRefused || hdr.Authoritative || len(ans) != 0 {
			t.Fatalf("%s: want REFUSED AA=0, got rcode=%v aa=%v ans=%d", outName, hdr.RCode, hdr.Authoritative, len(ans))
		}
	}

	// Protocol error edge cases.
	resp, ok := dnsSrv.HandlePacket(buildDNSQuery(t, 8, "home.bobo.hogman.", dnsmessage.TypeA, true, 1), false)
	if !ok {
		t.Fatal("expected BADVERS response")
	}
	hdr, ans, _, optHdr := parseDNSResp(t, resp)
	if optHdr == nil || optHdr.ExtendedRCode(hdr.RCode) != dnsmessage.RCode(16) || len(ans) != 0 {
		t.Fatalf("expected BADVERS (extended RCODE 16), got opt=%+v baseRCode=%v ans=%d", optHdr, hdr.RCode, len(ans))
	}
	if _, ok := dnsSrv.HandlePacket([]byte{1, 2, 3}, false); ok {
		t.Fatal("expected short packet to be ignored")
	}
}

func TestDNSLiveCrossProcessAndKick(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	bob, err := e.svc.AddMember(ctx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, srv := e.addDevice(t, "bob", "server", "bob-srv", "100.64.0.30", "")
	dnsSrv, err := NewDNSServer(e.svc)
	if err != nil {
		t.Fatal(err)
	}

	// Separate Store handle on the same SQLite DB simulates `hogman name claim` CLI.
	stCLI, err := OpenStore(filepath.Join(e.dir, "registrar.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer stCLI.db.Close()
	svcCLI, err := NewService(e.svc.cfg, stCLI, e.svc.hs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svcCLI.Claim(Actor{CLI: true}, "bob", "radio", srv.ID); err != nil {
		t.Fatal(err)
	}
	if got := mustResolveA(t, dnsSrv, "radio.bobo.hogman."); got != "100.64.0.30" {
		t.Fatalf("live cross-store claim: radio = %s want 100.64.0.30", got)
	}
	_ = bob

	if _, err := e.svc.Kick(ctx, cli, "bob", "bye"); err != nil {
		t.Fatal(err)
	}
	resp, _ := dnsSrv.HandlePacket(buildDNSQuery(t, 9, "radio.bobo.hogman.", dnsmessage.TypeA, false, 0), false)
	hdr, _, _, _ := parseDNSResp(t, resp)
	if hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("after kick: want NXDOMAIN, got %v", hdr.RCode)
	}
}

func TestDNSUDPAndTCPRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	dnsSrv, err := NewDNSServer(e.svc)
	if err != nil {
		t.Fatal(err)
	}

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()

	go dnsSrv.serveUDP(udpConn)
	go dnsSrv.serveTCP(tcpLn)

	// UDP query via Go net.Resolver.
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", udpConn.LocalAddr().String())
		},
	}
	addrs, err := r.LookupHost(context.Background(), "home.bobo.hogman")
	if err != nil || len(addrs) != 1 || addrs[0] != "100.64.0.1" {
		t.Fatalf("UDP LookupHost(home.bobo.hogman) = %v, %v", addrs, err)
	}

	// Concurrent TCP queries with 2-byte framing.
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			conn, err := net.Dial("tcp", tcpLn.Addr().String())
			if err != nil {
				t.Errorf("tcp dial: %v", err)
				return
			}
			defer conn.Close()
			req := buildDNSQuery(t, id, "ca.bobo.hogman.", dnsmessage.TypeA, true, 0)
			frame := make([]byte, 2+len(req))
			binary.BigEndian.PutUint16(frame[:2], uint16(len(req)))
			copy(frame[2:], req)
			if _, err := conn.Write(frame); err != nil {
				t.Errorf("tcp write: %v", err)
				return
			}
			var lb [2]byte
			if _, err := io.ReadFull(conn, lb[:]); err != nil {
				t.Errorf("tcp read len: %v", err)
				return
			}
			n := int(binary.BigEndian.Uint16(lb[:]))
			resp := make([]byte, n)
			if _, err := io.ReadFull(conn, resp); err != nil {
				t.Errorf("tcp read body: %v", err)
				return
			}
			hdr, ans, _, _ := parseDNSResp(t, resp)
			if hdr.RCode != dnsmessage.RCodeSuccess || len(ans) != 1 {
				t.Errorf("tcp resp: rcode=%v len=%d", hdr.RCode, len(ans))
			}
		}(uint16(100 + i))
	}
	wg.Wait()
}
