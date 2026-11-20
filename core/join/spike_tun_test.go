package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

func TestSpikeSynthPoolAndDNS(t *testing.T) {
	subnet, localIP, dnsIP, pool, err := parseSpikeSubnet("")
	if err != nil {
		t.Fatal(err)
	}
	if localIP != netip.MustParseAddr("198.19.0.1") || dnsIP != netip.MustParseAddr("198.19.0.53") {
		t.Fatalf("unexpected local=%s dns=%s", localIP, dnsIP)
	}

	a1, err := pool.alloc("bobo.hogman", "100.64.0.1")
	if err != nil || !subnet.Contains(a1) || a1 != netip.MustParseAddr("198.19.1.1") {
		t.Fatalf("alloc bobo home: ip=%s err=%v", a1, err)
	}
	a1Again, err := pool.alloc("bobo.hogman", "100.64.0.1")
	if err != nil || a1Again != a1 {
		t.Fatalf("expected deterministic reuse, got %s vs %s (err=%v)", a1Again, a1, err)
	}
	a2, err := pool.alloc("zebra.hogman", "100.64.0.1")
	if err != nil || a2 == a1 || !subnet.Contains(a2) {
		t.Fatalf("expected distinct synthetic IP across pens for identical mesh IP, got %s vs %s (err=%v)", a2, a1, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Exercise .nodes.<zone> peerLookup fallback on spikePen.
	pen := &spikePen{
		cfg: &agentConfig{Zone: "bobo.hogman", DNSServer: "100.64.0.2"},
		up:  true,
		resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return nil, &net.DNSError{IsNotFound: true}
		}},
		peerLookup: func(ctx context.Context, host string) ([]string, error) {
			return peerIPsForHost(&ipnstate.Status{
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					key.NewNode().Public(): {
						DNSName:      "laptop.nodes.bobo.hogman.",
						TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.44")},
					},
				},
			}, host), nil
		},
		cache: map[string]cachedLookup{},
	}
	if got, up, err := pen.resolveHost(ctx, "laptop.nodes.bobo.hogman"); err != nil || !up || len(got) != 1 || got[0] != "100.64.0.44" {
		t.Fatalf(".nodes fallback resolveHost: got=%v up=%v err=%v", got, up, err)
	}

	b, err := newSpikeBridge(
		ctx, dnsIP, subnet.Bits(), pool, []string{"bobo.hogman", "zebra.hogman"},
		func(_ context.Context, zone, host string) ([]string, bool, error) {
			switch {
			case zone == "bobo.hogman" && host == "home.bobo.hogman":
				return []string{"100.64.0.1"}, true, nil
			case zone == "bobo.hogman" && host == "srv.bobo.hogman":
				return []string{"100.64.0.11"}, true, nil
			case zone == "zebra.hogman" && host == "booting.zebra.hogman":
				return nil, false, errors.New("not ready")
			default:
				return nil, true, &net.DNSError{IsNotFound: true}
			}
		},
		func(_ context.Context, _, _, _ string) (net.Conn, error) {
			return nil, errors.New("unused")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()

	packQ := func(name string, qtype dnsmessage.Type) []byte {
		t.Helper()
		qname, err := dnsmessage.NewName(name)
		if err != nil {
			t.Fatal(err)
		}
		mb := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, RecursionDesired: true})
		_ = mb.StartQuestions()
		_ = mb.Question(dnsmessage.Question{Name: qname, Type: qtype, Class: dnsmessage.ClassINET})
		raw, err := mb.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	unpack := func(raw []byte) dnsmessage.Message {
		t.Helper()
		var m dnsmessage.Message
		if err := m.Unpack(raw); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		return m
	}

	// Known A record.
	mA := unpack(b.handleSpikeDNS(ctx, packQ("home.bobo.hogman.", dnsmessage.TypeA)))
	if mA.RCode != dnsmessage.RCodeSuccess || len(mA.Answers) != 1 {
		t.Fatalf("A home.bobo.hogman: rcode=%v ans=%d", mA.RCode, len(mA.Answers))
	}
	if ip := netip.AddrFrom4(mA.Answers[0].Body.(*dnsmessage.AResource).A); ip != netip.MustParseAddr("198.19.1.1") {
		t.Fatalf("A home.bobo.hogman = %s want 198.19.1.1", ip)
	}

	// Known host AAAA and HTTPS (65) -> NOERROR with 0 answers (NODATA).
	for _, qt := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.Type(65)} {
		m := unpack(b.handleSpikeDNS(ctx, packQ("home.bobo.hogman.", qt)))
		if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
			t.Fatalf("type %v home.bobo.hogman: rcode=%v ans=%d", qt, m.RCode, len(m.Answers))
		}
	}

	// Missing in-zone name -> NXDOMAIN.
	mMissing := unpack(b.handleSpikeDNS(ctx, packQ("missing.bobo.hogman.", dnsmessage.TypeA)))
	if mMissing.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("missing name rcode=%v want NXDOMAIN", mMissing.RCode)
	}

	// Out-of-zone name -> REFUSED.
	mOut := unpack(b.handleSpikeDNS(ctx, packQ("example.com.", dnsmessage.TypeA)))
	if mOut.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("out-of-zone rcode=%v want REFUSED", mOut.RCode)
	}

	// Pen still connecting -> SERVFAIL (do not negative-cache NXDOMAIN).
	mBoot := unpack(b.handleSpikeDNS(ctx, packQ("booting.zebra.hogman.", dnsmessage.TypeA)))
	if mBoot.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("connecting pen rcode=%v want SERVFAIL", mBoot.RCode)
	}
}

func TestSpikeNetstackRoundTripTCPUDPAndDNS(t *testing.T) {
	subnet, localIP, dnsIP, pool, err := parseSpikeSubnet("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Spin up real loopback TCP + UDP servers (supporting full TCP half-close unlike net.Pipe).
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				b, _ := io.ReadAll(conn)
				_, _ = conn.Write(append([]byte("tcp:"), b...))
			}(c)
		}
	}()

	udpPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpPC.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udpPC.ReadFrom(buf)
			if n > 0 {
				_, _ = udpPC.WriteTo(append([]byte("udp:"), buf[:n]...), addr)
			}
			if err != nil {
				return
			}
		}
	}()

	// Build bridge backed by those local TCP and UDP servers.
	bridge, err := newSpikeBridge(
		ctx, dnsIP, subnet.Bits(), pool, []string{"bobo.hogman"},
		func(_ context.Context, zone, host string) ([]string, bool, error) {
			switch host {
			case "home.bobo.hogman":
				return []string{"100.64.0.1"}, true, nil
			case "srv.bobo.hogman":
				return []string{"100.64.0.11"}, true, nil
			default:
				return nil, true, &net.DNSError{IsNotFound: true}
			}
		},
		func(_ context.Context, zone, network, addr string) (net.Conn, error) {
			if zone != "bobo.hogman" {
				return nil, errors.New("wrong zone")
			}
			switch {
			case network == "tcp" && addr == "100.64.0.1:2222":
				return net.Dial("tcp", tcpLn.Addr().String())
			case network == "udp" && addr == "100.64.0.11:9999":
				return net.Dial("udp", udpPC.LocalAddr().String())
			default:
				return nil, errors.New("connection refused")
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()

	// Create a synthetic client gVisor stack connected back-to-back with bridge.
	clientEP := channel.New(512, spikeMTU, "")
	clientStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if tErr := clientStack.CreateNIC(1, clientEP); tErr != nil {
		t.Fatalf("client CreateNIC: %v", tErr)
	}
	clientAddr := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4(localIP.As4()), PrefixLen: 16}
	if tErr := clientStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: clientAddr,
	}, stack.AddressProperties{}); tErr != nil {
		t.Fatalf("client AddProtocolAddress: %v", tErr)
	}
	defV4, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	clientStack.SetRouteTable([]tcpip.Route{{Destination: defV4, NIC: 1}})
	defer func() {
		clientEP.Close()
		clientStack.Close()
		clientStack.Wait()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(from, to *channel.Endpoint) {
		defer wg.Done()
		for {
			pkt := from.ReadContext(ctx)
			if pkt == nil {
				return
			}
			raw := make([]byte, pkt.Size())
			n := copy(raw, pkt.NetworkHeader().Slice())
			n += copy(raw[n:], pkt.TransportHeader().Slice())
			n += copy(raw[n:], pkt.Data().AsRange().ToSlice())
			pkt.DecRef()
			in := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(raw[:n]),
			})
			to.InjectInbound(header.IPv4ProtocolNumber, in)
			in.DecRef()
		}
	}
	go pump(clientEP, bridge.ep)
	go pump(bridge.ep, clientEP)

	// 1. UDP DNS query over netstack -> synthetic IP.
	queryDNSUDP := func(name string) netip.Addr {
		t.Helper()
		c, err := gonet.DialUDP(clientStack, nil, &tcpip.FullAddress{
			NIC: 1, Addr: tcpip.AddrFrom4(dnsIP.As4()), Port: 53,
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("DialUDP DNS: %v", err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		qn, _ := dnsmessage.NewName(name)
		mb := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
		_ = mb.StartQuestions()
		_ = mb.Question(dnsmessage.Question{Name: qn, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		rawQ, _ := mb.Finish()
		if _, err := c.Write(rawQ); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, 512)
		n, err := c.Read(resp)
		if err != nil {
			t.Fatalf("Read DNS UDP: %v", err)
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(resp[:n]); err != nil || len(msg.Answers) != 1 {
			t.Fatalf("unpack DNS resp: %+v err=%v", msg, err)
		}
		return netip.AddrFrom4(msg.Answers[0].Body.(*dnsmessage.AResource).A)
	}

	homeIP := queryDNSUDP("home.bobo.hogman.")
	if homeIP != netip.MustParseAddr("198.19.1.1") {
		t.Fatalf("home.bobo.hogman resolved to %s", homeIP)
	}

	// 2. TCP DNS query over netstack -> srv.bobo.hogman.
	tcpDNSConn, err := gonet.DialTCP(clientStack, tcpip.FullAddress{
		NIC: 1, Addr: tcpip.AddrFrom4(dnsIP.As4()), Port: 53,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialTCP DNS: %v", err)
	}
	_ = tcpDNSConn.SetDeadline(time.Now().Add(3 * time.Second))
	qn, _ := dnsmessage.NewName("srv.bobo.hogman.")
	mb := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 8, RecursionDesired: true})
	_ = mb.StartQuestions()
	_ = mb.Question(dnsmessage.Question{Name: qn, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	rawQ, _ := mb.Finish()
	framed := make([]byte, 2+len(rawQ))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(rawQ)))
	copy(framed[2:], rawQ)
	if _, err := tcpDNSConn.Write(framed); err != nil {
		t.Fatal(err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(tcpDNSConn, lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	respTCP := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(tcpDNSConn, respTCP); err != nil {
		t.Fatal(err)
	}
	_ = tcpDNSConn.Close()
	var tcpMsg dnsmessage.Message
	if err := tcpMsg.Unpack(respTCP); err != nil || len(tcpMsg.Answers) != 1 {
		t.Fatalf("TCP DNS unpack: %+v err=%v", tcpMsg, err)
	}
	srvIP := netip.AddrFrom4(tcpMsg.Answers[0].Body.(*dnsmessage.AResource).A)
	if srvIP != netip.MustParseAddr("198.19.1.2") {
		t.Fatalf("srv.bobo.hogman resolved to %s", srvIP)
	}

	// 3. TCP round-trip + half-close through bridge to mock dialFn.
	tcpConn, err := gonet.DialTCP(clientStack, tcpip.FullAddress{
		NIC: 1, Addr: tcpip.AddrFrom4(homeIP.As4()), Port: 2222,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialTCP service: %v", err)
	}
	_ = tcpConn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := tcpConn.Write([]byte("hello-pen")); err != nil {
		t.Fatal(err)
	}
	_ = tcpConn.CloseWrite()
	gotTCP, err := io.ReadAll(tcpConn)
	_ = tcpConn.Close()
	if err != nil || string(gotTCP) != "tcp:hello-pen" {
		t.Fatalf("TCP echo got=%q err=%v", string(gotTCP), err)
	}

	// 4. UDP round-trip through bridge to mock dialFn.
	udpConn, err := gonet.DialUDP(clientStack, nil, &tcpip.FullAddress{
		NIC: 1, Addr: tcpip.AddrFrom4(srvIP.As4()), Port: 9999,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP service: %v", err)
	}
	_ = udpConn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := udpConn.Write([]byte("ping-dgram")); err != nil {
		t.Fatal(err)
	}
	uBuf := make([]byte, 128)
	n, err := udpConn.Read(uBuf)
	_ = udpConn.Close()
	if err != nil || string(uBuf[:n]) != "udp:ping-dgram" {
		t.Fatalf("UDP echo got=%q err=%v", string(uBuf[:n]), err)
	}

	// 5. Unmapped synthetic IP gets immediate RST instead of timing out.
	badCtx, badCancel := context.WithTimeout(ctx, 2*time.Second)
	defer badCancel()
	badConn, err := gonet.DialContextTCP(badCtx, clientStack, tcpip.FullAddress{
		NIC: 1, Addr: tcpip.AddrFrom4(netip.MustParseAddr("198.19.1.250").As4()), Port: 80,
	}, ipv4.ProtocolNumber)
	if err == nil {
		_ = badConn.Close()
		t.Fatal("expected unmapped IP dial to fail with RST")
	}
	if !strings.Contains(err.Error(), "refused") && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("unexpected error for unmapped IP (wanted RST, not timeout): %v", err)
	}

	cancel()
	bridge.close()
	clientEP.Close()
	wg.Wait()
}
