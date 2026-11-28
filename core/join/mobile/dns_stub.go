package mobile

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

// SplitDNSStubIP is the single /32 link-local-style resolver address inside
// CGNAT space intercepted inside libhogman for split DNS on mobile.
var SplitDNSStubIP = netip.MustParseAddr("100.100.100.100")

const (
	dnsQueryTimeout     = 3 * time.Second
	maxDNSWireBytes     = 4096
	maxConcurrentDNSOps = 64
	ephemeralPortMin    = 50000
	ephemeralPortSpan   = 10000
)

type penPendingQuery struct {
	txid   uint16
	server netip.Addr
	ch     chan []byte
}

// SplitDNSStub intercepts IPv4 UDP DNS queries sent to SplitDNSStubIP:53:
//   - Queries in the active pen's zone (excluding the public LoginServer host)
//     allow ONLY A records for the exact query name pointing at live Headscale
//     netmap peers ("dial only pen devices"), answer all other Qtypes with an
//     empty NOERROR, and clear Ns/Extra. Pen queries are injected directly into
//     the WireGuard tstun engine so zero 100.64/10 packets ever touch OS sockets
//     or physical/carrier interfaces.
//   - All other queries (Android catch-all mode) forward directly to the active
//     network's upstream DNS servers via protected sockets with zero logging,
//     zero counting, and zero post-TTL caching.
type SplitDNSStub struct {
	mu              sync.RWMutex
	zone            string // lowercase, no trailing dot
	loginHost       string // lowercase control/login host exempted from pen-internal DNS
	selfIP          netip.Addr
	penDNS          netip.Addr
	peers           map[netip.Addr]bool
	routesConfirmed bool
	upstream        []netip.Addr
	tun             *tstun.Wrapper
	protect         func(fd int) error
	sem             chan struct{}

	pendingMu sync.Mutex
	pending   map[uint16]penPendingQuery
	nextPort  uint16

	// Optional hooks for deterministic unit testing.
	forwardPen      func(ctx context.Context, raw []byte, server netip.Addr) ([]byte, error)
	forwardUpstream func(ctx context.Context, raw []byte, servers []netip.Addr) ([]byte, error)
}

func NewSplitDNSStub(zone string, protect func(fd int) error) *SplitDNSStub {
	s := &SplitDNSStub{
		zone:     strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), ".")),
		peers:    make(map[netip.Addr]bool),
		protect:  protect,
		sem:      make(chan struct{}, maxConcurrentDNSOps),
		pending:  make(map[uint16]penPendingQuery),
		nextPort: ephemeralPortMin,
	}
	s.forwardPen = s.defaultForwardPen
	s.forwardUpstream = s.defaultForwardUpstream
	return s
}

// AttachTunnel wires the DNS stub directly into tstun's outbound and inbound
// hooks so pen DNS traffic travels exclusively through the WireGuard engine.
func (s *SplitDNSStub) AttachTunnel(t *tstun.Wrapper) {
	if t == nil {
		return
	}
	s.mu.Lock()
	s.tun = t
	s.mu.Unlock()

	prevOut := t.PreFilterPacketOutboundToWireGuardEngineIntercept
	t.PreFilterPacketOutboundToWireGuardEngineIntercept = func(p *packet.Parsed, w *tstun.Wrapper) filter.Response {
		if s.HandlePacket(p, w) {
			return filter.DropSilently
		}
		if prevOut != nil {
			return prevOut(p, w)
		}
		return filter.Accept
	}

	prevIn := t.PreFilterPacketInboundFromWireGuard
	t.PreFilterPacketInboundFromWireGuard = func(p *packet.Parsed, w *tstun.Wrapper) filter.Response {
		if s.HandleInboundPacket(p) {
			return filter.DropSilently
		}
		if prevIn != nil {
			return prevIn(p, w)
		}
		return filter.Accept
	}
}

func (s *SplitDNSStub) UpdatePen(selfIP, penDNS netip.Addr, allowedPeers map[netip.Addr]bool, routesConfirmed bool) {
	cp := make(map[netip.Addr]bool, len(allowedPeers))
	for ip := range allowedPeers {
		cp[ip.Unmap()] = true
	}
	s.mu.Lock()
	s.selfIP = selfIP.Unmap()
	s.penDNS = penDNS.Unmap()
	s.peers = cp
	s.routesConfirmed = routesConfirmed
	s.mu.Unlock()
}

func (s *SplitDNSStub) UpdateUpstream(servers []netip.Addr) {
	cp := make([]netip.Addr, 0, len(servers))
	for _, ip := range servers {
		ip = ip.Unmap()
		if !ip.IsValid() || ip == SplitDNSStubIP {
			continue
		}
		cp = append(cp, ip)
	}
	s.mu.Lock()
	s.upstream = cp
	s.mu.Unlock()
}

// SetLoginHost registers the pen's public control/login hostname so self-hosted
// pens whose PUBLIC_HOST lives inside or at the apex of ZONE still resolve via
// public upstream DNS while the split tunnel is active.
func (s *SplitDNSStub) SetLoginHost(host string) {
	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	s.mu.Lock()
	s.loginHost = norm
	s.mu.Unlock()
}

// InZone reports whether qname (with or without trailing dot) belongs strictly
// to the pen's internal zone (excluding the public control/login host).
func (s *SplitDNSStub) InZone(qname string) bool {
	s.mu.RLock()
	zone := s.zone
	loginHost := s.loginHost
	s.mu.RUnlock()
	return hostInPenDNS(qname, zone, loginHost)
}

func hostInPenDNS(qname, zone, loginHost string) bool {
	if zone == "" {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	if loginHost != "" && name == loginHost {
		return false
	}
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// HandlePacket intercepts outbound IPv4 UDP DNS queries addressed to
// SplitDNSStubIP:53 on t and injects the response asynchronously. Returns true
// if the packet was consumed.
func (s *SplitDNSStub) HandlePacket(p *packet.Parsed, t *tstun.Wrapper) bool {
	if p == nil || p.IPVersion != 4 || p.IPProto != ipproto.UDP {
		return false
	}
	if p.Dst.Addr() != SplitDNSStubIP || p.Dst.Port() != 53 {
		return false
	}
	payload := p.Payload()
	if len(payload) == 0 || len(payload) > maxDNSWireBytes {
		return true
	}
	reqWire := make([]byte, len(payload))
	copy(reqWire, payload)
	src := p.Src
	dst := p.Dst

	select {
	case s.sem <- struct{}{}:
	default:
		// Bound concurrency under floods; drop cleanly so the caller retries.
		return true
	}
	go func() {
		defer func() { <-s.sem }()
		ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout)
		defer cancel()
		respWire, err := s.ResolveWire(ctx, reqWire)
		if err != nil || len(respWire) == 0 {
			return
		}
		hdr := packet.UDP4Header{
			IP4Header: packet.IP4Header{
				IPProto: ipproto.UDP,
				Src:     dst.Addr(),
				Dst:     src.Addr(),
			},
			SrcPort: dst.Port(),
			DstPort: src.Port(),
		}
		t.InjectInboundCopy(packet.Generate(hdr, respWire))
	}()
	return true
}

// HandleInboundPacket captures replies to engine-injected pen DNS queries
// coming back from WireGuard before they reach the OS TUN interface.
func (s *SplitDNSStub) HandleInboundPacket(p *packet.Parsed) bool {
	if p == nil || p.IPVersion != 4 || p.IPProto != ipproto.UDP || p.Src.Port() != 53 {
		return false
	}
	payload := p.Payload()
	if len(payload) < 2 {
		return false
	}
	s.mu.RLock()
	selfIP := s.selfIP
	penDNS := s.penDNS
	s.mu.RUnlock()

	if !selfIP.Is4() || !penDNS.Is4() {
		return false
	}
	if p.Src.Addr() != penDNS || p.Dst.Addr() != selfIP {
		return false
	}
	txid := binary.BigEndian.Uint16(payload[:2])

	s.pendingMu.Lock()
	entry, ok := s.pending[p.Dst.Port()]
	if !ok || entry.txid != txid || entry.server != p.Src.Addr() {
		s.pendingMu.Unlock()
		return false
	}
	delete(s.pending, p.Dst.Port())
	s.pendingMu.Unlock()

	cp := make([]byte, len(payload))
	copy(cp, payload)
	select {
	case entry.ch <- cp:
	default:
	}
	return true
}

// ResolveWire resolves a single DNS wire message, enforcing split-DNS routing
// and strict A-only live-peer allowlisting for pen names.
func (s *SplitDNSStub) ResolveWire(ctx context.Context, raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxDNSWireBytes {
		return nil, errors.New("invalid DNS wire message size")
	}
	var req dns.Msg
	if err := req.Unpack(raw); err != nil {
		return nil, err
	}
	if len(req.Question) == 0 {
		return packRcode(&req, dns.RcodeFormatError)
	}
	q := req.Question[0]

	s.mu.RLock()
	zone := s.zone
	loginHost := s.loginHost
	penDNS := s.penDNS
	peers := s.peers
	routesConfirmed := s.routesConfirmed
	upstream := s.upstream
	s.mu.RUnlock()

	if hostInPenDNS(q.Name, zone, loginHost) {
		return s.resolvePenQuery(ctx, &req, raw, penDNS, peers, routesConfirmed)
	}
	// Non-pen query: forward directly to upstream without logging, counting,
	// or caching.
	if len(upstream) == 0 {
		return packRcode(&req, dns.RcodeServerFailure)
	}
	return s.forwardUpstream(ctx, raw, upstream)
}

func (s *SplitDNSStub) resolvePenQuery(ctx context.Context, req *dns.Msg, raw []byte, penDNS netip.Addr, peers map[netip.Addr]bool, routesConfirmed bool) ([]byte, error) {
	q := req.Question[0]
	// Strict allowlist: pen services are IPv4 A records only. Every other query
	// type (AAAA, HTTPS, SVCB, CNAME, DNAME, TXT, SRV, ANY, ...) returns an
	// empty NOERROR locally so a compromised registrar cannot redirect pen names
	// off-mesh via CNAME/DNAME/HTTPS ipv4hint.
	if q.Qtype != dns.TypeA {
		return packRcode(req, dns.RcodeSuccess)
	}
	if !routesConfirmed || !penDNS.IsValid() || !penDNS.Is4() {
		return packRcode(req, dns.RcodeServerFailure)
	}
	replyWire, err := s.forwardPen(ctx, raw, penDNS)
	if err != nil {
		return packRcode(req, dns.RcodeServerFailure)
	}
	var resp dns.Msg
	if err := resp.Unpack(replyWire); err != nil {
		return packRcode(req, dns.RcodeServerFailure)
	}
	resp.Answer = filterPenAOnly(resp.Answer, q.Name, peers)
	resp.Ns = nil
	resp.Extra = nil
	return resp.Pack()
}

// filterPenAOnly enforces a strict allowlist on pen DNS responses: keep ONLY
// IPv4 A records whose owner name matches qname and whose address is a live
// peer in the pen's Headscale netmap. CNAME, DNAME, HTTPS/SVCB, AAAA, mismatched
// owner names, and off-mesh A records are all dropped.
func filterPenAOnly(rrs []dns.RR, qname string, peers map[netip.Addr]bool) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	wantName := strings.ToLower(dns.Fqdn(qname))
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		if strings.ToLower(dns.Fqdn(a.Hdr.Name)) != wantName {
			continue
		}
		addr, ok := netip.AddrFromSlice(a.A)
		if !ok {
			continue
		}
		if !peers[addr.Unmap()] {
			continue
		}
		out = append(out, a)
	}
	return out
}

func packRcode(req *dns.Msg, rcode int) ([]byte, error) {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	resp.RecursionAvailable = true
	return resp.Pack()
}

func (s *SplitDNSStub) allocPendingPort(txid uint16, server netip.Addr) (uint16, chan []byte, error) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for i := 0; i < ephemeralPortSpan; i++ {
		port := ephemeralPortMin + uint16((int(s.nextPort-ephemeralPortMin)+i)%ephemeralPortSpan)
		if _, busy := s.pending[port]; !busy {
			s.nextPort = ephemeralPortMin + uint16((int(port-ephemeralPortMin)+1)%ephemeralPortSpan)
			ch := make(chan []byte, 1)
			s.pending[port] = penPendingQuery{txid: txid, server: server, ch: ch}
			return port, ch, nil
		}
	}
	return 0, nil, errors.New("no ephemeral port available for pen DNS query")
}

func (s *SplitDNSStub) releasePendingPort(port uint16) {
	s.pendingMu.Lock()
	delete(s.pending, port)
	s.pendingMu.Unlock()
}

// defaultForwardPen injects the DNS UDP query straight into the WireGuard
// tstun engine (zero OS sockets) so pen-bound packets can never leak onto
// physical or cellular carrier networks on iOS or Android.
func (s *SplitDNSStub) defaultForwardPen(ctx context.Context, raw []byte, server netip.Addr) ([]byte, error) {
	if len(raw) < 12 {
		return nil, errors.New("truncated DNS query")
	}
	s.mu.RLock()
	tun := s.tun
	selfIP := s.selfIP
	routesConfirmed := s.routesConfirmed
	s.mu.RUnlock()

	if tun == nil || !selfIP.Is4() || !server.Is4() || !routesConfirmed {
		return nil, errors.New("pen tunnel is not ready")
	}

	txid := binary.BigEndian.Uint16(raw[:2])
	port, ch, err := s.allocPendingPort(txid, server)
	if err != nil {
		return nil, err
	}
	defer s.releasePendingPort(port)

	hdr := packet.UDP4Header{
		IP4Header: packet.IP4Header{
			IPProto: ipproto.UDP,
			Src:     selfIP,
			Dst:     server,
		},
		SrcPort: port,
		DstPort: 53,
	}
	if err := tun.InjectOutbound(packet.Generate(hdr, raw)); err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *SplitDNSStub) defaultForwardUpstream(ctx context.Context, raw []byte, servers []netip.Addr) ([]byte, error) {
	d := newProtectedDialer(s.protect)
	var lastErr error
	for _, srv := range servers {
		resp, err := exchangeDNS(ctx, d, netip.AddrPortFrom(srv, 53), raw)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream DNS servers available")
	}
	return nil, lastErr
}

func exchangeDNS(ctx context.Context, dialer *net.Dialer, target netip.AddrPort, raw []byte) ([]byte, error) {
	reply, err := exchangeUDP(ctx, dialer, target, raw)
	if err != nil {
		return nil, err
	}
	// If the UDP response is truncated (TC bit = byte 2 bit 1), retry over TCP.
	if len(reply) >= 12 && (reply[2]&0x02) != 0 {
		if tcpReply, terr := exchangeTCP(ctx, dialer, target, raw); terr == nil {
			return tcpReply, nil
		}
	}
	return reply, nil
}

func exchangeUDP(ctx context.Context, dialer *net.Dialer, target netip.AddrPort, raw []byte) ([]byte, error) {
	conn, err := dialer.DialContext(ctx, "udp", target.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}
	buf := make([]byte, maxDNSWireBytes)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func exchangeTCP(ctx context.Context, dialer *net.Dialer, target netip.AddrPort, raw []byte) ([]byte, error) {
	if len(raw) > 65535 {
		return nil, errors.New("DNS query too large for TCP")
	}
	conn, err := dialer.DialContext(ctx, "tcp", target.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	framed := make([]byte, 2+len(raw))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(raw)))
	copy(framed[2:], raw)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen == 0 || respLen > maxDNSWireBytes {
		return nil, errors.New("invalid TCP DNS response length")
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
