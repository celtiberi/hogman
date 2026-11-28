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
)

// SplitDNSStubIP is the single /32 link-local-style resolver address inside
// CGNAT space intercepted inside libhogman for split DNS on mobile.
var SplitDNSStubIP = netip.MustParseAddr("100.100.100.100")

const (
	dnsQueryTimeout     = 3 * time.Second
	maxDNSWireBytes     = 4096
	maxConcurrentDNSOps = 64
)

// SplitDNSStub intercepts IPv4 UDP DNS queries sent to SplitDNSStubIP:53:
//   - Queries in the active pen's zone forward to the pen's tag:infra DNS over
//     the tunnel, dropping all AAAA records and any A record whose IP is not a
//     live peer in the pen's Headscale netmap ("dial only pen devices").
//   - All other queries (Android catch-all mode) forward directly to the active
//     network's upstream DNS servers via protected sockets with zero logging,
//     zero counting, and zero post-TTL caching.
type SplitDNSStub struct {
	mu       sync.RWMutex
	zone     string // lowercase, no trailing dot
	penDNS   netip.Addr
	peers    map[netip.Addr]bool
	upstream []netip.Addr
	protect  func(fd int) error
	sem      chan struct{}

	// Optional hooks for deterministic unit testing.
	forwardPen      func(ctx context.Context, raw []byte, server netip.Addr) ([]byte, error)
	forwardUpstream func(ctx context.Context, raw []byte, servers []netip.Addr) ([]byte, error)
}

func NewSplitDNSStub(zone string, protect func(fd int) error) *SplitDNSStub {
	s := &SplitDNSStub{
		zone:    strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), ".")),
		peers:   make(map[netip.Addr]bool),
		protect: protect,
		sem:     make(chan struct{}, maxConcurrentDNSOps),
	}
	s.forwardPen = s.defaultForwardPen
	s.forwardUpstream = s.defaultForwardUpstream
	return s
}

func (s *SplitDNSStub) UpdatePen(penDNS netip.Addr, allowedPeers map[netip.Addr]bool) {
	cp := make(map[netip.Addr]bool, len(allowedPeers))
	for ip := range allowedPeers {
		cp[ip.Unmap()] = true
	}
	s.mu.Lock()
	s.penDNS = penDNS.Unmap()
	s.peers = cp
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

// InZone reports whether qname (with or without trailing dot) belongs strictly
// to the pen's zone (exact zone or subdomain label boundary).
func (s *SplitDNSStub) InZone(qname string) bool {
	s.mu.RLock()
	zone := s.zone
	s.mu.RUnlock()
	return hostInZone(qname, zone)
}

func hostInZone(qname, zone string) bool {
	if zone == "" {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
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

// ResolveWire resolves a single DNS wire message, enforcing split-DNS routing
// and peer filtering for pen names.
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
	penDNS := s.penDNS
	peers := s.peers
	upstream := s.upstream
	s.mu.RUnlock()

	if hostInZone(q.Name, zone) {
		return s.resolvePenQuery(ctx, &req, raw, penDNS, peers)
	}
	// Non-pen query: forward directly to upstream without logging, counting,
	// or caching.
	if len(upstream) == 0 {
		return packRcode(&req, dns.RcodeServerFailure)
	}
	return s.forwardUpstream(ctx, raw, upstream)
}

func (s *SplitDNSStub) resolvePenQuery(ctx context.Context, req *dns.Msg, raw []byte, penDNS netip.Addr, peers map[netip.Addr]bool) ([]byte, error) {
	// Pen mesh policy is IPv4-only: answer AAAA directly with NOERROR empty
	// answer so dual-stack clients immediately use the A record.
	if req.Question[0].Qtype == dns.TypeAAAA {
		return packRcode(req, dns.RcodeSuccess)
	}
	if !penDNS.IsValid() || !penDNS.Is4() {
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
	resp.Answer = filterPenRRs(resp.Answer, peers)
	resp.Extra = filterPenRRs(resp.Extra, peers)
	return resp.Pack()
}

// filterPenRRs enforces desktop's "dial only pen devices" invariant on mobile
// DNS responses: drop every AAAA record and drop any A record whose address is
// not an active peer in the pen's live Headscale netmap.
func filterPenRRs(rrs []dns.RR, peers map[netip.Addr]bool) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.AAAA:
			continue
		case *dns.A:
			addr, ok := netip.AddrFromSlice(v.A)
			if !ok {
				continue
			}
			if !peers[addr.Unmap()] {
				continue
			}
			out = append(out, rr)
		default:
			out = append(out, rr)
		}
	}
	return out
}

func packRcode(req *dns.Msg, rcode int) ([]byte, error) {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	resp.RecursionAvailable = true
	return resp.Pack()
}

func (s *SplitDNSStub) defaultForwardPen(ctx context.Context, raw []byte, server netip.Addr) ([]byte, error) {
	// Unprotected dialer so packets to the pen's tag:infra DNS route through the
	// WireGuard TUN interface.
	d := &net.Dialer{}
	return exchangeDNS(ctx, d, netip.AddrPortFrom(server, 53), raw)
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
