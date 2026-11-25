package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	dnsTTL       = 60
	dnsEDNSUDPB  = 1232
	dnsMaxPacket = 4096
	dnsTCPMax    = 64
	dnsTCPTimeo  = 5 * time.Second
)

// DNSServer answers authoritative DNS queries for the pen's zone directly
// from SQLite and config, refusing queries for any name outside the zone.
type DNSServer struct {
	svc       *Service
	zoneFQDN  string
	zoneName  dnsmessage.Name
	nsName    dnsmessage.Name
	ownerName dnsmessage.Name
	coreV4    netip.Addr
	serial    uint32
}

// NewDNSServer builds an authoritative DNS handler for s's configured zone.
func NewDNSServer(s *Service) (*DNSServer, error) {
	coreV4, err := netip.ParseAddr(strings.TrimSpace(s.cfg.CoreIP))
	if err != nil || !coreV4.Is4() {
		return nil, fmt.Errorf("dns: invalid CORE_MESH_IP %q", s.cfg.CoreIP)
	}
	return NewDNSServerWithIP(s, coreV4)
}

// NewDNSServerWithIP builds an authoritative IPv4-only DNS handler using an
// explicit core IPv4 address (e.g. from an embedded tsnet node).
func NewDNSServerWithIP(s *Service, coreV4 netip.Addr) (*DNSServer, error) {
	zone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s.cfg.Zone)), ".")
	if zone == "" {
		return nil, errors.New("dns: zone is empty")
	}
	fqdn := zone + "."
	zoneName, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("dns: zone name %q: %w", fqdn, err)
	}
	nsName, err := dnsmessage.NewName("ns." + fqdn)
	if err != nil {
		return nil, fmt.Errorf("dns: ns name: %w", err)
	}
	ownerName, err := dnsmessage.NewName("owner." + fqdn)
	if err != nil {
		return nil, fmt.Errorf("dns: owner name: %w", err)
	}
	if !coreV4.IsValid() || !coreV4.Is4() {
		return nil, fmt.Errorf("dns: invalid core IPv4 %q", coreV4)
	}
	return &DNSServer{
		svc:       s,
		zoneFQDN:  fqdn,
		zoneName:  zoneName,
		nsName:    nsName,
		ownerName: ownerName,
		coreV4:    coreV4,
		serial:    uint32(time.Now().Unix()),
	}, nil
}

// Start binds both UDP and TCP sockets on addr and serves until ctx cancels.
func (d *DNSServer) Start(ctx context.Context, addr string) error {
	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		_ = udpConn.Close()
		return err
	}
	d.Serve(ctx, []net.PacketConn{udpConn}, tcpLn)
	return nil
}

// Serve handles DNS over already-bound UDP PacketConns (IPv4 and optional IPv6)
// and a TCP Listener until ctx cancels.
func (d *DNSServer) Serve(ctx context.Context, udpConns []net.PacketConn, tcpLn net.Listener) {
	go func() {
		<-ctx.Done()
		for _, c := range udpConns {
			_ = c.Close()
		}
		if tcpLn != nil {
			_ = tcpLn.Close()
		}
	}()
	for _, c := range udpConns {
		go d.serveUDP(c)
	}
	if tcpLn != nil {
		go d.serveTCP(tcpLn)
	}
}

// SelfCheck builds a wire-format A query for home.<zone> and verifies HandlePacket
// answers with coreV4.
func (d *DNSServer) SelfCheck() error {
	qname, err := dnsmessage.NewName("home." + d.zoneFQDN)
	if err != nil {
		return err
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 128), dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	req, err := b.Finish()
	if err != nil {
		return err
	}
	resp, ok := d.HandlePacket(req, false)
	if !ok {
		return errors.New("dns self-check returned no packet")
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		return err
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return fmt.Errorf("dns self-check rcode=%v", hdr.RCode)
	}
	_ = p.SkipAllQuestions()
	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			return fmt.Errorf("dns self-check missing A answer: %w", err)
		}
		if ah.Type == dnsmessage.TypeA {
			a, err := p.AResource()
			if err != nil {
				return err
			}
			if netip.AddrFrom4(a.A) == d.coreV4 {
				return nil
			}
			return fmt.Errorf("dns self-check got %s, want %s", netip.AddrFrom4(a.A), d.coreV4)
		}
		_ = p.SkipAnswer()
	}
}

func (d *DNSServer) serveUDP(conn net.PacketConn) {
	buf := make([]byte, dnsMaxPacket)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if resp, ok := d.HandlePacket(buf[:n], false); ok {
			_, _ = conn.WriteTo(resp, peer)
		}
	}
}

func (d *DNSServer) serveTCP(ln net.Listener) {
	sem := make(chan struct{}, dnsTCPMax)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
			go func(conn net.Conn) {
				defer func() { <-sem }()
				d.handleTCPConn(conn)
			}(c)
		default:
			_ = c.Close()
		}
	}
}

func (d *DNSServer) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	var lenBuf [2]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(dnsTCPTimeo))
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		if n == 0 || n > dnsMaxPacket {
			return
		}
		req := make([]byte, n)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		resp, ok := d.HandlePacket(req, true)
		if !ok {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
		copy(out[2:], resp)
		_ = conn.SetWriteDeadline(time.Now().Add(dnsTCPTimeo))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// HandlePacket parses a wire-format DNS query and builds a wire-format response.
func (d *DNSServer) HandlePacket(req []byte, isTCP bool) ([]byte, bool) {
	if len(req) < 12 {
		return nil, false
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(req)
	if err != nil {
		return d.buildError(req, false, dnsmessage.Question{}, false, 0, dnsmessage.RCodeFormatError)
	}
	if hdr.Response {
		return nil, false
	}

	q, hasQ, err := parseQuestion(&p)
	if err != nil {
		return d.buildError(req, false, dnsmessage.Question{}, false, 0, dnsmessage.RCodeFormatError)
	}
	hasOPT, clientMaxUDP, badVers := inspectEDNS(&p)

	if hdr.OpCode != 0 {
		return d.buildError(req, hasQ, q, hasOPT, 0, dnsmessage.RCodeNotImplemented)
	}
	if badVers {
		return d.buildError(req, hasQ, q, true, dnsmessage.RCode(16), dnsmessage.RCodeSuccess)
	}
	if !hasQ {
		return d.buildError(req, false, dnsmessage.Question{}, hasOPT, 0, dnsmessage.RCodeFormatError)
	}

	qname := strings.ToLower(q.Name.String())
	if qname != d.zoneFQDN && !strings.HasSuffix(qname, "."+d.zoneFQDN) {
		return d.buildError(req, true, q, hasOPT, 0, dnsmessage.RCodeRefused)
	}
	if q.Class != dnsmessage.ClassINET && q.Class != dnsmessage.ClassANY {
		return d.buildError(req, true, q, hasOPT, 0, dnsmessage.RCodeRefused)
	}

	resp, ok := d.buildAuthoritative(hdr, q, qname, hasOPT, clientMaxUDP, isTCP)
	return resp, ok
}

func parseQuestion(p *dnsmessage.Parser) (dnsmessage.Question, bool, error) {
	q, err := p.Question()
	if errors.Is(err, dnsmessage.ErrSectionDone) {
		return dnsmessage.Question{}, false, nil
	}
	if err != nil {
		return dnsmessage.Question{}, false, err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return dnsmessage.Question{}, false, err
	}
	return q, true, nil
}

func inspectEDNS(p *dnsmessage.Parser) (hasOPT bool, maxUDP int, badVers bool) {
	maxUDP = 512
	_ = p.SkipAllAnswers()
	_ = p.SkipAllAuthorities()
	for {
		ah, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if ah.Type == dnsmessage.TypeOPT {
			hasOPT = true
			if ver := (ah.TTL >> 16) & 0xff; ver != 0 {
				badVers = true
			}
			sz := int(ah.Class)
			if sz > 512 {
				if sz > dnsEDNSUDPB {
					sz = dnsEDNSUDPB
				}
				maxUDP = sz
			}
		}
		if err := p.SkipAdditional(); err != nil {
			break
		}
	}
	return hasOPT, maxUDP, badVers
}

func (d *DNSServer) buildError(req []byte, hasQ bool, q dnsmessage.Question, hasOPT bool, extRCode dnsmessage.RCode, rcode dnsmessage.RCode) ([]byte, bool) {
	id := binary.BigEndian.Uint16(req[:2])
	hdr := dnsmessage.Header{
		ID:       id,
		Response: true,
		OpCode:   dnsmessage.OpCode((req[2] >> 3) & 0x0f),
		RCode:    rcode,
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 128), hdr)
	b.EnableCompression()
	if hasQ {
		_ = b.StartQuestions()
		_ = b.Question(q)
	}
	if hasOPT {
		_ = b.StartAdditionals()
		_ = b.OPTResource(optHeader(extRCode), dnsmessage.OPTResource{})
	}
	out, err := b.Finish()
	return out, err == nil
}

func (d *DNSServer) buildAuthoritative(reqHdr dnsmessage.Header, q dnsmessage.Question, qname string, hasOPT bool, maxUDP int, isTCP bool) ([]byte, bool) {
	rcode, answers, needSOA := d.resolve(q, qname)
	respHdr := dnsmessage.Header{
		ID:               reqHdr.ID,
		Response:         true,
		Authoritative:    true,
		RecursionDesired: reqHdr.RecursionDesired,
		RCode:            rcode,
	}
	out, ok := d.marshalMessage(respHdr, q, answers, needSOA, hasOPT)
	if !ok {
		return d.buildError(packetID(reqHdr.ID), true, q, hasOPT, 0, dnsmessage.RCodeServerFailure)
	}
	if !isTCP && len(out) > maxUDP {
		truncHdr := respHdr
		truncHdr.Truncated = true
		return d.marshalMessage(truncHdr, q, nil, false, hasOPT)
	}
	return out, true
}

func packetID(id uint16) []byte {
	var b [4]byte
	binary.BigEndian.PutUint16(b[:2], id)
	return b[:]
}

func (d *DNSServer) marshalMessage(hdr dnsmessage.Header, q dnsmessage.Question, answers []dnsmessage.ResourceBody, needSOA, hasOPT bool) ([]byte, bool) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 256), hdr)
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	if len(answers) > 0 {
		_ = b.StartAnswers()
		for _, body := range answers {
			rh := dnsmessage.ResourceHeader{Name: q.Name, Type: answerType(body), Class: dnsmessage.ClassINET, TTL: dnsTTL}
			switch r := body.(type) {
			case *dnsmessage.AResource:
				_ = b.AResource(rh, *r)
			case *dnsmessage.AAAAResource:
				_ = b.AAAAResource(rh, *r)
			case *dnsmessage.NSResource:
				_ = b.NSResource(rh, *r)
			case *dnsmessage.SOAResource:
				_ = b.SOAResource(rh, *r)
			}
		}
	}
	if needSOA {
		_ = b.StartAuthorities()
		soaHdr := dnsmessage.ResourceHeader{Name: d.zoneName, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: dnsTTL}
		_ = b.SOAResource(soaHdr, d.soaResource())
	}
	if hasOPT {
		_ = b.StartAdditionals()
		_ = b.OPTResource(optHeader(0), dnsmessage.OPTResource{})
	}
	out, err := b.Finish()
	return out, err == nil
}

func (d *DNSServer) resolve(q dnsmessage.Question, qname string) (dnsmessage.RCode, []dnsmessage.ResourceBody, bool) {
	var ans []dnsmessage.ResourceBody
	if qname == d.zoneFQDN {
		if q.Type == dnsmessage.TypeSOA || q.Type == dnsmessage.TypeALL {
			soa := d.soaResource()
			ans = append(ans, &soa)
		}
		if q.Type == dnsmessage.TypeNS || q.Type == dnsmessage.TypeALL {
			ans = append(ans, &dnsmessage.NSResource{NS: d.nsName})
		}
		return dnsmessage.RCodeSuccess, ans, len(ans) == 0
	}

	rel := strings.TrimSuffix(qname, "."+d.zoneFQDN)
	if v4, ok := d.coreAddr(rel); ok {
		// Mesh policy is IPv4-only; AAAA intentionally returns NOERROR / NODATA
		// so clients always dial over IPv4 and mesh IPv6 stays default-denied.
		if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeALL {
			ans = append(ans, &dnsmessage.AResource{A: v4.As4()})
		}
		return dnsmessage.RCodeSuccess, ans, len(ans) == 0
	}

	n, err := d.svc.st.ResolvableName(rel)
	if errors.Is(err, ErrNotFound) {
		hasChild, cerr := d.svc.st.HasResolvableChild(rel)
		if cerr != nil {
			return dnsmessage.RCodeServerFailure, nil, false
		}
		if hasChild {
			return dnsmessage.RCodeSuccess, nil, true
		}
		return dnsmessage.RCodeNameError, nil, true
	}
	if err != nil {
		return dnsmessage.RCodeServerFailure, nil, false
	}

	if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeALL {
		if v4, perr := netip.ParseAddr(n.IPv4); perr == nil && v4.Is4() {
			ans = append(ans, &dnsmessage.AResource{A: v4.As4()})
		}
	}
	return dnsmessage.RCodeSuccess, ans, len(ans) == 0
}

func (d *DNSServer) coreAddr(rel string) (netip.Addr, bool) {
	switch rel {
	case "ns", "home":
		return d.coreV4, true
	default:
		return netip.Addr{}, false
	}
}

func (d *DNSServer) soaResource() dnsmessage.SOAResource {
	return dnsmessage.SOAResource{
		NS:      d.nsName,
		MBox:    d.ownerName,
		Serial:  d.serial,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		MinTTL:  dnsTTL,
	}
}

func optHeader(extRCode dnsmessage.RCode) dnsmessage.ResourceHeader {
	var rh dnsmessage.ResourceHeader
	_ = rh.SetEDNS0(dnsEDNSUDPB, extRCode, false)
	return rh
}

func answerType(b dnsmessage.ResourceBody) dnsmessage.Type {
	switch b.(type) {
	case *dnsmessage.AResource:
		return dnsmessage.TypeA
	case *dnsmessage.AAAAResource:
		return dnsmessage.TypeAAAA
	case *dnsmessage.NSResource:
		return dnsmessage.TypeNS
	case *dnsmessage.SOAResource:
		return dnsmessage.TypeSOA
	default:
		return 0
	}
}
