package main

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"tailscale.com/tsnet"
)

const (
	spikeDefaultSubnet     = "198.19.0.0/16"
	spikeDefaultStatusAddr = "127.0.0.1:19819"
	spikeMTU               = 1280
	spikeNICID             = tcpip.NICID(1)
	spikeWriteOffset       = 64 // headroom >= darwin PI header (4B) and linux virtioNetHdr (10B)
	spikeDNSTTL            = 30
	spikeUDPFallbackIdle   = 60 * time.Second
)

type synthTarget struct {
	Zone   string
	MeshIP string
}

// synthPool allocates unique synthetic IPv4 addresses inside the spike subnet
// (e.g. 198.19.1.1+) so traffic never touches CGNAT 100.64.0.0/10.
type synthPool struct {
	baseU32 uint32
	maxIdx  uint32

	mu       sync.Mutex
	nextIdx  uint32
	byTarget map[synthTarget]netip.Addr
	byIP     map[netip.Addr]synthTarget
}

func parseSpikeSubnet(raw string) (subnet netip.Prefix, localIP, dnsIP netip.Addr, pool *synthPool, err error) {
	if raw == "" {
		raw = spikeDefaultSubnet
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, nil, fmt.Errorf("invalid --subnet %q: %w", raw, err)
	}
	p = p.Masked()
	if !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 22 {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, nil, fmt.Errorf("--subnet %q must be an IPv4 /8 through /22 prefix", raw)
	}
	b := p.Addr().As4()
	base := binary.BigEndian.Uint32(b[:])
	hostSpan := uint32(1) << (32 - p.Bits())
	localIP = u32ToAddr4(base + 1)
	dnsIP = u32ToAddr4(base + 53)
	poolStart := base + 257 // start at .1.1 so .0.x stays reserved for local TUN + DNS
	maxIdx := hostSpan - 258
	return p, localIP, dnsIP, &synthPool{
		baseU32:  poolStart,
		maxIdx:   maxIdx,
		byTarget: map[synthTarget]netip.Addr{},
		byIP:     map[netip.Addr]synthTarget{},
	}, nil
}

func u32ToAddr4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func (p *synthPool) alloc(zone, meshIP string) (netip.Addr, error) {
	t := synthTarget{Zone: zone, MeshIP: meshIP}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ip, ok := p.byTarget[t]; ok {
		return ip, nil
	}
	for scanned := uint32(0); scanned < p.maxIdx; scanned++ {
		idx := (p.nextIdx + scanned) % p.maxIdx
		cand := u32ToAddr4(p.baseU32 + idx)
		lastOctet := cand.As4()[3]
		if lastOctet == 0 || lastOctet == 255 {
			continue
		}
		if _, used := p.byIP[cand]; used {
			continue
		}
		p.byTarget[t] = cand
		p.byIP[cand] = t
		p.nextIdx = (idx + 1) % p.maxIdx
		return cand, nil
	}
	return netip.Addr{}, errors.New("synthetic address pool exhausted")
}

func (p *synthPool) lookupIP(ip netip.Addr) (synthTarget, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.byIP[ip]
	return t, ok
}

func (p *synthPool) snapshot() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.byIP))
	for ip, t := range p.byIP {
		out[ip.String()] = t.MeshIP + " (" + t.Zone + ")"
	}
	return out
}

// ------------------------------------------------------------------ pens --

type cachedLookup struct {
	ips []string
	exp time.Time
}

type spikePen struct {
	dir        string
	cfg        *agentConfig
	node       *tsnet.Server
	resolver   *net.Resolver
	peerLookup func(context.Context, string) ([]string, error)

	mu    sync.Mutex
	up    bool
	ips   []string
	err   string
	cache map[string]cachedLookup
}

func loadSpikePen(dir string) (*spikePen, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	c, err := loadAgentConfig(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: load config.json: %w", dir, err)
	}
	if !zoneRE.MatchString(c.Zone) {
		return nil, fmt.Errorf("%s: invalid zone %q", dir, c.Zone)
	}
	if c.DNSServer == "" {
		return nil, fmt.Errorf("%s: missing dns_server in config.json", dir)
	}
	return &spikePen{dir: abs, cfg: c, cache: map[string]cachedLookup{}}, nil
}

// installCombinedControlCAs combines ControlCA PEMs from all spike pens into a
// single fallback cert pool before starting tsnet nodes, so multiple test pens
// with distinct self-signed control CAs all connect cleanly in one process.
func installCombinedControlCAs(pens []*spikePen) {
	pool := x509.NewCertPool()
	added := false
	for _, p := range pens {
		if p.cfg.ControlCA == "" {
			continue
		}
		if pool.AppendCertsFromPEM([]byte(p.cfg.ControlCA)) {
			added = true
		}
	}
	if !added {
		return
	}
	gd := os.Getenv("GODEBUG")
	if !strings.Contains(gd, "x509usefallbackroots=1") {
		if gd != "" {
			gd += ","
		}
		_ = os.Setenv("GODEBUG", gd+"x509usefallbackroots=1")
	}
	x509.SetFallbackRoots(pool)
}

func (p *spikePen) start(ctx context.Context) error {
	keyFile := filepath.Join(p.dir, "authkey")
	keyBytes, _ := os.ReadFile(keyFile)
	node := newNode(p.dir, p.cfg, strings.TrimSpace(string(keyBytes)))
	p.mu.Lock()
	p.node = node
	p.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(dctx context.Context, network, _ string) (net.Conn, error) {
			return node.Dial(dctx, network, net.JoinHostPort(p.cfg.DNSServer, "53"))
		},
	}
	p.peerLookup = func(pctx context.Context, host string) ([]string, error) {
		lc, err := node.LocalClient()
		if err != nil {
			return nil, err
		}
		st, err := lc.Status(pctx)
		if err != nil {
			return nil, err
		}
		return peerIPsForHost(st, host), nil
	}
	p.mu.Unlock()

	upCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	st, err := node.Up(upCtx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.err = err.Error()
		return err
	}
	_ = os.Remove(keyFile)
	for _, ip := range st.TailscaleIPs {
		p.ips = append(p.ips, ip.String())
	}
	p.up = true
	p.err = ""
	log.Printf("spike pen %s online as %s", p.cfg.Zone, strings.Join(p.ips, ", "))
	return nil
}

func (p *spikePen) close() {
	p.mu.Lock()
	node := p.node
	p.mu.Unlock()
	if node != nil {
		_ = node.Close()
	}
}

func (p *spikePen) isUp() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.up
}

func (p *spikePen) resolveHost(ctx context.Context, host string) ([]string, bool, error) {
	norm := strings.ToLower(strings.TrimSuffix(host, "."))
	p.mu.Lock()
	if ent, ok := p.cache[norm]; ok && time.Now().Before(ent.exp) {
		up := p.up
		p.mu.Unlock()
		return ent.ips, up, nil
	}
	res := p.resolver
	peerLookup := p.peerLookup
	up := p.up
	p.mu.Unlock()

	if !up || res == nil {
		return nil, false, errors.New("pen is still connecting")
	}

	ips, err := res.LookupHost(ctx, norm)
	if len(ips) == 0 && strings.HasSuffix(norm, ".nodes."+p.cfg.Zone) && peerLookup != nil {
		if pips, perr := peerLookup(ctx, norm); perr == nil && len(pips) > 0 {
			ips = pips
			err = nil
		}
	}
	ordered := orderIPs(ips)
	if len(ordered) > 0 {
		p.mu.Lock()
		p.cache[norm] = cachedLookup{ips: ordered, exp: time.Now().Add(5 * time.Second)}
		p.mu.Unlock()
		return ordered, true, nil
	}
	return nil, true, err
}

// --------------------------------------------------------------- bridge --

type spikeBridge struct {
	ctx   context.Context
	dnsIP netip.Addr
	pool  *synthPool
	stack *stack.Stack
	ep    *channel.Endpoint

	lookupFn func(ctx context.Context, zone, host string) ([]string, bool, error)
	dialFn   func(ctx context.Context, zone, network, addr string) (net.Conn, error)

	zones   []string
	zoneSet map[string]bool

	dnsQueries atomic.Uint64
	tcpConns   atomic.Uint64
	udpFlows   atomic.Uint64
}

func newSpikeBridge(ctx context.Context, dnsIP netip.Addr, prefixBits int, pool *synthPool, zones []string,
	lookupFn func(ctx context.Context, zone, host string) ([]string, bool, error),
	dialFn func(ctx context.Context, zone, network, addr string) (net.Conn, error),
) (*spikeBridge, error) {
	ep := channel.New(1024, spikeMTU, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})

	cubicOpt := tcpip.CongestionControlOption("cubic")
	if tErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &cubicOpt); tErr != nil {
		s.Close()
		return nil, fmt.Errorf("set cubic: %v", tErr)
	}
	rxBuf := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20}
	if tErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rxBuf); tErr != nil {
		s.Close()
		return nil, fmt.Errorf("set tcp rx buf: %v", tErr)
	}
	txBuf := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20}
	if tErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &txBuf); tErr != nil {
		s.Close()
		return nil, fmt.Errorf("set tcp tx buf: %v", tErr)
	}

	if tErr := s.CreateNIC(spikeNICID, ep); tErr != nil {
		s.Close()
		return nil, fmt.Errorf("create netstack nic: %v", tErr)
	}
	dnsAddr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4(dnsIP.As4()),
		PrefixLen: prefixBits,
	}
	if tErr := s.AddProtocolAddress(spikeNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: dnsAddr,
	}, stack.AddressProperties{}); tErr != nil {
		s.Close()
		return nil, fmt.Errorf("add dns protocol addr: %v", tErr)
	}
	if tErr := s.SetPromiscuousMode(spikeNICID, true); tErr != nil {
		s.Close()
		return nil, fmt.Errorf("set promiscuous: %v", tErr)
	}
	if tErr := s.SetSpoofing(spikeNICID, true); tErr != nil {
		s.Close()
		return nil, fmt.Errorf("set spoofing: %v", tErr)
	}
	defaultV4, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	if err != nil {
		s.Close()
		return nil, err
	}
	s.SetRouteTable([]tcpip.Route{{Destination: defaultV4, NIC: spikeNICID}})

	zoneSet := make(map[string]bool, len(zones))
	sortedZones := make([]string, 0, len(zones))
	for _, z := range zones {
		nz := strings.ToLower(strings.TrimSuffix(z, "."))
		if !zoneSet[nz] {
			zoneSet[nz] = true
			sortedZones = append(sortedZones, nz)
		}
	}
	sort.Slice(sortedZones, func(i, j int) bool { return len(sortedZones[i]) > len(sortedZones[j]) })

	b := &spikeBridge{
		ctx:      ctx,
		dnsIP:    dnsIP,
		pool:     pool,
		stack:    s,
		ep:       ep,
		lookupFn: lookupFn,
		dialFn:   dialFn,
		zones:    sortedZones,
		zoneSet:  zoneSet,
	}

	tcpFwd := tcp.NewForwarder(s, 0, 1024, b.handleTCP)
	udpFwd := udp.NewForwarder(s, b.handleUDP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return b, nil
}

func (b *spikeBridge) close() {
	b.ep.Close()
	b.stack.Close()
	b.stack.Wait()
}

func (b *spikeBridge) matchZone(qname string) (string, bool) {
	h := strings.ToLower(strings.TrimSuffix(qname, "."))
	for _, z := range b.zones {
		if h == z || strings.HasSuffix(h, "."+z) {
			return z, true
		}
	}
	return "", false
}

func (b *spikeBridge) handleSpikeDNS(ctx context.Context, raw []byte) []byte {
	b.dnsQueries.Add(1)
	var req dnsmessage.Message
	if err := req.Unpack(raw); err != nil || len(req.Questions) == 0 {
		return nil
	}
	q := req.Questions[0]
	respHdr := dnsmessage.Header{
		ID:                 req.ID,
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   req.RecursionDesired,
		RecursionAvailable: true,
	}
	packMsg := func(rcode dnsmessage.RCode, answer *dnsmessage.AResource) []byte {
		respHdr.RCode = rcode
		buf := make([]byte, 0, 512)
		mb := dnsmessage.NewBuilder(buf, respHdr)
		mb.EnableCompression()
		if err := mb.StartQuestions(); err != nil {
			return nil
		}
		if err := mb.Question(q); err != nil {
			return nil
		}
		if answer != nil {
			if err := mb.StartAnswers(); err != nil {
				return nil
			}
			if err := mb.AResource(dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   spikeDNSTTL,
			}, *answer); err != nil {
				return nil
			}
		}
		out, err := mb.Finish()
		if err != nil {
			return nil
		}
		return out
	}

	zone, ok := b.matchZone(q.Name.String())
	if !ok {
		return packMsg(dnsmessage.RCodeRefused, nil)
	}
	qhost := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	if qhost == zone {
		// Zone apex itself has no host IP; return NOERROR NODATA just like registrar DNS.
		return packMsg(dnsmessage.RCodeSuccess, nil)
	}

	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, penUp, err := b.lookupFn(lctx, zone, qhost)
	cancel()
	if len(ips) == 0 {
		if !penUp {
			return packMsg(dnsmessage.RCodeServerFailure, nil)
		}
		if err != nil {
			var dnserr *net.DNSError
			if errors.As(err, &dnserr) && dnserr.IsNotFound {
				return packMsg(dnsmessage.RCodeNameError, nil)
			}
			// Treat resolver lookups with no addresses as NXDOMAIN once the pen is up.
			return packMsg(dnsmessage.RCodeNameError, nil)
		}
		return packMsg(dnsmessage.RCodeNameError, nil)
	}

	if q.Type != dnsmessage.TypeA {
		// Known host: reply NOERROR with zero answers so AAAA / HTTPS queries don't stall.
		return packMsg(dnsmessage.RCodeSuccess, nil)
	}

	synthIP, err := b.pool.alloc(zone, ips[0])
	if err != nil {
		return packMsg(dnsmessage.RCodeServerFailure, nil)
	}
	ans := &dnsmessage.AResource{A: synthIP.As4()}
	return packMsg(dnsmessage.RCodeSuccess, ans)
}

func (b *spikeBridge) serveTUN(dev tun.Device) {
	go func() {
		for range dev.Events() {
		}
	}()
	go b.pumpTUNToStack(dev)
	go b.pumpStackToTUN(dev)
}

func (b *spikeBridge) pumpTUNToStack(dev tun.Device) {
	batch := dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	slab := make([]byte, 256<<10)
	packets := make([]tun.ReadPacket, batch)
	for {
		n, err := dev.Read(slab, packets)
		for i := 0; i < n; i++ {
			off := packets[i].Offset
			sz := packets[i].Size
			if off < 0 || sz < 20 || off+sz > len(slab) {
				continue
			}
			raw := slab[off : off+sz]
			if raw[0]>>4 != 4 {
				continue
			}
			cp := make([]byte, len(raw))
			copy(cp, raw)
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(cp),
			})
			b.ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
			pkt.DecRef()
		}
		if err != nil {
			if b.ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return
			}
			log.Printf("spike tun read: %v", err)
			return
		}
	}
}

func (b *spikeBridge) pumpStackToTUN(dev tun.Device) {
	for {
		pkt := b.ep.ReadContext(b.ctx)
		if pkt == nil {
			return
		}
		buf := make([]byte, spikeWriteOffset+pkt.Size())
		n := copy(buf[spikeWriteOffset:], pkt.NetworkHeader().Slice())
		n += copy(buf[spikeWriteOffset+n:], pkt.TransportHeader().Slice())
		n += copy(buf[spikeWriteOffset+n:], pkt.Data().AsRange().ToSlice())
		pkt.DecRef()
		if _, err := dev.Write([][]byte{buf[:spikeWriteOffset+n]}, spikeWriteOffset); err != nil {
			if b.ctx.Err() == nil && !errors.Is(err, os.ErrClosed) {
				log.Printf("spike tun write: %v", err)
			}
			return
		}
	}
}

func (b *spikeBridge) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dstIP, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		r.Complete(true)
		return
	}
	dstIP = dstIP.Unmap()

	if dstIP == b.dnsIP && id.LocalPort == 53 {
		var wq waiter.Queue
		ep, tErr := r.CreateEndpoint(&wq)
		r.Complete(tErr != nil)
		if tErr != nil {
			return
		}
		b.serveDNSTCP(gonet.NewTCPConn(&wq, ep))
		return
	}

	target, ok := b.pool.lookupIP(dstIP)
	if !ok {
		r.Complete(true)
		return
	}

	dialCtx, cancel := context.WithTimeout(b.ctx, 15*time.Second)
	up, err := b.dialFn(dialCtx, target.Zone, "tcp", net.JoinHostPort(target.MeshIP, strconv.Itoa(int(id.LocalPort))))
	cancel()
	if err != nil {
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, tErr := r.CreateEndpoint(&wq)
	if tErr != nil {
		r.Complete(true)
		_ = up.Close()
		return
	}
	r.Complete(false)
	down := gonet.NewTCPConn(&wq, ep)
	b.tcpConns.Add(1)

	pipeTCPConns(down, up)
}

func pipeTCPConns(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go copyOne(b, a)
	go copyOne(a, b)
	wg.Wait()
}

func (b *spikeBridge) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dstIP, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return false
	}
	dstIP = dstIP.Unmap()

	isDNS := dstIP == b.dnsIP && id.LocalPort == 53
	var target synthTarget
	if !isDNS {
		target, ok = b.pool.lookupIP(dstIP)
		if !ok {
			return false
		}
	}

	var wq waiter.Queue
	ep, tErr := r.CreateEndpoint(&wq)
	if tErr != nil {
		return true
	}
	down := gonet.NewUDPConn(&wq, ep)
	if isDNS {
		go b.serveDNSUDP(down)
		return true
	}
	b.udpFlows.Add(1)
	go b.relayUDP(down, target, id.LocalPort)
	return true
}

func (b *spikeBridge) serveDNSUDP(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		resp := b.handleSpikeDNS(b.ctx, buf[:n])
		if len(resp) > 0 {
			_, _ = conn.Write(resp)
		}
	}
}

func (b *spikeBridge) serveDNSTCP(conn net.Conn) {
	defer conn.Close()
	var lenBuf [2]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		qLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if qLen == 0 || qLen > 65535 {
			return
		}
		q := make([]byte, qLen)
		if _, err := io.ReadFull(conn, q); err != nil {
			return
		}
		resp := b.handleSpikeDNS(b.ctx, q)
		if len(resp) == 0 {
			return
		}
		pkt := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(pkt[:2], uint16(len(resp)))
		copy(pkt[2:], resp)
		if _, err := conn.Write(pkt); err != nil {
			return
		}
	}
}

func (b *spikeBridge) relayUDP(down net.Conn, target synthTarget, dstPort uint16) {
	dialCtx, cancel := context.WithTimeout(b.ctx, 10*time.Second)
	up, err := b.dialFn(dialCtx, target.Zone, "udp", net.JoinHostPort(target.MeshIP, strconv.Itoa(int(dstPort))))
	cancel()
	if err != nil {
		_ = down.Close()
		return
	}

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = down.Close()
			_ = up.Close()
		})
	}
	defer closeBoth()

	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		defer closeBoth()
		buf := make([]byte, 64<<10)
		for {
			_ = src.SetReadDeadline(time.Now().Add(spikeUDPFallbackIdle))
			n, rerr := src.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(spikeUDPFallbackIdle))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}
	go pump(up, down)
	go pump(down, up)
	wg.Wait()
}

// ------------------------------------------------------------------ CLI --

func spikeInitCmd(args []string, o options) error {
	if len(args) != 2 {
		return errorf("usage: hogman-join spike-init <dir> '<link>' [--no-trust] [--handle H] [--hostname N] [--control-ca FILE]")
	}
	dir, rawLink := args[0], args[1]
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(absDir, "config.json")); err == nil {
		note("spike pen already initialized in %s", absDir)
		return nil
	}

	link, err := ParseLink(rawLink)
	if err != nil {
		return errorf("%v", err)
	}
	client, err := controlClient(o.controlCA)
	if err != nil {
		return err
	}
	step("Checking the network at %s", link.Host)
	n, err := fetchNetwork(client, link.Host)
	if err != nil {
		return err
	}
	if n.DNSServer == "" {
		return errorf("this pen's server is too old (missing dns_server)")
	}
	root, err := CheckRoot(n.RootCA, link.Fingerprint, n.Zone)
	if err != nil {
		return errorf("%v", err)
	}

	certFile, cleanupCert, err := writeTempCert(root.PEM)
	if err != nil {
		return err
	}
	defer cleanupCert()
	if !o.noTrust {
		step("Adding the %s certificate to this computer", n.Zone)
		if err := installTrust(root, certFile); err != nil {
			return err
		}
	}

	key := link.DeviceKey
	if link.InviteToken != "" {
		step("Redeeming the invite")
		en, err := redeemWithHandle(client, link, o)
		if err != nil {
			return err
		}
		key = en.AuthKey
		note("welcome, %s", en.Handle)
	}

	hostname := o.hostname
	if hostname == "" {
		hostname = defaultHostname()
	}
	cfg := &agentConfig{
		Zone:        n.Zone,
		LoginServer: n.LoginServer,
		DNSServer:   n.DNSServer,
		Hostname:    hostname,
	}
	if o.controlCA != "" {
		pemBytes, err := os.ReadFile(o.controlCA)
		if err != nil {
			return errorf("--control-ca: %v", err)
		}
		cfg.ControlCA = string(pemBytes)
	}
	if err := os.MkdirAll(absDir, 0o700); err != nil {
		return err
	}
	if err := cfg.save(absDir); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(absDir, "authkey"), []byte(key), 0o600); err != nil {
		return err
	}
	say("✓ initialized spike state for %s in %s", n.Zone, absDir)
	return nil
}

func spikeTunCmd(args []string, o options) error {
	if len(args) < 1 {
		return errorf("usage: hogman-join spike-tun [--subnet 198.19.0.0/16] [--status-addr 127.0.0.1:19819] <dir1> [<dir2> ...]")
	}
	subnet, localIP, dnsIP, pool, err := parseSpikeSubnet(o.subnet)
	if err != nil {
		return errorf("%v", err)
	}
	statusAddr := o.statusAddr
	if statusAddr == "" {
		statusAddr = spikeDefaultStatusAddr
	}

	var pens []*spikePen
	byZone := map[string]*spikePen{}
	zones := make([]string, 0, len(args))
	for _, dir := range args {
		p, err := loadSpikePen(dir)
		if err != nil {
			return errorf("%v", err)
		}
		if _, dup := byZone[p.cfg.Zone]; dup {
			return errorf("duplicate pen zone %s", p.cfg.Zone)
		}
		byZone[p.cfg.Zone] = p
		pens = append(pens, p)
		zones = append(zones, p.cfg.Zone)
	}

	installCombinedControlCAs(pens)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	step("Starting spike TUN (%s, local %s, dns %s) for %s", subnet, localIP, dnsIP, strings.Join(zones, ", "))
	tunDev, osCleanup, err := setupSpikeTUN(subnet, localIP, dnsIP, spikeMTU, zones)
	if err != nil {
		return errorf("%v", err)
	}
	defer osCleanup()

	ifname, _ := tunDev.Name()
	bridge, err := newSpikeBridge(
		ctx, dnsIP, subnet.Bits(), pool, zones,
		func(lctx context.Context, zone, host string) ([]string, bool, error) {
			p := byZone[zone]
			if p == nil {
				return nil, false, errors.New("unknown pen zone")
			}
			return p.resolveHost(lctx, host)
		},
		func(dctx context.Context, zone, network, addr string) (net.Conn, error) {
			p := byZone[zone]
			if p == nil {
				return nil, errors.New("unknown pen zone")
			}
			p.mu.Lock()
			node := p.node
			up := p.up
			p.mu.Unlock()
			if !up || node == nil {
				return nil, errors.New("pen not connected")
			}
			return node.Dial(dctx, network, addr)
		},
	)
	if err != nil {
		return fmt.Errorf("init netstack bridge: %w", err)
	}
	defer bridge.close()
	bridge.serveTUN(tunDev)

	defer func() {
		for _, p := range pens {
			p.close()
		}
	}()
	for _, p := range pens {
		go func(sp *spikePen) {
			if err := sp.start(ctx); err != nil {
				log.Printf("spike pen %s failed: %v", sp.cfg.Zone, err)
			}
		}(p)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		type penView struct {
			Zone  string   `json:"zone"`
			Up    bool     `json:"up"`
			IPs   []string `json:"ips,omitempty"`
			Error string   `json:"error,omitempty"`
		}
		views := make([]penView, 0, len(pens))
		ready := len(pens) > 0
		for _, p := range pens {
			p.mu.Lock()
			views = append(views, penView{Zone: p.cfg.Zone, Up: p.up, IPs: p.ips, Error: p.err})
			if !p.up {
				ready = false
			}
			p.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ifname":      ifname,
			"subnet":      subnet.String(),
			"local_ip":    localIP.String(),
			"dns_ip":      dnsIP.String(),
			"ready":       ready,
			"pens":        views,
			"mappings":    pool.snapshot(),
			"dns_queries": bridge.dnsQueries.Load(),
			"tcp_conns":   bridge.tcpConns.Load(),
			"udp_flows":   bridge.udpFlows.Load(),
		})
	})

	ln, err := net.Listen("tcp", statusAddr)
	if err != nil {
		return fmt.Errorf("status listener %s: %w", statusAddr, err)
	}
	statusSrv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = statusSrv.Serve(ln) }()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = statusSrv.Shutdown(sctx)
	}()

	say("✓ spike TUN %s up (DNS %s, status http://%s/status)", ifname, dnsIP, statusAddr)
	<-ctx.Done()
	say("stopping spike TUN %s", ifname)
	return nil
}
