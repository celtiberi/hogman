package mobile

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func TestParseLinkValidationAndCaps(t *testing.T) {
	c := NewController()

	inv, err := c.ParseLink("https://bobo.gate.example.com/join#t=secret123")
	if err != nil {
		t.Fatalf("ParseLink(invite): %v", err)
	}
	if inv.Host != "bobo.gate.example.com" || inv.Kind != "invite" || inv.ForShare {
		t.Fatalf("unexpected invite parse: %+v", inv)
	}

	dev, err := c.ParseLink("https://bobo.gate.example.com/join#k=key123")
	if err != nil {
		t.Fatalf("ParseLink(device): %v", err)
	}
	if dev.Kind != "device" {
		t.Fatalf("unexpected device parse: %+v", dev)
	}

	// Server share links must be rejected on mobile.
	if _, err := c.ParseLink("https://bobo.gate.example.com/join#k=key123&for=share"); err == nil {
		t.Fatalf("expected server link to be rejected on mobile")
	}

	// Oversized input must be rejected (never truncated, D-56).
	huge := "https://bobo.gate.example.com/join#t=" + strings.Repeat("a", MaxLinkBytes)
	if _, err := c.ParseLink(huge); err == nil || !strings.Contains(err.Error(), "exceeds maximum length") {
		t.Fatalf("expected max-length rejection, got: %v", err)
	}
}

func TestJoinRejectsCustomControlCAInReleaseBuild(t *testing.T) {
	if allowCustomControlCA {
		t.Skip("running with -tags hogman_mobile_debug")
	}
	c := NewController()
	_, err := c.Join(
		t.TempDir(),
		testKey(3),
		"https://bobo.gate.example.com/join#k=key123",
		"",
		"phone",
		"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
	)
	if err == nil || !strings.Contains(err.Error(), "disabled in release builds") {
		t.Fatalf("expected release custom-CA rejection, got: %v", err)
	}
}

func TestParseUpstreamDNSJSONCapsAndValidation(t *testing.T) {
	got, err := ParseUpstreamDNSJSON(`["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"]`)
	if err != nil || len(got) != 3 {
		t.Fatalf("ParseUpstreamDNSJSON valid = (%v, %v)", got, err)
	}
	if _, err := ParseUpstreamDNSJSON(`["not-an-ip"]`); err == nil {
		t.Fatalf("expected error on invalid IP")
	}
	many := make([]string, MaxUpstreamDNS+1)
	for i := range many {
		many[i] = "1.1.1.1"
	}
	rawMany, _ := json.Marshal(many)
	if _, err := ParseUpstreamDNSJSON(string(rawMany)); err == nil {
		t.Fatalf("expected error on >%d upstream servers", MaxUpstreamDNS)
	}
	if _, err := ParseUpstreamDNSJSON(strings.Repeat(" ", MaxDNSJSONBytes+1)); err == nil {
		t.Fatalf("expected error on oversized upstream_dns_json")
	}
}

func TestComputeTunnelPlanRoutesOnlyInfraAndServerPeersAs32(t *testing.T) {
	infraKey := key.NewNode().Public()
	serverKey := key.NewNode().Public()
	memberKey := key.NewNode().Public()

	infraTags := views.SliceOf([]string{"tag:infra"})
	serverTags := views.SliceOf([]string{"tag:server"})
	st := &ipnstate.Status{
		BackendState: "Running",
		Self: &ipnstate.PeerStatus{
			TailscaleIPs: []netip.Addr{
				netip.MustParseAddr("fd7a:115c:a1e0::12"),
				netip.MustParseAddr("100.64.0.12"),
			},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			infraKey: {
				Online: true,
				Tags:   &infraTags,
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
			},
			serverKey: {
				Online: true,
				Tags:   &serverTags,
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.9"),
					netip.MustParseAddr("fd7a:115c:a1e0::9"),
				},
			},
			memberKey: {
				Online: true,
				// Personal member peer (no infra/server tag): must NOT be routed or allowed!
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.77"),
				},
			},
		},
	}

	selfIP, penDNS, routes, allowed := ComputeTunnelPlan(st, "100.64.0.1")
	if selfIP != netip.MustParseAddr("100.64.0.12") {
		t.Fatalf("selfIP = %v, want 100.64.0.12", selfIP)
	}
	if penDNS != netip.MustParseAddr("100.64.0.1") {
		t.Fatalf("penDNS = %v, want 100.64.0.1", penDNS)
	}

	wantRoutes := []string{
		"100.64.0.1/32",
		"100.64.0.9/32",
		"100.100.100.100/32",
	}
	if !slices.Equal(routes, wantRoutes) {
		t.Fatalf("routes = %v, want %v", routes, wantRoutes)
	}
	if allowed[netip.MustParseAddr("100.64.0.77")] {
		t.Fatalf("member peer IP must not be in allowed DNS set")
	}
	if !allowed[netip.MustParseAddr("100.64.0.1")] || !allowed[netip.MustParseAddr("100.64.0.9")] {
		t.Fatalf("expected infra and server peers in allowed set: %v", allowed)
	}
}

func TestListPensAndForceLeaveLocalCleanup(t *testing.T) {
	c := NewController()
	dataDir := t.TempDir()
	key := testKey(5)

	for _, zone := range []string{"zeta.pens.example.com", "alpha.pens.example.com"} {
		dir := penDirPath(dataDir, zone)
		if err := savePenMeta(dir, &PenMeta{
			Zone:        zone,
			LoginServer: "https://gate.example.com",
			Portal:      "https://home." + zone,
			DNSServer:   "100.64.0.1",
			Hostname:    "phone",
		}); err != nil {
			t.Fatal(err)
		}
	}

	pens, err := c.ListPens(dataDir)
	if err != nil {
		t.Fatalf("ListPens: %v", err)
	}
	if len(pens) != 2 || pens[0].Zone != "alpha.pens.example.com" || pens[1].Zone != "zeta.pens.example.com" {
		t.Fatalf("ListPens = %+v", pens)
	}

	// Non-force leave while disconnected must refuse cleanly.
	if err := c.Leave(dataDir, key, "alpha.pens.example.com", false); err == nil {
		t.Fatalf("expected non-force leave while disconnected to refuse")
	}

	// Force leave removes the pen directory cleanly.
	if err := c.Leave(dataDir, key, "alpha.pens.example.com", true); err != nil {
		t.Fatalf("force Leave: %v", err)
	}
	if _, err := os.Stat(penDirPath(dataDir, "alpha.pens.example.com")); !os.IsNotExist(err) {
		t.Fatalf("expected pen dir removed after force leave, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(penDirPath(dataDir, "zeta.pens.example.com"), penMetaFilename)); err != nil {
		t.Fatalf("unrelated pen should remain intact: %v", err)
	}
}

type mockTUN struct {
	packets chan []byte
	closed  chan struct{}
	events  chan tun.Event
}

func newMockTUN() *mockTUN {
	return &mockTUN{
		packets: make(chan []byte, 4),
		closed:  make(chan struct{}),
		events:  make(chan tun.Event, 2),
	}
}

func (m *mockTUN) File() *os.File { return nil }
func (m *mockTUN) Read(slab []byte, pkts []tun.ReadPacket) (int, error) {
	select {
	case <-m.closed:
		return 0, os.ErrClosed
	case b := <-m.packets:
		n := copy(slab[tun.ReadPacketSpacing:], b)
		pkts[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: n}
		return 1, nil
	}
}
func (m *mockTUN) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }
func (m *mockTUN) MTU() (int, error)                       { return 1280, nil }
func (m *mockTUN) Name() (string, error)                   { return "mock0", nil }
func (m *mockTUN) Events() <-chan tun.Event                { return m.events }
func (m *mockTUN) BatchSize() int                          { return 1 }
func (m *mockTUN) Close() error {
	select {
	case <-m.closed:
	default:
		close(m.closed)
	}
	return nil
}

func TestSwappableTUNAttachSwapAndClose(t *testing.T) {
	sw := NewSwappableTUN(1280)
	defer sw.Close()

	readDone := make(chan string, 2)
	go func() {
		slab := make([]byte, 2048)
		pkts := make([]tun.ReadPacket, 1)
		for {
			n, err := sw.Read(slab, pkts)
			if err != nil {
				return
			}
			if n == 1 {
				p := pkts[0]
				readDone <- string(slab[p.Offset : p.Offset+p.Size])
			}
		}
	}()

	// Attach first TUN and send a packet.
	t1 := newMockTUN()
	if err := sw.Attach(t1); err != nil {
		t.Fatalf("Attach(t1): %v", err)
	}
	t1.packets <- []byte("pkt-1")
	select {
	case got := <-readDone:
		if got != "pkt-1" {
			t.Fatalf("got %q, want pkt-1", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out reading pkt-1")
	}

	// Swap to second TUN; first TUN is closed and Read continues seamlessly.
	t2 := newMockTUN()
	if err := sw.Attach(t2); err != nil {
		t.Fatalf("Attach(t2): %v", err)
	}
	t2.packets <- []byte("pkt-2")
	select {
	case got := <-readDone:
		if got != "pkt-2" {
			t.Fatalf("got %q, want pkt-2", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out reading pkt-2 after swap")
	}
}

func TestSelfDeleteOverTunnelFailsClosedWithoutConfirmedRoutesOrTUN(t *testing.T) {
	selfIP := netip.MustParseAddr("100.64.0.12")
	homeIP := netip.MustParseAddr("100.64.0.1")

	// Unconfirmed routes must refuse immediately before creating any socket.
	if err := selfDeleteOverTunnel("bobo.pens.example.com", selfIP, homeIP, "utun99", false, false); err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("expected unconfirmed-routes error, got: %v", err)
	}

	// Confirmed routes with a nonexistent TUN interface / inactive IP must fail closed.
	if err := selfDeleteOverTunnel("bobo.pens.example.com", selfIP, homeIP, "nonexistent_tun_99", true, false); err == nil {
		t.Fatalf("expected fail-closed error when TUN interface does not exist")
	}
}

func TestComputeTunnelPlanEnforces10064CGNATRange(t *testing.T) {
	infraKey := key.NewNode().Public()
	serverKey := key.NewNode().Public()
	infraTags := views.SliceOf([]string{"tag:infra"})
	serverTags := views.SliceOf([]string{"tag:server"})

	// 1. Public/LAN peer IPs and non-CGNAT configured DNS must never enter routes or allowed set.
	st := &ipnstate.Status{
		BackendState: "Running",
		Self: &ipnstate.PeerStatus{
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.12")},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			infraKey: {
				Online: true,
				Tags:   &infraTags,
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("8.8.8.8"),
					netip.MustParseAddr("100.64.0.1"),
				},
			},
			serverKey: {
				Online: true,
				Tags:   &serverTags,
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("1.1.1.1"),
					netip.MustParseAddr("192.168.1.50"),
					netip.MustParseAddr("100.127.255.254"),
					netip.MustParseAddr("100.128.0.1"), // just outside 100.64.0.0/10
				},
			},
		},
	}

	selfIP, penDNS, routes, allowed := ComputeTunnelPlan(st, "8.8.8.8")
	if selfIP != netip.MustParseAddr("100.64.0.12") {
		t.Fatalf("selfIP = %v, want 100.64.0.12", selfIP)
	}
	if penDNS.IsValid() {
		t.Fatalf("non-CGNAT configuredDNS 8.8.8.8 must be rejected, got %v", penDNS)
	}
	wantRoutes := []string{
		"100.64.0.1/32",
		"100.100.100.100/32",
		"100.127.255.254/32",
	}
	if !slices.Equal(routes, wantRoutes) {
		t.Fatalf("routes = %v, want %v", routes, wantRoutes)
	}
	for _, bad := range []string{"8.8.8.8", "1.1.1.1", "192.168.1.50", "100.128.0.1"} {
		if allowed[netip.MustParseAddr(bad)] {
			t.Fatalf("non-CGNAT IP %s must not enter allowed DNS set", bad)
		}
	}

	// 2. Non-CGNAT self IP must invalidate the entire tunnel plan.
	stBadSelf := &ipnstate.Status{
		BackendState: "Running",
		Self: &ipnstate.PeerStatus{
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("8.8.4.4")},
		},
		Peer: st.Peer,
	}
	badSelf, badDNS, badRoutes, badAllowed := ComputeTunnelPlan(stBadSelf, "100.64.0.1")
	if badSelf.IsValid() || badDNS.IsValid() || len(badRoutes) != 0 || len(badAllowed) != 0 {
		t.Fatalf("expected empty plan for non-CGNAT self IP, got self=%v dns=%v routes=%v allowed=%v",
			badSelf, badDNS, badRoutes, badAllowed)
	}
}

func TestLoadPenMetaCanonicalizesPortalFromZone(t *testing.T) {
	dir := t.TempDir()
	raw := `{"zone":"bobo.pens.example.com","login_server":"https://bobo.gate.example.com","portal":"market://details?id=evil","dns_server":"100.64.0.1","hostname":"phone"}`
	if err := os.WriteFile(filepath.Join(dir, penMetaFilename), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	meta, err := loadPenMeta(dir)
	if err != nil {
		t.Fatalf("loadPenMeta: %v", err)
	}
	if meta.Portal != "https://home.bobo.pens.example.com" {
		t.Fatalf("Portal = %q, want canonical https://home.bobo.pens.example.com", meta.Portal)
	}
}
