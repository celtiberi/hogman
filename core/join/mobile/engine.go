package mobile

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	tsdns "tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/router"

	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/peerstatus"
	"hogman/join/internal/penapi"
)

const (
	penMetaFilename = "pen.json"
	iosMemoryLimit  = 28 << 20 // 28 MiB soft Go limit under iOS 50 MB Jetsam ceiling
	iosGCPercent    = 25
)

// meshCGNATPrefix is RFC 6598 (100.64.0.0/10), the only IPv4 range permitted
// for Hogman WireGuard self addresses, pen DNS, and per-peer /32 tunnel routes.
var meshCGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")

func isMeshCGNATIPv4(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.Is4() && meshCGNATPrefix.Contains(ip)
}

func canonicalPortalURL(zone string) string {
	return "https://home." + zone
}

// PenMeta stores one enrolled mobile pen's non-secret metadata on disk.
// WireGuard/Tailscale keys and pending authkeys are stored encrypted separately.
type PenMeta struct {
	Zone        string `json:"zone"`
	LoginServer string `json:"login_server"`
	Portal      string `json:"portal"`
	DNSServer   string `json:"dns_server"`
	Hostname    string `json:"hostname"`
	Handle      string `json:"handle,omitempty"`
	ControlCA   string `json:"control_ca,omitempty"` // debug/staging builds only
}

// ParsedLink describes a validated join link without exposing secret tokens.
type ParsedLink struct {
	Host     string `json:"host"`
	Kind     string `json:"kind"` // "invite" (#t=) or "device" (#k=)
	ForShare bool   `json:"for_share"`
}

// TunnelReconfig is passed to the platform VPN callback whenever self IP,
// DNS peer, or reachable tag:infra / tag:server /32 peer routes change.
type TunnelReconfig struct {
	Zone       string   `json:"zone"`
	SelfIPv4   string   `json:"self_ipv4"`
	DNSIP      string   `json:"dns_ip"`
	DNSStubIP  string   `json:"dns_stub_ip"`
	MTU        int      `json:"mtu"`
	PeerRoutes []string `json:"peer_routes"` // exact /32 routes only
}

// TunnelStatus reports the active tunnel's current state to the mobile UI.
type TunnelStatus struct {
	State      string   `json:"state"` // "disconnected", "connecting", "connected", "removed", "error"
	Zone       string   `json:"zone,omitempty"`
	Portal     string   `json:"portal,omitempty"`
	SelfIPv4   string   `json:"self_ipv4,omitempty"`
	DNSIP      string   `json:"dns_ip,omitempty"`
	PeerRoutes []string `json:"peer_routes,omitempty"`
	NeedsLogin bool     `json:"needs_login,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// TunnelCallbacks connects libhogman to platform VPN primitives.
type TunnelCallbacks struct {
	// ProtectFD exempts an outbound socket fd from the OS VPN (Android VpnService.protect).
	ProtectFD func(fd int) error
	// ReconfigVPN applies TUN address, DNS, and per-peer /32 routes on the OS.
	// Return values:
	//   >= 0: new TUN fd to attach to SwappableTUN (Android VpnService.Builder.establish)
	//   -1:   routes updated in place; keep existing TUN fd (iOS setTunnelNetworkSettings)
	//   -2:   fatal OS VPN error; stop the tunnel immediately
	ReconfigVPN func(cfg TunnelReconfig) int
}

// Controller manages Hogman Mobile pen enrollment and the single active tunnel.
type Controller struct {
	mu       sync.Mutex
	active   *activeTunnel
	lastStat TunnelStatus
}

type activeTunnel struct {
	zone       string
	portal     string
	penDir     string
	controlCA  string
	mtu        int
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	swappable  *SwappableTUN
	dnsStub    *SplitDNSStub
	netMon     *netmon.Monitor
	eng        wgengine.Engine
	lb         *ipnlocal.LocalBackend
	store      *EncryptedStateStore
	protectFn  func(int) error
	reconfigFn func(TunnelReconfig) int

	mu              sync.Mutex
	lastReconfig    TunnelReconfig
	penDNS          netip.Addr
	selfIPv4        netip.Addr
	routesConfirmed bool
}

// NewController creates a mobile controller with disconnected initial state.
func NewController() *Controller {
	return &Controller{
		lastStat: TunnelStatus{State: "disconnected"},
	}
}

func noopLogf(string, ...any) {}

func penDirPath(dataDir, zone string) string {
	return filepath.Join(dataDir, "pens", zone)
}

func loadPenMeta(dir string) (*PenMeta, error) {
	b, err := os.ReadFile(filepath.Join(dir, penMetaFilename))
	if err != nil {
		return nil, err
	}
	var m PenMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if zone, err := validateZoneName(m.Zone); err == nil {
		m.Zone = zone
		// Always derive Portal from the validated zone rather than trusting a
		// server-supplied URL (prevents tel:/market:/intent: scheme injection).
		m.Portal = canonicalPortalURL(zone)
	}
	return &m, nil
}

func savePenMeta(dir string, m *PenMeta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, penMetaFilename), b, 0o600)
}

// ParseLink validates a join link without returning any secret tokens or keys.
func (c *Controller) ParseLink(rawLink string) (*ParsedLink, error) {
	if err := checkMaxLen("link", rawLink, MaxLinkBytes); err != nil {
		return nil, err
	}
	l, err := link.Parse(rawLink)
	if err != nil {
		return nil, err
	}
	if l.ForShare {
		return nil, errors.New("that is a server link; mobile devices join with a personal or invite link")
	}
	kind := "device"
	if l.InviteToken != "" {
		kind = "invite"
	}
	return &ParsedLink{
		Host:     l.Host,
		Kind:     kind,
		ForShare: l.ForShare,
	}, nil
}

// Join validates rawLink, fetches network metadata, redeems an invite (#t=) if
// needed, and saves the pen metadata plus AEAD-encrypted one-time authkey.
// stateKey must be 32 bytes; Join never retains stateKey after returning.
func (c *Controller) Join(dataDir string, stateKey []byte, rawLink, handle, deviceName, controlCAPEM string) (*PenMeta, error) {
	if err := checkMaxLen("data_dir", dataDir, MaxDataDirBytes); err != nil {
		return nil, err
	}
	if err := checkMaxLen("link", rawLink, MaxLinkBytes); err != nil {
		return nil, err
	}
	if err := checkMaxLen("handle", handle, MaxShortBytes); err != nil {
		return nil, err
	}
	if err := checkMaxLen("device_name", deviceName, MaxShortBytes); err != nil {
		return nil, err
	}
	if err := checkMaxLen("control_ca_pem", controlCAPEM, MaxCAPEMBytes); err != nil {
		return nil, err
	}
	if err := validateStateKey(stateKey); err != nil {
		return nil, err
	}
	controlCAPEM = strings.TrimSpace(controlCAPEM)
	if controlCAPEM != "" && !allowCustomControlCA {
		return nil, errors.New("custom control CA is disabled in release builds")
	}
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("data_dir is required")
	}

	l, err := link.Parse(rawLink)
	if err != nil {
		return nil, err
	}
	if l.ForShare {
		return nil, errors.New("that is a server link; mobile devices join with a personal or invite link")
	}

	client, err := controlHTTPClient(controlCAPEM)
	if err != nil {
		return nil, err
	}
	netInfo, err := penapi.FetchNetwork(client, l.Host)
	if err != nil {
		return nil, err
	}
	zone, err := validateZoneName(netInfo.Zone)
	if err != nil {
		return nil, err
	}

	authKey := l.DeviceKey
	resolvedHandle := ""
	if l.InviteToken != "" {
		h := strings.ToLower(strings.TrimSpace(handle))
		if !link.HandleRE.MatchString(h) {
			return nil, errors.New("choose a handle: 2-32 lowercase letters, digits, or dashes, starting with a letter")
		}
		en, err := penapi.Redeem(client, l.Host, l.InviteToken, h)
		if err != nil {
			return nil, err
		}
		authKey = en.AuthKey
		resolvedHandle = en.Handle
	}
	if strings.TrimSpace(authKey) == "" {
		return nil, errors.New("no enrollment key available")
	}

	hostname, err := resolveMobileHostname(deviceName)
	if err != nil {
		return nil, err
	}

	dir := penDirPath(dataDir, zone)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	meta := &PenMeta{
		Zone:        zone,
		LoginServer: netInfo.LoginServer,
		Portal:      canonicalPortalURL(zone),
		DNSServer:   netInfo.DNSServer,
		Hostname:    hostname,
		Handle:      resolvedHandle,
	}
	if allowCustomControlCA && controlCAPEM != "" {
		meta.ControlCA = controlCAPEM
	}
	// Reset stale encrypted node state when re-enrolling with a fresh key.
	_ = os.Remove(filepath.Join(dir, encryptedStoreFilename))

	if err := savePenMeta(dir, meta); err != nil {
		return nil, err
	}
	authPath := filepath.Join(dir, encryptedAuthKeyFile)
	authBytes := []byte(authKey)
	err = saveEncryptedSecret(authPath, stateKey, []byte("hogman-authkey:"+zone), authBytes)
	clear(authBytes)
	if err != nil {
		return nil, err
	}
	return meta, nil
}

// ListPens returns all enrolled pens sorted by zone name.
func (c *Controller) ListPens(dataDir string) ([]PenMeta, error) {
	if err := checkMaxLen("data_dir", dataDir, MaxDataDirBytes); err != nil {
		return nil, err
	}
	pensRoot := filepath.Join(dataDir, "pens")
	entries, err := os.ReadDir(pensRoot)
	if os.IsNotExist(err) {
		return []PenMeta{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]PenMeta, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		meta, err := loadPenMeta(filepath.Join(pensRoot, e.Name()))
		if err != nil || meta.Zone == "" {
			continue
		}
		out = append(out, *meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Zone < out[j].Zone })
	return out, nil
}

// StartTunnel activates the split-tunnel engine for zone. If another pen tunnel
// is already running, it is stopped cleanly first.
func (c *Controller) StartTunnel(dataDir string, stateKey []byte, zone string, mtu int, upstreamDNS []netip.Addr, cb TunnelCallbacks) error {
	if err := checkMaxLen("data_dir", dataDir, MaxDataDirBytes); err != nil {
		return err
	}
	if err := validateStateKey(stateKey); err != nil {
		return err
	}
	zone, err := validateZoneName(zone)
	if err != nil {
		return err
	}
	if mtu <= 0 {
		mtu = DefaultTunnelMTU
	}
	if mtu < MinTunnelMTU || mtu > MaxTunnelMTU {
		return fmt.Errorf("mtu must be between %d and %d (got %d)", MinTunnelMTU, MaxTunnelMTU, mtu)
	}

	// Tune Go GC aggressively on iOS to stay well below the 50 MB Jetsam ceiling.
	if runtime.GOOS == "ios" {
		debug.SetMemoryLimit(iosMemoryLimit)
		debug.SetGCPercent(iosGCPercent)
	}
	// Android and iOS app sandboxes leave HOME, XDG_CACHE_HOME, and TMPDIR unset
	// (with cwd="/"), which causes Tailscale's logpolicy to panic when probing
	// for a writable state directory. Point them inside the app's private dataDir.
	if runtime.GOOS == "android" || runtime.GOOS == "ios" {
		runtimeDir := filepath.Join(dataDir, "runtime")
		if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
			return fmt.Errorf("create runtime dir: %w", err)
		}
		for _, k := range []string{"TS_LOGS_DIR", "TMPDIR", "XDG_CACHE_HOME", "HOME"} {
			if os.Getenv(k) == "" {
				_ = os.Setenv(k, runtimeDir)
			}
		}
	}

	c.StopTunnel()

	dir := penDirPath(dataDir, zone)
	meta, err := loadPenMeta(dir)
	if err != nil {
		return fmt.Errorf("pen %s is not enrolled: %w", zone, err)
	}

	var extraCAs *x509.CertPool
	if allowCustomControlCA && meta.ControlCA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(meta.ControlCA)) {
			return errors.New("stored control CA is invalid PEM")
		}
		extraCAs = pool
	}

	encStore, err := NewEncryptedStateStore(dir, zone, stateKey)
	if err != nil {
		return err
	}

	authPath := filepath.Join(dir, encryptedAuthKeyFile)
	authKey := ""
	if rawKey, err := loadEncryptedSecret(authPath, stateKey, []byte("hogman-authkey:"+zone)); err == nil {
		authKey = strings.TrimSpace(string(rawKey))
		clear(rawKey)
	} else if !os.IsNotExist(err) {
		encStore.Close()
		return fmt.Errorf("load pending enrollment key: %w", err)
	}

	registerPlatformProtectFunc(cb.ProtectFD)

	sys := tsd.NewSystem()
	netMon, err := netmon.New(sys.Bus.Get(), noopLogf)
	if err != nil {
		encStore.Close()
		return fmt.Errorf("netmon: %w", err)
	}

	dialer := &tsdial.Dialer{Logf: noopLogf}
	dialer.SetBus(sys.Bus.Get())

	swappable := NewSwappableTUN(mtu)
	fakeRouter := router.NewFake(noopLogf)
	noopDNS, err := tsdns.NewNoopManager()
	if err != nil {
		_ = swappable.Close()
		_ = netMon.Close()
		encStore.Close()
		return fmt.Errorf("dns manager: %w", err)
	}

	eng, err := wgengine.NewUserspaceEngine(noopLogf, wgengine.Config{
		Tun:           swappable,
		Router:        fakeRouter,
		DNS:           noopDNS,
		EventBus:      sys.Bus.Get(),
		NetMon:        netMon,
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		ControlKnobs:  sys.ControlKnobs(),
		HealthTracker: sys.HealthTracker.Get(),
		ExtraRootCAs:  extraCAs,
		Metrics:       sys.UserMetricsRegistry(),
	})
	if err != nil {
		_ = swappable.Close()
		_ = netMon.Close()
		encStore.Close()
		return fmt.Errorf("wgengine: %w", err)
	}
	sys.Set(eng)
	sys.Set(encStore)

	dnsStub := NewSplitDNSStub(zone, cb.ProtectFD)
	if u, err := url.Parse(meta.LoginServer); err == nil && u.Hostname() != "" {
		dnsStub.SetLoginHost(u.Hostname())
	}
	dnsStub.UpdateUpstream(upstreamDNS)

	tundev := sys.Tun.Get()
	dnsStub.AttachTunnel(tundev)
	tundev.Start()

	privLogID, err := logid.NewPrivateID()
	if err != nil {
		eng.Close()
		_ = swappable.Close()
		_ = netMon.Close()
		encStore.Close()
		return fmt.Errorf("logid: %w", err)
	}
	lb, err := ipnlocal.NewLocalBackend(noopLogf, privLogID.Public(), sys, controlclient.LoginDefault|controlclient.LocalBackendStartKeyOSNeutral)
	if err != nil {
		eng.Close()
		_ = swappable.Close()
		_ = netMon.Close()
		encStore.Close()
		return fmt.Errorf("local backend: %w", err)
	}
	lb.SetVarRoot(dir)

	prefs := ipn.NewPrefs()
	prefs.Hostname = meta.Hostname
	prefs.WantRunning = true
	prefs.ControlURL = meta.LoginServer
	prefs.CorpDNS = false
	prefs.RouteAll = false

	if err := lb.Start(ipn.Options{
		UpdatePrefs: prefs,
		AuthKey:     authKey,
	}); err != nil {
		lb.Shutdown()
		eng.Close()
		_ = swappable.Close()
		_ = netMon.Close()
		encStore.Close()
		return fmt.Errorf("start backend: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if authKey != "" && lb.State() == ipn.NeedsLogin {
		if err := lb.StartLoginInteractive(ctx); err != nil {
			cancel()
			lb.Shutdown()
			eng.Close()
			_ = swappable.Close()
			_ = netMon.Close()
			encStore.Close()
			return fmt.Errorf("start login: %w", err)
		}
	}
	at := &activeTunnel{
		zone:       zone,
		portal:     meta.Portal,
		penDir:     dir,
		controlCA:  meta.ControlCA,
		mtu:        mtu,
		ctx:        ctx,
		cancel:     cancel,
		done:       make(chan struct{}),
		swappable:  swappable,
		dnsStub:    dnsStub,
		netMon:     netMon,
		eng:        eng,
		lb:         lb,
		store:      encStore,
		protectFn:  cb.ProtectFD,
		reconfigFn: cb.ReconfigVPN,
	}

	c.mu.Lock()
	c.active = at
	c.lastStat = TunnelStatus{
		State:  "connecting",
		Zone:   zone,
		Portal: meta.Portal,
	}
	c.mu.Unlock()

	go c.watchTunnel(at, meta, authKey != "")
	return nil
}

func (c *Controller) watchTunnel(at *activeTunnel, meta *PenMeta, hadAuthKey bool) {
	defer close(at.done)

	// Freshly enrolled devices start in NeedsLogin while Headscale exchanges the
	// one-time authkey; already-enrolled devices start authorized, so NeedsLogin
	// immediately indicates removal.
	sawStarting := !hadAuthKey
	at.lb.WatchNotifications(at.ctx, ipn.NotifyInitialState, nil, func(n *ipn.Notify) bool {
		if at.ctx.Err() != nil {
			return false
		}
		if n.ErrMessage != nil && *n.ErrMessage != "" {
			c.setStatusIfActive(at, TunnelStatus{
				State:  "error",
				Zone:   at.zone,
				Portal: at.portal,
				Error:  *n.ErrMessage,
			})
			return true
		}
		if n.State != nil {
			switch *n.State {
			case ipn.Starting, ipn.Running:
				sawStarting = true
			case ipn.NeedsLogin:
				if sawStarting {
					c.setStatusIfActive(at, TunnelStatus{
						State:      "removed",
						Zone:       at.zone,
						Portal:     at.portal,
						NeedsLogin: true,
						Error:      peerstatus.ErrDeviceRemoved.Error(),
					})
					return false
				}
			}
		}
		if n.BrowseToURL != nil && *n.BrowseToURL != "" {
			errMsg := peerstatus.ErrDeviceRemoved.Error()
			if hadAuthKey && !sawStarting {
				errMsg = "enrollment key was rejected or expired; create a new link on home." + at.zone
			}
			c.setStatusIfActive(at, TunnelStatus{
				State:      "removed",
				Zone:       at.zone,
				Portal:     at.portal,
				NeedsLogin: true,
				Error:      errMsg,
			})
			return false
		}

		st := at.lb.Status()
		if st == nil {
			return true
		}
		if st.BackendState == "NeedsLogin" && sawStarting {
			c.setStatusIfActive(at, TunnelStatus{
				State:      "removed",
				Zone:       at.zone,
				Portal:     at.portal,
				NeedsLogin: true,
				Error:      peerstatus.ErrDeviceRemoved.Error(),
			})
			return false
		}
		if st.BackendState != "Running" {
			return true
		}

		// Delete pending one-time authkey as soon as Headscale enrollment succeeds.
		_ = os.Remove(filepath.Join(at.penDir, encryptedAuthKeyFile))

		selfIPv4, penDNS, peerRoutes, allowedPeers := ComputeTunnelPlan(st, meta.DNSServer)
		if !selfIPv4.IsValid() {
			return true
		}

		reconfig := TunnelReconfig{
			Zone:       at.zone,
			SelfIPv4:   selfIPv4.String(),
			DNSIP:      addrString(penDNS),
			DNSStubIP:  SplitDNSStubIP.String(),
			MTU:        at.mtu,
			PeerRoutes: peerRoutes,
		}

		at.mu.Lock()
		changed := !reconfigEqual(at.lastReconfig, reconfig)
		confirmed := at.routesConfirmed
		at.mu.Unlock()

		if changed {
			// Fail closed while OS VPN routes are being applied or updated.
			confirmed = false
			at.dnsStub.UpdatePen(selfIPv4, penDNS, allowedPeers, false)
			if at.reconfigFn != nil {
				fd := at.reconfigFn(reconfig)
				switch {
				case fd >= 0:
					if err := at.swappable.AttachFD(fd); err != nil {
						at.mu.Lock()
						at.routesConfirmed = false
						at.mu.Unlock()
						c.setStatusIfActive(at, TunnelStatus{
							State:  "error",
							Zone:   at.zone,
							Portal: at.portal,
							Error:  fmt.Sprintf("attach TUN fd: %v", err),
						})
						return false
					}
					confirmed = true
				case fd == -1:
					confirmed = true
				default:
					at.mu.Lock()
					at.routesConfirmed = false
					at.mu.Unlock()
					c.setStatusIfActive(at, TunnelStatus{
						State:  "error",
						Zone:   at.zone,
						Portal: at.portal,
						Error:  "platform VPN configuration failed",
					})
					return false
				}
			} else {
				confirmed = true
			}
		}

		at.mu.Lock()
		if changed {
			at.lastReconfig = reconfig
		}
		at.penDNS = penDNS
		at.selfIPv4 = selfIPv4
		at.routesConfirmed = confirmed
		at.mu.Unlock()

		at.dnsStub.UpdatePen(selfIPv4, penDNS, allowedPeers, confirmed)

		c.setStatusIfActive(at, TunnelStatus{
			State:      "connected",
			Zone:       at.zone,
			Portal:     at.portal,
			SelfIPv4:   reconfig.SelfIPv4,
			DNSIP:      reconfig.DNSIP,
			PeerRoutes: peerRoutes,
		})
		return true
	})
}

func (c *Controller) setStatusIfActive(at *activeTunnel, st TunnelStatus) {
	c.mu.Lock()
	if c.active == at {
		c.lastStat = st
	}
	c.mu.Unlock()
}

// ComputeTunnelPlan extracts the device's IPv4 mesh address, the verified
// tag:infra DNS server IPv4, sorted exact /32 routes for active tag:infra and
// tag:server peers plus SplitDNSStubIP, and the allowed-peer set for DNS filtering.
// Every accepted address is strictly constrained to RFC 6598 (100.64.0.0/10)
// so a compromised control plane cannot hijack public internet or LAN IPs.
func ComputeTunnelPlan(st *ipnstate.Status, configuredDNS string) (selfIPv4, penDNS netip.Addr, routes []string, allowed map[netip.Addr]bool) {
	allowed = make(map[netip.Addr]bool)
	if st == nil {
		return netip.Addr{}, netip.Addr{}, nil, allowed
	}
	if st.Self != nil {
		for _, ip := range st.Self.TailscaleIPs {
			ip = ip.Unmap()
			if isMeshCGNATIPv4(ip) {
				selfIPv4 = ip
				break
			}
		}
	}
	if !isMeshCGNATIPv4(selfIPv4) {
		return netip.Addr{}, netip.Addr{}, nil, allowed
	}
	if ip, ok := peerstatus.ResolvePenDNSIP(st, configuredDNS); ok && isMeshCGNATIPv4(ip) {
		penDNS = ip.Unmap()
		allowed[penDNS] = true
	}
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		if !peerstatus.PeerHasTag(p, "tag:infra") && !peerstatus.PeerHasTag(p, "tag:server") {
			continue
		}
		for _, raw := range p.TailscaleIPs {
			ip := raw.Unmap()
			if isMeshCGNATIPv4(ip) {
				allowed[ip] = true
			}
		}
	}
	routeSet := make(map[netip.Addr]struct{}, len(allowed)+1)
	for ip := range allowed {
		routeSet[ip] = struct{}{}
	}
	routeSet[SplitDNSStubIP] = struct{}{}

	addrs := make([]netip.Addr, 0, len(routeSet))
	for ip := range routeSet {
		addrs = append(addrs, ip)
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	routes = make([]string, 0, len(addrs))
	for _, ip := range addrs {
		routes = append(routes, ip.String()+"/32")
	}
	return selfIPv4, penDNS, routes, allowed
}

func addrString(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

func reconfigEqual(a, b TunnelReconfig) bool {
	return a.Zone == b.Zone &&
		a.SelfIPv4 == b.SelfIPv4 &&
		a.DNSIP == b.DNSIP &&
		a.DNSStubIP == b.DNSStubIP &&
		a.MTU == b.MTU &&
		slices.Equal(a.PeerRoutes, b.PeerRoutes)
}

// UpdateNetwork refreshes the upstream DNS servers used by the Android
// split-DNS stub and nudges netmon/WireGuard on network link changes.
func (c *Controller) UpdateNetwork(upstreamDNS []netip.Addr, linkChanged bool) {
	c.mu.Lock()
	at := c.active
	c.mu.Unlock()
	if at == nil {
		return
	}
	at.dnsStub.UpdateUpstream(upstreamDNS)
	if linkChanged && at.netMon != nil {
		at.netMon.InjectEvent()
	}
}

// Status returns a snapshot of the active tunnel status.
func (c *Controller) Status() TunnelStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.lastStat
	if len(st.PeerRoutes) > 0 {
		cp := make([]string, len(st.PeerRoutes))
		copy(cp, st.PeerRoutes)
		st.PeerRoutes = cp
	}
	return st
}

// StopTunnel tears down the active tunnel (if any) and wipes the in-memory DEK.
func (c *Controller) StopTunnel() {
	c.mu.Lock()
	at := c.active
	c.active = nil
	c.lastStat = TunnelStatus{State: "disconnected"}
	c.mu.Unlock()

	if at == nil {
		return
	}
	at.cancel()
	select {
	case <-at.done:
	case <-time.After(6 * time.Second):
	}
	if at.lb != nil {
		at.lb.Shutdown()
	}
	if at.eng != nil {
		at.eng.Close()
	}
	if at.swappable != nil {
		_ = at.swappable.Close()
	}
	if at.netMon != nil {
		_ = at.netMon.Close()
	}
	if at.store != nil {
		at.store.Close()
	}
	registerPlatformProtectFunc(nil)
}

// Leave removes this device from zone. When the tunnel is currently connected
// to zone, it checks sole-owner lockout protection (unless force is true) and
// calls DELETE /api/devices/<self> before removing local state.
func (c *Controller) Leave(dataDir string, stateKey []byte, zone string, force bool) error {
	if err := checkMaxLen("data_dir", dataDir, MaxDataDirBytes); err != nil {
		return err
	}
	if err := validateStateKey(stateKey); err != nil {
		return err
	}
	zone, err := validateZoneName(zone)
	if err != nil {
		return err
	}
	dir := penDirPath(dataDir, zone)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("this device is not in pen %s", zone)
	}

	c.mu.Lock()
	at := c.active
	stat := c.lastStat
	c.mu.Unlock()

	if at != nil && at.zone == zone && stat.State == "connected" && !stat.NeedsLogin {
		at.mu.Lock()
		penDNS := at.penDNS
		selfIPv4 := at.selfIPv4
		routesConfirmed := at.routesConfirmed
		at.mu.Unlock()
		tunName, _ := at.swappable.Name()
		if err := selfDeleteOverTunnel(zone, selfIPv4, penDNS, tunName, routesConfirmed, force); err != nil && !force {
			return err
		}
		c.StopTunnel()
	} else if !force && (at == nil || at.zone != zone || !stat.NeedsLogin) {
		return fmt.Errorf("connect to %s first so this device can be removed cleanly, or confirm force leave by typing %s", zone, zone)
	} else if at != nil && at.zone == zone {
		c.StopTunnel()
	}

	return os.RemoveAll(dir)
}

func selfDeleteOverTunnel(zone string, selfIPv4, homeIP netip.Addr, tunName string, routesConfirmed, force bool) error {
	if !routesConfirmed {
		return errors.New("pen tunnel routes are not confirmed yet")
	}
	if !homeIP.IsValid() || !homeIP.Is4() {
		return errors.New("pen home server IP is not available")
	}
	dialer, err := newTunnelBoundDialer(selfIPv4, tunName, 5*time.Second)
	if err != nil {
		return fmt.Errorf("bind leave request to pen tunnel: %w", err)
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(homeIP.String(), "443"))
		},
		TLSClientConfig: &tls.Config{
			ServerName: "home." + zone,
			MinVersion: tls.VersionTLS12,
		},
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Timeout: 8 * time.Second, Transport: tr}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var me penapi.MeView
	if _, err := penapi.HomeAPICtx(ctx, hc, zone, http.MethodGet, "/me", nil, &me); err != nil {
		return fmt.Errorf("could not verify membership on %s: %w", zone, err)
	}
	if !force && isSoleOwnerLastDevice(&me) {
		return fmt.Errorf("you are the sole owner of %s and this is your last personal device; add another owner first, or confirm force leave by typing %s", zone, zone)
	}
	if me.ThisDevice.ID <= 0 {
		return errors.New("pen did not report this device's ID")
	}
	delCtx, delCancel := context.WithTimeout(context.Background(), penapi.SelfDeleteTimeout)
	defer delCancel()
	code, err := penapi.HomeAPICtx(delCtx, hc, zone, http.MethodDelete, fmt.Sprintf("/devices/%d", me.ThisDevice.ID), nil, nil)
	if err != nil && code != http.StatusNotFound && code != 0 {
		return fmt.Errorf("could not remove device from %s: %w", zone, err)
	}
	return nil
}

func isSoleOwnerLastDevice(me *penapi.MeView) bool {
	if me == nil || me.IsOwner == nil || !*me.IsOwner || me.Owners == nil || *me.Owners > 1 {
		return false
	}
	livePersonal := 0
	for _, d := range me.Devices {
		if d.Kind == "personal" && d.RemovedAt == nil {
			livePersonal++
		}
	}
	return livePersonal <= 1
}

func resolveMobileHostname(deviceName string) (string, error) {
	if strings.TrimSpace(deviceName) != "" {
		h, err := link.SanitizeHostname(deviceName)
		if err != nil {
			return "", err
		}
		if h != "" {
			return h, nil
		}
	}
	if runtime.GOOS == "ios" {
		return "iphone", nil
	}
	if runtime.GOOS == "android" {
		return "android", nil
	}
	return link.DefaultHostname()
}

func controlHTTPClient(caPEM string) (*http.Client, error) {
	if caPEM == "" {
		return penapi.ControlClient("")
	}
	if !allowCustomControlCA {
		return nil, errors.New("custom control CA is disabled in release builds")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("control_ca_pem contains no valid PEM certificate")
	}
	base, err := penapi.ControlClient("")
	if err != nil {
		return nil, err
	}
	tr := base.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	base.Transport = tr
	return base, nil
}
