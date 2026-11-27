package registrar

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"tailscale.com/types/key"

	"hogman/registrar/internal/headscale"
	"hogman/registrar/internal/store"
)

// PeerIdentity is the cryptographic peer identity returned by the embedded
// tsnet server's local WhoIs(remoteAddr) lookup. Role, device kind, and member
// status are NEVER taken from WhoIs — they come strictly from SQLite.
type PeerIdentity struct {
	IP        string
	HSNodeID  string
	NodeKey   string
	KeyExpiry time.Time // zero means key does not expire (e.g. node.expiry: 0 or tagged servers)
	Expired   bool      // true when control/tsnet flagged the peer node as expired
}

const (
	// Headscale 0.28+ Tags-as-Identity pseudo-user assigned to tagged nodes.
	headscaleTaggedUserID   = "2147455555"
	headscaleTaggedUserName = "tagged-devices"
)

func isTaggedPseudoUser(u *headscale.User) bool {
	return u == nil || u.ID == "" || (u.ID == headscaleTaggedUserID && u.Name == headscaleTaggedUserName)
}

// nodeMatchesBinding verifies that a Headscale node's tag/user ownership still
// matches the device's enrolled role in SQLite. Server devices must carry
// tag:server (never tag:infra) with no real user; personal devices must carry
// no tags and belong to the member's Headscale user ID.
func nodeMatchesBinding(m *store.Member, d *store.Device, n *headscale.Node) bool {
	if m == nil || d == nil || n == nil {
		return false
	}
	if d.Kind == "server" {
		return n.HasTag("tag:server") && !n.HasTag("tag:infra") && isTaggedPseudoUser(n.User)
	}
	return len(n.Tags) == 0 && n.User != nil && n.User.ID != "" && n.User.ID == m.HSUserID
}

// canonicalNodeKey parses a WireGuard node public key via tailscale's typed
// key.NodePublic parser (accepting "nodekey:<64-hex>" in any case or bare
// 64-hex) and returns the canonical "nodekey:<lowercase-hex>" representation.
func canonicalNodeKey(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	lower := strings.ToLower(s)
	if !strings.Contains(lower, ":") && len(lower) == 64 {
		lower = "nodekey:" + lower
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(lower)); err != nil || k.IsZero() {
		return "", false
	}
	return k.String(), true
}

// canonicalMachineKey parses a Tailscale machine public key via tailscale's
// typed key.MachinePublic parser (accepting "mkey:<64-hex>" in any case or
// bare 64-hex) and returns the canonical "mkey:<lowercase-hex>" representation.
func canonicalMachineKey(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	lower := strings.ToLower(s)
	if !strings.Contains(lower, ":") && len(lower) == 64 {
		lower = "mkey:" + lower
	}
	var k key.MachinePublic
	if err := k.UnmarshalText([]byte(lower)); err != nil || k.IsZero() {
		return "", false
	}
	return k.String(), true
}

func nodeMatchesAddr(n *headscale.Node, addr netip.Addr) bool {
	if n == nil {
		return false
	}
	want := addr.Unmap()
	for _, raw := range n.IPAddresses {
		if parsed, err := netip.ParseAddr(raw); err == nil && parsed.Unmap() == want {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------- keyRotator --

type rotateCall struct {
	done    chan struct{}
	err     error
	waiters int
}

// keyRotator provides per-node single-flight coalescing, per-node cooldown,
// and bounded concurrency for Headscale single-node verification during
// WireGuard node key rotation.
type keyRotator struct {
	clock    func() time.Time
	cooldown time.Duration
	spawn    func(func()) bool
	logger   *slog.Logger

	mu          sync.Mutex
	lastAttempt map[string]time.Time
	flight      map[string]*rotateCall
	sem         chan struct{}
}

func newKeyRotator(clock func() time.Time, cooldown time.Duration, maxConc int, spawn func(func()) bool, logger *slog.Logger) *keyRotator {
	if clock == nil {
		clock = time.Now
	}
	if maxConc <= 0 {
		maxConc = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &keyRotator{
		clock:       clock,
		cooldown:    cooldown,
		spawn:       spawn,
		logger:      logger,
		lastAttempt: map[string]time.Time{},
		flight:      map[string]*rotateCall{},
		sem:         make(chan struct{}, maxConc),
	}
}

// Do runs fn once per key (coalescing overlapping callers) while enforcing
// per-key cooldown and global concurrency limits. If fn is rate-limited,
// concurrency-capped, or shutdown rejects spawning, Do returns ErrNotFound.
func (r *keyRotator) Do(ctx context.Context, keyID string, fn func() error) error {
	nowT := r.clock()
	r.mu.Lock()
	call := r.flight[keyID]
	if call == nil {
		if prev, ok := r.lastAttempt[keyID]; ok && nowT.Sub(prev) < r.cooldown {
			r.mu.Unlock()
			r.logger.Warn("auth: WhoIs node key mismatch (rate-limited)", "hs_node_id", keyID)
			return ErrNotFound
		}
		select {
		case r.sem <- struct{}{}:
		default:
			r.mu.Unlock()
			r.logger.Warn("auth: WhoIs node key mismatch (concurrency cap reached)", "hs_node_id", keyID)
			return ErrNotFound
		}
		if len(r.lastAttempt) >= 256 {
			for k, ts := range r.lastAttempt {
				if nowT.Sub(ts) >= r.cooldown {
					delete(r.lastAttempt, k)
				}
			}
		}
		r.lastAttempt[keyID] = nowT
		call = &rotateCall{done: make(chan struct{})}
		r.flight[keyID] = call
		started := r.spawn(func() {
			defer func() { <-r.sem }()
			rerr := fn()
			r.mu.Lock()
			call.err = rerr
			close(call.done)
			delete(r.flight, keyID)
			r.mu.Unlock()
		})
		if !started {
			<-r.sem
			delete(r.flight, keyID)
			r.mu.Unlock()
			return ErrNotFound
		}
	} else {
		call.waiters++
	}
	r.mu.Unlock()

	select {
	case <-call.done:
		return call.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ---------------------------------------------------------- presenceCache --

type presenceCall struct {
	done    chan struct{}
	nodes   map[string]headscale.Node
	waiters int
}

// presenceCache maintains a display-only TTL cache of Headscale nodes with
// single-flight refresh and error backoff. No authorization, identity, or ACL
// policy decision may ever read this cache.
type presenceCache struct {
	clock   func() time.Time
	ttl     time.Duration
	timeout time.Duration
	baseCtx func() context.Context
	spawn   func(func()) bool
	fetch   func(context.Context) ([]headscale.Node, error)

	mu        sync.RWMutex
	byID      map[string]headscale.Node
	at        time.Time
	attemptAt time.Time
	flight    *presenceCall
}

func newPresenceCache(
	clock func() time.Time,
	ttl, timeout time.Duration,
	baseCtx func() context.Context,
	spawn func(func()) bool,
	fetch func(context.Context) ([]headscale.Node, error),
) *presenceCache {
	if clock == nil {
		clock = time.Now
	}
	if baseCtx == nil {
		baseCtx = context.Background
	}
	return &presenceCache{
		clock:   clock,
		ttl:     ttl,
		timeout: timeout,
		baseCtx: baseCtx,
		spawn:   spawn,
		fetch:   fetch,
	}
}

func (c *presenceCache) Set(nodes []headscale.Node) {
	snap := indexNodesByID(nodes)
	ts := c.clock()
	c.mu.Lock()
	c.byID = snap
	c.at = ts
	c.attemptAt = ts
	c.mu.Unlock()
}

func (c *presenceCache) SetTTL(d time.Duration) {
	c.mu.Lock()
	c.ttl = d
	c.mu.Unlock()
}

func (c *presenceCache) Clear() {
	c.mu.Lock()
	c.byID = map[string]headscale.Node{}
	c.mu.Unlock()
}

func indexNodesByID(nodes []headscale.Node) map[string]headscale.Node {
	byID := make(map[string]headscale.Node, len(nodes))
	for _, n := range nodes {
		if n.ID != "" {
			byID[n.ID] = n
		}
	}
	return byID
}

func (c *presenceCache) Snapshot(ctx context.Context) map[string]headscale.Node {
	nowT := c.clock()
	c.mu.RLock()
	if c.byID != nil && !c.at.IsZero() && nowT.Sub(c.at) < c.ttl {
		snap := c.byID
		c.mu.RUnlock()
		return snap
	}
	if !c.attemptAt.IsZero() && nowT.Sub(c.attemptAt) < c.ttl {
		stale := c.byID
		c.mu.RUnlock()
		return stale
	}
	stale := c.byID
	c.mu.RUnlock()

	c.mu.Lock()
	nowT = c.clock()
	if c.byID != nil && !c.at.IsZero() && nowT.Sub(c.at) < c.ttl {
		snap := c.byID
		c.mu.Unlock()
		return snap
	}
	if !c.attemptAt.IsZero() && nowT.Sub(c.attemptAt) < c.ttl {
		stale = c.byID
		c.mu.Unlock()
		return stale
	}
	call := c.flight
	if call == nil {
		call = &presenceCall{done: make(chan struct{})}
		c.flight = call
		started := c.spawn(func() {
			workCtx, cancel := context.WithTimeout(c.baseCtx(), c.timeout)
			defer cancel()
			nodes, err := c.fetch(workCtx)
			var snap map[string]headscale.Node
			if err == nil {
				snap = indexNodesByID(nodes)
			}
			ts := c.clock()
			c.mu.Lock()
			c.attemptAt = ts
			if err == nil {
				c.byID = snap
				c.at = ts
				call.nodes = snap
			} else {
				call.nodes = c.byID
			}
			close(call.done)
			c.flight = nil
			c.mu.Unlock()
		})
		if !started {
			c.flight = nil
			c.mu.Unlock()
			return stale
		}
	} else {
		call.waiters++
	}
	c.mu.Unlock()

	select {
	case <-call.done:
		if call.nodes != nil {
			return call.nodes
		}
		return stale
	case <-ctx.Done():
		return stale
	}
}

// ------------------------------------------------------ peer verification --

// VerifyDirectPeer authenticates a caller over the embedded tsnet listener
// using the WireGuard peer's Headscale node ID and node public key from
// local WhoIs, matched against SQLite with zero Headscale REST calls in
// steady state.
//
// Revocations performed through the registrar (kick, suspend, device remove)
// update SQLite immediately so the next request is refused regardless of
// Headscale netmap lag. Deleting a node out-of-band with the headscale CLI
// leaves a brief window until Headscale drops the peer from core's netmap;
// operators should always delete devices through the registrar.
func (s *Service) VerifyDirectPeer(ctx context.Context, peer *PeerIdentity) (*store.Member, *store.Device, error) {
	if peer == nil || peer.Expired || peer.HSNodeID == "" || peer.NodeKey == "" || peer.IP == "" {
		return nil, nil, ErrNotFound
	}
	peerNodeKey, ok := canonicalNodeKey(peer.NodeKey)
	if !ok {
		return nil, nil, ErrNotFound
	}
	// KeyExpiry.IsZero() means the node key does not expire (e.g. node.expiry: 0
	// or tagged servers). Only reject non-zero timestamps that have passed.
	if !peer.KeyExpiry.IsZero() && !peer.KeyExpiry.After(s.clock()) {
		return nil, nil, ErrNotFound
	}
	addr, err := netip.ParseAddr(peer.IP)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return nil, nil, ErrNotFound
	}
	canon := addr.String()

	logger := s.loggerOrDefault()
	d, err := s.st.DeviceByHSNodeID(peer.HSNodeID)
	if errors.Is(err, ErrNotFound) {
		// Only trigger a cooldown-gated, single-flight Sync when an open device
		// key could explain a newly enrolled device racing ahead of the poll.
		if open, kerr := s.st.HasOpenDeviceKeys(); kerr == nil && open && s.canTriggerInlineSync() {
			if serr := s.Sync(ctx); serr != nil {
				logger.Warn("auth: inline sync failed for unknown node", "hs_node_id", peer.HSNodeID, "err", serr)
				return nil, nil, ErrNotFound
			}
			d, err = s.st.DeviceByHSNodeID(peer.HSNodeID)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if d.RemovedAt != nil {
		return nil, nil, ErrNotFound
	}
	m, err := s.st.MemberByID(d.MemberID)
	if err != nil {
		return nil, nil, err
	}
	if m.Status != "active" {
		return nil, nil, forbidden("membership %s", m.Status)
	}
	// Keep key rotation narrow (node key only): if the mesh IP does not match
	// what SQLite holds, refuse immediately and leave IP shifts to syncOnce().
	if d.IPv4 != canon {
		return nil, nil, ErrNotFound
	}
	storedNodeKey, okNK := canonicalNodeKey(d.NodeKey)
	_, okMK := canonicalMachineKey(d.MachineKey)
	if !okNK || !okMK {
		logger.Warn("auth: node missing or invalid pinned node_key/machine_key; refusing", "hs_node_id", d.HSNodeID, "name", d.Name)
		return nil, nil, ErrNotFound
	}
	if storedNodeKey != peerNodeKey {
		return s.verifyAndRotateNodeKey(ctx, d.HSNodeID, peerNodeKey, addr, canon)
	}
	return m, d, nil
}

// verifyAndRotateNodeKey handles legitimate WireGuard node key rotation (e.g.
// `tailscale up --force-reauth`) by verifying a single node in Headscale under
// per-device single-flight, per-device cooldown, and bounded concurrency. It
// commits under s.mu (preventing stale syncOnce snapshots from reverting a fresh
// rotation), requires pinned machine_key + owner/tag binding + IP match + active
// member, and returns freshly reloaded Member/Device rows so concurrent
// suspensions or role demotions cannot be bypassed.
func (s *Service) verifyAndRotateNodeKey(ctx context.Context, hsNodeID, peerNodeKey string, addr netip.Addr, canon string) (*store.Member, *store.Device, error) {
	logger := s.loggerOrDefault()
	err := s.rotator.Do(ctx, hsNodeID, func() error {
		workCtx, cancel := context.WithTimeout(s.baseContext(), 15*time.Second)
		n, hsErr := s.hs.Node(workCtx, hsNodeID)
		cancel()
		if hsErr != nil {
			logger.Warn("auth: key-rotation verify failed", "hs_node_id", hsNodeID, "err", hsErr)
			return ErrNotFound
		}
		return s.commitNodeKeyRotation(hsNodeID, n, addr, canon)
	})
	if err != nil {
		return nil, nil, err
	}

	// Reload fresh device and member state after rotation completes so every
	// coalesced caller verifies its own presented NodeKey against the committed
	// row and receives up-to-date status/role.
	d, err := s.st.DeviceByHSNodeID(hsNodeID)
	if err != nil || d.RemovedAt != nil {
		return nil, nil, ErrNotFound
	}
	m, err := s.st.MemberByID(d.MemberID)
	if err != nil {
		return nil, nil, err
	}
	if m.Status != "active" {
		return nil, nil, forbidden("membership %s", m.Status)
	}
	if d.IPv4 != canon {
		return nil, nil, ErrNotFound
	}
	curNodeKey, okNK := canonicalNodeKey(d.NodeKey)
	_, okMK := canonicalMachineKey(d.MachineKey)
	if !okNK || !okMK || curNodeKey != peerNodeKey {
		return nil, nil, ErrNotFound
	}
	return m, d, nil
}

func (s *Service) commitNodeKeyRotation(hsNodeID string, n *headscale.Node, addr netip.Addr, canon string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	logger := s.loggerOrDefault()
	d, err := s.st.DeviceByHSNodeID(hsNodeID)
	if err != nil || d.RemovedAt != nil {
		return ErrNotFound
	}
	m, err := s.st.MemberByID(d.MemberID)
	if err != nil {
		return err
	}
	if m.Status != "active" {
		return forbidden("membership %s", m.Status)
	}
	if d.IPv4 != canon {
		return ErrNotFound
	}
	storedNodeKey, okNK := canonicalNodeKey(d.NodeKey)
	storedMachKey, okMK := canonicalMachineKey(d.MachineKey)
	if !okNK || !okMK {
		return ErrNotFound
	}
	if n == nil {
		return ErrNotFound
	}
	hsMachKey, okHSMK := canonicalMachineKey(n.MachineKey)
	if !okHSMK || hsMachKey != storedMachKey {
		logger.Warn("auth: ALERT machine_key mismatch on key rotation",
			"hs_node_id", d.HSNodeID, "name", d.Name, "stored", storedMachKey, "headscale", n.MachineKey)
		return ErrNotFound
	}
	if !nodeMatchesBinding(m, d, n) {
		logger.Warn("auth: ALERT owner/tag binding mismatch on key rotation", "hs_node_id", d.HSNodeID, "name", d.Name)
		return ErrNotFound
	}
	hsNodeKey, okHSNK := canonicalNodeKey(n.NodeKey)
	if !nodeMatchesAddr(n, addr) || !okHSNK {
		logger.Warn("auth: WhoIs node key/IP mismatch against Headscale", "hs_node_id", d.HSNodeID, "name", d.Name)
		return ErrNotFound
	}
	if storedNodeKey == hsNodeKey {
		// Already rotated (e.g. by a concurrent syncOnce) or Headscale still holds
		// the old key; caller verifies canonicalNodeKey(d.NodeKey) == peerNodeKey after waking.
		return nil
	}
	rotated, err := s.st.RotateDeviceNodeKeyAudited(d.ID, d.NodeKey, d.MachineKey, hsNodeKey, &store.AuditRecord{
		Actor:  "registrar",
		Action: "device.key_rotate",
		Target: fmt.Sprintf("%s/%s#%d", m.Handle, d.Name, d.ID),
	})
	if err != nil {
		return err
	}
	if !rotated {
		logger.Warn("auth: conditional key rotation lost race (device removed, member inactive, or changed)",
			"hs_node_id", d.HSNodeID, "name", d.Name)
		return ErrNotFound
	}
	return nil
}

// PresenceSnapshot returns a display-only map of Headscale nodes indexed by
// node ID for UI online/last-seen badges (GET /api/directory and
// GET /api/admin/devices). No authorization, identity, or ACL policy decision
// may ever read this snapshot.
func (s *Service) PresenceSnapshot(ctx context.Context) map[string]headscale.Node {
	return s.presence.Snapshot(ctx)
}

func (s *Service) setPresence(nodes []headscale.Node) {
	s.presence.Set(nodes)
}
