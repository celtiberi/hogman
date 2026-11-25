package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestVerifyDirectPeerSteadyStateExpiryAndActiveMember(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	nowT := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	e.svc.nowFn = func() time.Time { return nowT }

	if _, err := e.svc.AddMember(ctx, cli, "owner1", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "alice", "member"); err != nil {
		t.Fatal(err)
	}
	_, aliceLaptop := e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")

	e.hs.mu.Lock()
	e.hs.listNodesCalls = 0
	e.hs.getNodeCalls = 0
	e.hs.mu.Unlock()

	// 1. Steady-state auth with zero KeyExpiry (tagged server or node.expiry: 0) makes 0 Headscale calls.
	m, d, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP:        "::ffff:100.64.0.10", // IPv4-mapped IPv6 normalizes cleanly
		HSNodeID:  aliceLaptop.HSNodeID,
		NodeKey:   aliceLaptop.NodeKey,
		KeyExpiry: time.Time{},
	})
	if err != nil || m.Handle != "alice" || d.ID != aliceLaptop.ID {
		t.Fatalf("VerifyDirectPeer zero expiry: m=%+v d=%+v err=%v", m, d, err)
	}
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP:        "100.64.0.11",
		HSNodeID:  aliceSrv.HSNodeID,
		NodeKey:   aliceSrv.NodeKey,
		KeyExpiry: time.Time{},
	}); err != nil {
		t.Fatalf("VerifyDirectPeer server zero expiry: %v", err)
	}

	// 2. Future KeyExpiry accepted; equal/past KeyExpiry and Expired flag rejected with 0 Headscale calls.
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP:        "100.64.0.10",
		HSNodeID:  aliceLaptop.HSNodeID,
		NodeKey:   aliceLaptop.NodeKey,
		KeyExpiry: nowT.Add(time.Minute),
	}); err != nil {
		t.Fatalf("VerifyDirectPeer future expiry: %v", err)
	}
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP:        "100.64.0.10",
		HSNodeID:  aliceLaptop.HSNodeID,
		NodeKey:   aliceLaptop.NodeKey,
		KeyExpiry: time.Time{},
		Expired:   true,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("VerifyDirectPeer Expired=true = %v, want ErrNotFound", err)
	}
	for _, exp := range []time.Time{nowT, nowT.Add(-time.Second)} {
		if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
			IP:        "100.64.0.10",
			HSNodeID:  aliceLaptop.HSNodeID,
			NodeKey:   aliceLaptop.NodeKey,
			KeyExpiry: exp,
		}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("VerifyDirectPeer expired (%v) = %v, want ErrNotFound", exp, err)
		}
	}

	// 3. IP mismatch is rejected immediately with 0 Headscale calls (even if node_key matches).
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP:       "100.64.0.99",
		HSNodeID: aliceLaptop.HSNodeID,
		NodeKey:  aliceLaptop.NodeKey,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("VerifyDirectPeer IP mismatch = %v, want ErrNotFound", err)
	}

	e.hs.mu.Lock()
	listCalls, getCalls := e.hs.listNodesCalls, e.hs.getNodeCalls
	e.hs.mu.Unlock()
	if listCalls != 0 || getCalls != 0 {
		t.Fatalf("steady-state/expiry/IP checks hit Headscale (list=%d get=%d), want 0", listCalls, getCalls)
	}

	// 4. Active member check enforced centrally inside VerifyDirectPeer AND on routes without
	// their own status check (GET /api/directory, GET /api/me).
	if err := e.svc.Suspend(ctx, cli, "alice", "pause"); err != nil {
		t.Fatal(err)
	}
	var prob *Problem
	_, _, err = e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP:       "100.64.0.10",
		HSNodeID: aliceLaptop.HSNodeID,
		NodeKey:  aliceLaptop.NodeKey,
	})
	if !errors.As(err, &prob) || prob.Status != http.StatusForbidden {
		t.Fatalf("suspended member VerifyDirectPeer = %v, want 403", err)
	}

	peerPresent := atomic.Bool{}
	peerPresent.Store(true)
	h := MeshHandlerDirect(e.svc, func(_ context.Context, _ string) (*PeerIdentity, error) {
		if !peerPresent.Load() {
			return nil, errors.New("whois: peer not found in netmap")
		}
		return &PeerIdentity{
			IP:       "100.64.0.10",
			HSNodeID: aliceLaptop.HSNodeID,
			NodeKey:  aliceLaptop.NodeKey,
		}, nil
	})
	for _, path := range []string{"/api/me", "/api/directory"} {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "100.64.0.10:12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("suspended GET %s = %d, want 403 (%s)", path, rec.Code, rec.Body.String())
		}
	}

	// Resume restores access immediately, then out-of-band netmap drop (headscale CLI delete)
	// immediately refuses without waiting for Sync().
	if err := e.svc.Resume(ctx, cli, "alice"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/me", nil)
	req.RemoteAddr = "100.64.0.10:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("resumed GET /api/me = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	peerPresent.Store(false)
	req = httptest.NewRequest("GET", "/api/me", nil)
	req.RemoteAddr = "100.64.0.10:12345"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("out-of-band netmap removal GET /api/me = %d, want 403", rec.Code)
	}

	// Missing pinned node_key/machine_key in SQLite fails closed.
	peerPresent.Store(true)
	if _, err := e.st.db.Exec(`UPDATE devices SET machine_key = '' WHERE id = ?`, aliceLaptop.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP:       "100.64.0.10",
		HSNodeID: aliceLaptop.HSNodeID,
		NodeKey:  aliceLaptop.NodeKey,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing machine_key VerifyDirectPeer = %v, want ErrNotFound", err)
	}
}

func TestVerifyDirectPeerKeyRotationOptionAPrime(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	var mu sync.Mutex
	nowT := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	e.svc.nowFn = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return nowT
	}
	advance := func(d time.Duration) {
		mu.Lock()
		nowT = nowT.Add(d)
		mu.Unlock()
	}

	if _, err := e.svc.AddMember(ctx, cli, "owner1", "owner"); err != nil {
		t.Fatal(err)
	}
	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := e.svc.AddMember(ctx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, aliceLaptop := e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")
	_, bobLaptop := e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.12", "")

	updateHSNode := func(id string, fn func(*HSNode)) {
		e.hs.mu.Lock()
		defer e.hs.mu.Unlock()
		for i := range e.hs.nodes {
			if e.hs.nodes[i].ID == id {
				fn(&e.hs.nodes[i])
				return
			}
		}
		t.Fatalf("node %s not found in fakeHeadscale", id)
	}

	// 1. Legitimate personal node-key rotation (same machine_key, same user, same IP).
	newPersonalKey := testNodeKey("alice-rotated-1")
	updateHSNode(aliceLaptop.HSNodeID, func(n *HSNode) { n.NodeKey = newPersonalKey })
	e.hs.mu.Lock()
	e.hs.listNodesCalls, e.hs.getNodeCalls = 0, 0
	e.hs.mu.Unlock()

	if m, d, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: aliceLaptop.HSNodeID, NodeKey: newPersonalKey,
	}); err != nil || m.Handle != "alice" || d.NodeKey != newPersonalKey {
		t.Fatalf("valid personal key rotation failed: m=%+v d=%+v err=%v", m, d, err)
	}
	e.hs.mu.Lock()
	if e.hs.listNodesCalls != 0 || e.hs.getNodeCalls != 1 {
		t.Fatalf("personal rotation Headscale calls: list=%d get=%d, want 0/1", e.hs.listNodesCalls, e.hs.getNodeCalls)
	}
	e.hs.mu.Unlock()
	// Subsequent request with the rotated key makes 0 Headscale calls.
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: aliceLaptop.HSNodeID, NodeKey: newPersonalKey,
	}); err != nil {
		t.Fatalf("post-rotation steady-state call failed: %v", err)
	}
	e.hs.mu.Lock()
	if e.hs.getNodeCalls != 1 {
		t.Fatalf("post-rotation call hit Headscale again (get=%d)", e.hs.getNodeCalls)
	}
	e.hs.mu.Unlock()

	// Verify device.key_rotate audit log entry was recorded.
	logs, err := e.st.AuditLog(10)
	if err != nil {
		t.Fatal(err)
	}
	foundAudit := false
	for _, entry := range logs {
		if entry.Action == "device.key_rotate" && strings.Contains(entry.Target, "alice/alice-laptop") {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Fatalf("missing device.key_rotate audit entry: %+v", logs)
	}

	// 2. Legitimate server node-key rotation: works with both nil user AND Headscale 0.29.7
	// tagged-devices pseudo-user (id=2147455555, name="tagged-devices").
	newSrvKey := testNodeKey("srv-rotated-1")
	updateHSNode(aliceSrv.HSNodeID, func(n *HSNode) {
		n.NodeKey = newSrvKey
		n.User = &HSUser{ID: headscaleTaggedUserID, Name: headscaleTaggedUserName}
	})
	if _, d, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.11", HSNodeID: aliceSrv.HSNodeID, NodeKey: newSrvKey,
	}); err != nil || d.NodeKey != newSrvKey {
		t.Fatalf("valid server key rotation (tagged-devices pseudo-user) failed: d=%+v err=%v", d, err)
	}

	// 2b. Server carrying tag:infra in addition to tag:server is refused.
	advance(keyRotateCooldown + time.Second)
	updateHSNode(aliceSrv.HSNodeID, func(n *HSNode) {
		n.Tags = []string{"tag:server", "tag:infra"}
		n.NodeKey = testNodeKey("srv-infra-escalate")
	})
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.11", HSNodeID: aliceSrv.HSNodeID, NodeKey: testNodeKey("srv-infra-escalate"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("server with tag:infra rotation = %v, want ErrNotFound", err)
	}
	updateHSNode(aliceSrv.HSNodeID, func(n *HSNode) {
		n.Tags = []string{"tag:server"}
		n.User = nil
	})

	// 3. Server spoof with different machine_key is refused and leaves stored node_key untouched.
	advance(keyRotateCooldown + time.Second)
	updateHSNode(aliceSrv.HSNodeID, func(n *HSNode) {
		n.MachineKey = testMachineKey("attacker-other-machine")
		n.NodeKey = testNodeKey("attacker-srv-key")
	})
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.11", HSNodeID: aliceSrv.HSNodeID, NodeKey: testNodeKey("attacker-srv-key"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("server machine_key spoof = %v, want ErrNotFound", err)
	}
	gotSrv, _ := e.st.DeviceByID(aliceSrv.ID)
	if gotSrv.NodeKey != newSrvKey {
		t.Fatalf("server node_key mutated on spoof: got %q want %q", gotSrv.NodeKey, newSrvKey)
	}

	// 4. Server spoof where Headscale node lacks tag:server OR has a user is refused.
	advance(keyRotateCooldown + time.Second)
	updateHSNode(aliceSrv.HSNodeID, func(n *HSNode) {
		n.MachineKey = aliceSrv.MachineKey
		n.Tags = nil
		n.NodeKey = testNodeKey("untagged-srv")
	})
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.11", HSNodeID: aliceSrv.HSNodeID, NodeKey: testNodeKey("untagged-srv"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("untagged server rotation = %v, want ErrNotFound", err)
	}
	advance(keyRotateCooldown + time.Second)
	updateHSNode(aliceSrv.HSNodeID, func(n *HSNode) {
		n.Tags = []string{"tag:server"}
		n.User = &HSUser{ID: alice.HSUserID, Name: alice.Handle}
		n.NodeKey = testNodeKey("user-owned-srv")
	})
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.11", HSNodeID: aliceSrv.HSNodeID, NodeKey: testNodeKey("user-owned-srv"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("server with non-empty user rotation = %v, want ErrNotFound", err)
	}

	// 5. Personal spoof with different machine_key OR different user.id is refused.
	advance(keyRotateCooldown + time.Second)
	updateHSNode(aliceLaptop.HSNodeID, func(n *HSNode) {
		n.MachineKey = testMachineKey("stolen-id")
		n.NodeKey = testNodeKey("stolen-key")
	})
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: aliceLaptop.HSNodeID, NodeKey: testNodeKey("stolen-key"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("personal machine_key spoof = %v, want ErrNotFound", err)
	}
	advance(keyRotateCooldown + time.Second)
	updateHSNode(aliceLaptop.HSNodeID, func(n *HSNode) {
		n.MachineKey = aliceLaptop.MachineKey
		n.User = &HSUser{ID: bob.HSUserID, Name: bob.Handle}
		n.NodeKey = testNodeKey("wrong-user-key")
	})
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: aliceLaptop.HSNodeID, NodeKey: testNodeKey("wrong-user-key"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("personal wrong user.id rotation = %v, want ErrNotFound", err)
	}
	// Personal node carrying a tag is also refused even with matching user.id.
	advance(keyRotateCooldown + time.Second)
	updateHSNode(aliceLaptop.HSNodeID, func(n *HSNode) {
		n.User = &HSUser{ID: alice.HSUserID, Name: alice.Handle}
		n.Tags = []string{"tag:server"}
		n.NodeKey = testNodeKey("tagged-personal-key")
	})
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: aliceLaptop.HSNodeID, NodeKey: testNodeKey("tagged-personal-key"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("personal node with tag rotation = %v, want ErrNotFound", err)
	}
	updateHSNode(aliceLaptop.HSNodeID, func(n *HSNode) { n.Tags = nil })

	// 6. Narrow rotation: if IP also changed, refuse immediately with 0 Headscale calls.
	advance(keyRotateCooldown + time.Second)
	updateHSNode(aliceLaptop.HSNodeID, func(n *HSNode) {
		n.User = &HSUser{ID: alice.HSUserID, Name: alice.Handle}
		n.IPAddresses = []string{"100.64.0.250"}
		n.NodeKey = testNodeKey("ip-shifted")
	})
	e.hs.mu.Lock()
	beforeGet := e.hs.getNodeCalls
	e.hs.mu.Unlock()
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.250", HSNodeID: aliceLaptop.HSNodeID, NodeKey: testNodeKey("ip-shifted"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("IP+key rotation = %v, want ErrNotFound", err)
	}
	e.hs.mu.Lock()
	if e.hs.getNodeCalls != beforeGet {
		t.Fatalf("IP+key rotation called Headscale (before=%d after=%d), want 0 calls", beforeGet, e.hs.getNodeCalls)
	}
	e.hs.mu.Unlock()

	// 7. Per-device cooldown: spamming bad keys on aliceLaptop rate-limits aliceLaptop
	// WITHOUT blocking bobLaptop's legitimate rotation!
	advance(keyRotateCooldown + time.Second)
	updateHSNode(aliceLaptop.HSNodeID, func(n *HSNode) {
		n.IPAddresses = []string{"100.64.0.10"}
		n.NodeKey = newPersonalKey
	})
	e.hs.mu.Lock()
	beforeSpam := e.hs.getNodeCalls
	e.hs.mu.Unlock()
	for i := 0; i < 5; i++ {
		_, _, _ = e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
			IP: "100.64.0.10", HSNodeID: aliceLaptop.HSNodeID, NodeKey: testNodeKey("bogus-spam"),
		})
	}
	e.hs.mu.Lock()
	afterSpam := e.hs.getNodeCalls
	e.hs.mu.Unlock()
	if afterSpam-beforeSpam != 1 {
		t.Fatalf("5 rapid bad keys made %d Headscale calls, want 1 (rate-limited)", afterSpam-beforeSpam)
	}
	// Bob's legitimate rotation immediately succeeds despite Alice being in cooldown.
	updateHSNode(bobLaptop.HSNodeID, func(n *HSNode) { n.NodeKey = testNodeKey("bob-rotated-1") })
	if _, d, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.12", HSNodeID: bobLaptop.HSNodeID, NodeKey: testNodeKey("bob-rotated-1"),
	}); err != nil || d.NodeKey != testNodeKey("bob-rotated-1") {
		t.Fatalf("bob rotation blocked by alice cooldown: d=%+v err=%v", d, err)
	}

	// 8. Conditional SQLite rotation race: device marked removed while Headscale GET is in flight.
	advance(keyRotateCooldown + time.Second)
	updateHSNode(bobLaptop.HSNodeID, func(n *HSNode) { n.NodeKey = testNodeKey("bob-race-removed") })
	e.hs.mu.Lock()
	e.hs.onGetNode = func(_ context.Context, id string) {
		if id == bobLaptop.HSNodeID {
			_ = e.st.MarkDeviceRemoved(bobLaptop.ID)
		}
	}
	e.hs.mu.Unlock()
	_, _, err = e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.12", HSNodeID: bobLaptop.HSNodeID, NodeKey: testNodeKey("bob-race-removed"),
	})
	e.hs.mu.Lock()
	e.hs.onGetNode = nil
	e.hs.mu.Unlock()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotation racing with device removal = %v, want ErrNotFound", err)
	}
	gotBob, _ := e.st.DeviceByID(bobLaptop.ID)
	if gotBob.RemovedAt == nil || gotBob.NodeKey != testNodeKey("bob-rotated-1") {
		t.Fatalf("removed device altered by racing rotation: %+v", gotBob)
	}

	// 9. Bounded concurrency semaphore (keyRotateMaxConc = 4): 5th concurrent rotation fails fast.
	advance(keyRotateCooldown + time.Second)
	var devs []*Device
	for i := 0; i < keyRotateMaxConc+1; i++ {
		_, d := e.addDevice(t, "alice", "personal", "dev-sem-"+string(rune('a'+i)), "100.64.9."+string(rune('1'+i)), "")
		updateHSNode(d.HSNodeID, func(n *HSNode) { n.NodeKey = testNodeKey("sem-rot-" + d.Name) })
		devs = append(devs, d)
	}
	entered := make(chan struct{}, keyRotateMaxConc)
	release := make(chan struct{})
	e.hs.mu.Lock()
	e.hs.onGetNode = func(_ context.Context, _ string) {
		entered <- struct{}{}
		<-release
	}
	e.hs.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < keyRotateMaxConc; i++ {
		wg.Add(1)
		go func(d *Device) {
			defer wg.Done()
			_, _, _ = e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
				IP: d.IPv4, HSNodeID: d.HSNodeID, NodeKey: testNodeKey("sem-rot-" + d.Name),
			})
		}(devs[i])
	}
	for i := 0; i < keyRotateMaxConc; i++ {
		<-entered
	}
	// All 4 slots are occupied; the 5th must fail closed immediately without hitting Headscale.
	fifth := devs[keyRotateMaxConc]
	e.hs.mu.Lock()
	getBeforeFifth := e.hs.getNodeCalls
	e.hs.mu.Unlock()
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: fifth.IPv4, HSNodeID: fifth.HSNodeID, NodeKey: testNodeKey("sem-rot-" + fifth.Name),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("5th concurrent rotation = %v, want ErrNotFound", err)
	}
	e.hs.mu.Lock()
	if e.hs.getNodeCalls != getBeforeFifth {
		t.Fatalf("5th concurrent rotation bypassed concurrency cap")
	}
	e.hs.onGetNode = nil
	e.hs.mu.Unlock()
	close(release)
	wg.Wait()

	// CRITICAL (HIGH-3): the 5th device rejected by rotateSem must NOT have
	// burned its 10s cooldown — immediate retry succeeds without advancing clock!
	if _, d, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: fifth.IPv4, HSNodeID: fifth.HSNodeID, NodeKey: testNodeKey("sem-rot-" + fifth.Name),
	}); err != nil || d.NodeKey != testNodeKey("sem-rot-"+fifth.Name) {
		t.Fatalf("5th device retry after semaphore freed failed (cooldown burned?): d=%+v err=%v", d, err)
	}
}

func TestKeyRotationConcurrencyTOCTOUAndSyncInvariants(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	var clockMu sync.Mutex
	nowT := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	e.svc.nowFn = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return nowT
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		nowT = nowT.Add(d)
		clockMu.Unlock()
	}

	if _, err := e.svc.AddMember(ctx, cli, "owner1", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	_, aliceLap := e.addDevice(t, "alice", "personal", "alice-lap", "100.64.0.10", "")
	_, bobLap := e.addDevice(t, "bob", "personal", "bob-lap", "100.64.0.11", "")

	setNodeKey := func(hsID, nk string) {
		e.hs.mu.Lock()
		defer e.hs.mu.Unlock()
		for i := range e.hs.nodes {
			if e.hs.nodes[i].ID == hsID {
				e.hs.nodes[i].NodeKey = nk
				return
			}
		}
	}

	// 1. Parallel browser requests (3 valid + 1 bogus key) on the same device coalesce
	// into ONE GET /api/v1/node/{id}: all 3 valid succeed, the 1 bogus fails closed.
	setNodeKey(bobLap.HSNodeID, testNodeKey("bob-parallel-1"))
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	e.hs.mu.Lock()
	e.hs.getNodeCalls = 0
	e.hs.onGetNode = func(_ context.Context, _ string) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
	}
	e.hs.mu.Unlock()

	type res struct {
		m   *Member
		d   *Device
		err error
	}
	validCh := make(chan res, 3)
	bogusCh := make(chan res, 1)
	go func() {
		m, d, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
			IP: "100.64.0.11", HSNodeID: bobLap.HSNodeID, NodeKey: testNodeKey("bob-parallel-1"),
		})
		validCh <- res{m, d, err}
	}()
	<-started
	for i := 0; i < 2; i++ {
		go func() {
			m, d, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
				IP: "100.64.0.11", HSNodeID: bobLap.HSNodeID, NodeKey: testNodeKey("bob-parallel-1"),
			})
			validCh <- res{m, d, err}
		}()
	}
	go func() {
		m, d, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
			IP: "100.64.0.11", HSNodeID: bobLap.HSNodeID, NodeKey: testNodeKey("attacker-bogus"),
		})
		bogusCh <- res{m, d, err}
	}()
	time.Sleep(15 * time.Millisecond)
	close(release)
	e.hs.mu.Lock()
	e.hs.onGetNode = nil
	calls := e.hs.getNodeCalls
	e.hs.mu.Unlock()
	for i := 0; i < 3; i++ {
		r := <-validCh
		if r.err != nil || r.d.NodeKey != testNodeKey("bob-parallel-1") {
			t.Fatalf("coalesced valid caller #%d failed: %+v", i, r)
		}
	}
	if r := <-bogusCh; !errors.Is(r.err, ErrNotFound) {
		t.Fatalf("coalesced bogus caller succeeded: %+v", r)
	}
	if calls != 1 {
		t.Fatalf("4 parallel requests made %d Headscale calls, want 1", calls)
	}

	// 2. TOCTOU (HIGH-2): Suspend while s.hs.Node is in flight refuses rotation AND
	// leaves SQLite node_key untouched.
	advance(keyRotateCooldown + time.Second)
	setNodeKey(bobLap.HSNodeID, testNodeKey("bob-suspended-race"))
	e.hs.mu.Lock()
	e.hs.onGetNode = func(_ context.Context, _ string) {
		if err := e.svc.Suspend(ctx, cli, "bob", "race-suspend"); err != nil {
			t.Errorf("Suspend in hook: %v", err)
		}
	}
	e.hs.mu.Unlock()
	_, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.11", HSNodeID: bobLap.HSNodeID, NodeKey: testNodeKey("bob-suspended-race"),
	})
	e.hs.mu.Lock()
	e.hs.onGetNode = nil
	e.hs.mu.Unlock()
	var prob *Problem
	if !errors.As(err, &prob) || prob.Status != http.StatusForbidden {
		t.Fatalf("rotation racing with Suspend = %v, want 403", err)
	}
	gotBob, _ := e.st.DeviceByID(bobLap.ID)
	if gotBob.NodeKey != testNodeKey("bob-parallel-1") {
		t.Fatalf("suspended member rotated node_key to %q", gotBob.NodeKey)
	}

	// 3. TOCTOU (HIGH-2): Role demotion while s.hs.Node is in flight returns FRESH
	// member role ("member"), never the stale pre-rotation "owner" snapshot.
	setNodeKey(aliceLap.HSNodeID, testNodeKey("alice-demoted-race"))
	e.hs.mu.Lock()
	e.hs.onGetNode = func(_ context.Context, _ string) {
		if err := e.svc.SetRole(ctx, cli, "alice", "member"); err != nil {
			t.Errorf("SetRole in hook: %v", err)
		}
	}
	e.hs.mu.Unlock()
	mFresh, dFresh, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: aliceLap.HSNodeID, NodeKey: testNodeKey("alice-demoted-race"),
	})
	e.hs.mu.Lock()
	e.hs.onGetNode = nil
	e.hs.mu.Unlock()
	if err != nil || mFresh.Role != "member" || dFresh.NodeKey != testNodeKey("alice-demoted-race") {
		t.Fatalf("demoted rotation returned m=%+v d=%+v err=%v, want fresh Role=member", mFresh, dFresh, err)
	}

	// 4. Racing syncOnce already commits new key while s.hs.Node is in flight -> no spurious 403!
	advance(keyRotateCooldown + time.Second)
	setNodeKey(aliceLap.HSNodeID, testNodeKey("alice-synced-first"))
	e.hs.mu.Lock()
	e.hs.onGetNode = func(_ context.Context, _ string) {
		if err := e.svc.Sync(ctx); err != nil {
			t.Errorf("Sync in hook: %v", err)
		}
	}
	e.hs.mu.Unlock()
	_, dSynced, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: aliceLap.HSNodeID, NodeKey: testNodeKey("alice-synced-first"),
	})
	e.hs.mu.Lock()
	e.hs.onGetNode = nil
	e.hs.mu.Unlock()
	if err != nil || dSynced.NodeKey != testNodeKey("alice-synced-first") {
		t.Fatalf("rotation racing with syncOnce returned spurious error: d=%+v err=%v", dSynced, err)
	}

	// 5. syncOnce enforces owner/tag binding and non-empty machine_key (HIGH-1) AND
	// retires devices that gain tag:infra (LOW-2).
	e.hs.mu.Lock()
	for i := range e.hs.nodes {
		if e.hs.nodes[i].ID == aliceLap.HSNodeID {
			// Missing machineKey on pinned device must NOT overwrite node_key!
			e.hs.nodes[i].MachineKey = ""
			e.hs.nodes[i].NodeKey = testNodeKey("unpinned-attempt")
		}
	}
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	gotAlice, _ := e.st.DeviceByID(aliceLap.ID)
	if gotAlice.NodeKey != testNodeKey("alice-synced-first") {
		t.Fatalf("syncOnce updated node_key despite missing machine_key: got %q", gotAlice.NodeKey)
	}

	// Owner/tag drift on syncOnce retires the device instead of patching node_key in place.
	e.hs.mu.Lock()
	for i := range e.hs.nodes {
		if e.hs.nodes[i].ID == aliceLap.HSNodeID {
			e.hs.nodes[i].MachineKey = aliceLap.MachineKey
			e.hs.nodes[i].Tags = []string{"tag:server"} // personal device suddenly tagged!
			e.hs.nodes[i].NodeKey = testNodeKey("tampered-drift")
		}
	}
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	gotAlice, _ = e.st.DeviceByID(aliceLap.ID)
	if gotAlice.RemovedAt == nil || gotAlice.NodeKey != testNodeKey("alice-synced-first") {
		t.Fatalf("syncOnce did not retire device on owner/tag drift: %+v", gotAlice)
	}

	// Device whose Headscale node gains tag:infra out-of-band is retired by !seen[d.HSNodeID].
	_, aliceLap2 := e.addDevice(t, "alice", "personal", "alice-lap2", "100.64.0.15", "")
	e.hs.mu.Lock()
	for i := range e.hs.nodes {
		if e.hs.nodes[i].ID == aliceLap2.HSNodeID {
			e.hs.nodes[i].Tags = []string{"tag:infra"}
		}
	}
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got2, _ := e.st.DeviceByID(aliceLap2.ID); got2.RemovedAt == nil {
		t.Fatalf("device turned into tag:infra should be retired: %+v", got2)
	}
}

func TestSyncOnceMachineKeyChangeRetiresOldDevice(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, srv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.20", "")
	if _, err := e.svc.Claim(Actor{Member: alice}, "alice", "photos", srv.ID, nil); err != nil {
		t.Fatal(err)
	}

	// Simulate Headscale returning a different machine_key on the same node ID without a valid pre-auth key.
	e.hs.mu.Lock()
	for i := range e.hs.nodes {
		if e.hs.nodes[i].ID == srv.HSNodeID {
			e.hs.nodes[i].MachineKey = testMachineKey("replaced-hardware")
			e.hs.nodes[i].NodeKey = testNodeKey("replaced-hardware")
		}
	}
	e.hs.mu.Unlock()

	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	got, err := e.st.DeviceByID(srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RemovedAt == nil {
		t.Fatalf("old device should be retired when machine_key changes, got %+v", got)
	}
	if got.MachineKey != srv.MachineKey {
		t.Fatalf("old device machine_key was overwritten in place: got %q want %q", got.MachineKey, srv.MachineKey)
	}
	// No replacement device should have been enrolled because there was no valid open device key.
	if live, err := e.st.LiveDevices(); err != nil || len(live) != 0 {
		t.Fatalf("expected 0 live devices after unauthorized machine_key swap, got %d (err=%v)", len(live), err)
	}
	// DNS stops resolving the retired server's name immediately.
	if _, err := e.st.ResolvableName("photos"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("photos still resolves after machine_key retirement: err=%v", err)
	}
}

func TestPolicyGenTriggersNeedsFastSyncAndSetRoleRenewOnly(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	genOf := func() int64 {
		t.Helper()
		pGen, _, err := e.st.PolicyGenerations()
		if err != nil {
			t.Fatal(err)
		}
		return pGen
	}
	assertBumped := func(label string, fn func()) {
		t.Helper()
		before := genOf()
		fn()
		after := genOf()
		if after <= before {
			t.Fatalf("%s did not bump policy_gen (before=%d after=%d)", label, before, after)
		}
	}

	// Verify EVERY mutator on members and devices bumps policy_gen via SQLite triggers.
	var owner1, owner2, bob *Member
	assertBumped("InsertMember(owner1)", func() {
		owner1 = &Member{Handle: "owner1", Role: "owner", Status: "active", HSUserID: "u1"}
		if err := e.st.InsertMember(owner1); err != nil {
			t.Fatal(err)
		}
	})
	assertBumped("InsertMember(owner2)", func() {
		owner2 = &Member{Handle: "owner2", Role: "owner", Status: "active", HSUserID: "u2"}
		if err := e.st.InsertMember(owner2); err != nil {
			t.Fatal(err)
		}
	})
	assertBumped("InsertMember(bob)", func() {
		bob = &Member{Handle: "bob", Role: "member", Status: "active", HSUserID: "u3"}
		if err := e.st.InsertMember(bob); err != nil {
			t.Fatal(err)
		}
	})
	assertBumped("SetMemberStatus", func() {
		if err := e.st.SetMemberStatus(bob.ID, "suspended"); err != nil {
			t.Fatal(err)
		}
	})
	assertBumped("SetMemberRole", func() {
		if err := e.st.SetMemberRole(bob.ID, "admin"); err != nil {
			t.Fatal(err)
		}
	})
	assertBumped("DemoteOwner", func() {
		ok, err := e.st.DemoteOwner(owner2.ID, "admin")
		if err != nil || !ok {
			t.Fatalf("DemoteOwner ok=%v err=%v", ok, err)
		}
	})
	assertBumped("DeleteMember", func() {
		tmp := &Member{Handle: "tmpdel", Role: "member", Status: "active", HSUserID: "u-tmp"}
		if err := e.st.InsertMember(tmp); err != nil {
			t.Fatal(err)
		}
		if err := e.st.DeleteMember(tmp.ID); err != nil {
			t.Fatal(err)
		}
	})
	var dev *Device
	assertBumped("InsertDevice", func() {
		dev = &Device{
			MemberID: owner1.ID, Kind: "personal", HSNodeID: "hs-1",
			NodeKey: testNodeKey("1"), MachineKey: testMachineKey("1"), Name: "lap", IPv4: "100.64.0.10",
		}
		if err := e.st.InsertDevice(dev); err != nil {
			t.Fatal(err)
		}
	})
	assertUnchanged := func(label string, fn func()) {
		t.Helper()
		before := genOf()
		fn()
		after := genOf()
		if after != before {
			t.Fatalf("%s unexpectedly bumped policy_gen (before=%d after=%d)", label, before, after)
		}
	}
	assertBumped("UpdateDevice(ip change)", func() {
		if err := e.st.UpdateDevice(dev.ID, "lap2", "100.64.0.99", "", testNodeKey("1"), testMachineKey("1")); err != nil {
			t.Fatal(err)
		}
	})
	assertUnchanged("UpdateDevice(name/key only)", func() {
		if err := e.st.UpdateDevice(dev.ID, "lap3", "100.64.0.99", "", testNodeKey("1"), testMachineKey("1")); err != nil {
			t.Fatal(err)
		}
	})
	assertUnchanged("RotateDeviceNodeKey", func() {
		ok, err := e.st.RotateDeviceNodeKey(dev.ID, testNodeKey("1"), testMachineKey("1"), testNodeKey("2"))
		if err != nil || !ok {
			t.Fatalf("RotateDeviceNodeKey ok=%v err=%v", ok, err)
		}
	})
	assertUnchanged("ClearMemberHSUserID", func() {
		if err := e.st.ClearMemberHSUserID(bob.ID); err != nil {
			t.Fatal(err)
		}
	})
	assertBumped("MarkDeviceRemoved", func() {
		if err := e.st.MarkDeviceRemoved(dev.ID); err != nil {
			t.Fatal(err)
		}
	})

	// Test NeedsFastSync stays true until Sync succeeds & applied_gen catches up.
	e2 := newTestEnv(t)
	if _, err := e2.svc.AddMember(ctx, cli, "owner1", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	e2.addDevice(t, "owner1", "personal", "owner-lap", "100.64.0.10", "")
	e2.addDevice(t, "bob", "personal", "bob-lap", "100.64.0.11", "")

	if !e2.svc.NeedsFastSync() {
		t.Fatal("NeedsFastSync should be true before initial Sync")
	}
	// If SetPolicy fails, Sync fails and NeedsFastSync remains true.
	e2.hs.mu.Lock()
	e2.hs.failSetPolicy = true
	e2.hs.mu.Unlock()
	if err := e2.svc.Sync(ctx); err == nil {
		t.Fatal("expected Sync to fail when SetPolicy fails")
	}
	if !e2.svc.NeedsFastSync() {
		t.Fatal("NeedsFastSync must stay true after failed SetPolicy")
	}
	e2.hs.mu.Lock()
	e2.hs.failSetPolicy = false
	e2.hs.mu.Unlock()
	if err := e2.svc.Sync(ctx); err != nil {
		t.Fatalf("Sync recovery: %v", err)
	}
	if e2.svc.NeedsFastSync() {
		t.Fatal("NeedsFastSync should be false once in sync with no open keys or pending cleanup")
	}

	// Simulate cross-process CLI mutation (Suspend succeeded, then Resume updated SQLite but failed SetPolicy):
	// in-memory e2.svc.lastPolicy still matches the post-Resume policy, yet policy_gen > applied_gen
	// MUST force NeedsFastSync=true and re-push SetPolicy!
	if err := e2.st.SetMemberStatus(2, "suspended"); err != nil {
		t.Fatal(err)
	}
	if err := e2.st.SetMemberStatus(2, "active"); err != nil {
		t.Fatal(err)
	}
	if !e2.svc.NeedsFastSync() {
		t.Fatal("NeedsFastSync must be true when out-of-process SQLite writes bumped policy_gen")
	}
	e2.hs.mu.Lock()
	beforePush := e2.hs.setPolicyCalls
	e2.hs.mu.Unlock()
	if err := e2.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	e2.hs.mu.Lock()
	afterPush := e2.hs.setPolicyCalls
	e2.hs.mu.Unlock()
	if afterPush != beforePush+1 {
		t.Fatalf("SetPolicy calls = %d, want %d when policy_gen > applied_gen even with identical lastPolicy", afterPush, beforePush+1)
	}
	if e2.svc.NeedsFastSync() {
		t.Fatal("NeedsFastSync should return to false after dirty policy_gen applied")
	}

	// SetRole during renew_only applies policy synchronously so promoted admin gains access immediately.
	billingPath := filepath.Join(t.TempDir(), "billing-status.json")
	if err := os.WriteFile(billingPath, []byte(`{"pen":"bobo","state":"renew_only","renew_url":"https://get.example.com"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	e2.svc.cfg.BillingStatusPath = billingPath
	if !e2.svc.NeedsFastSync() {
		t.Fatal("NeedsFastSync must flip true immediately on renew_only transition")
	}
	if err := e2.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(e2.hs.policy, "100.64.0.11") {
		t.Fatalf("bob (member) should be excluded in renew_only policy:\n%s", e2.hs.policy)
	}
	if err := e2.svc.SetRole(ctx, cli, "bob", "admin"); err != nil {
		t.Fatalf("SetRole bob->admin in renew_only: %v", err)
	}
	if !strings.Contains(e2.hs.policy, "100.64.0.11") {
		t.Fatalf("SetRole during renew_only did not synchronously push policy adding bob:\n%s", e2.hs.policy)
	}
}

func TestNeedsFastSyncPendingMemberCleanupTagServer(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "owner1", "owner"); err != nil {
		t.Fatal(err)
	}
	bob, err := e.svc.AddMember(ctx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, bobSrv := e.addDevice(t, "bob", "server", "bob-srv", "100.64.0.20", "")
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}

	// Simulate an interrupted Kick where bob's status is removed and hs_user_id is already cleared,
	// but his tag:server device row is still live in SQLite and Headscale.
	if err := e.st.SetMemberStatus(bob.ID, "removed"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.ClearMemberHSUserID(bob.ID); err != nil {
		t.Fatal(err)
	}
	// Mark policy applied so ONLY HasPendingMemberCleanup could keep fast sync active.
	if pGen, _, err := e.st.PolicyGenerations(); err == nil {
		_ = e.st.MarkPolicyApplied(pGen)
	}
	if pending, err := e.st.HasPendingMemberCleanup(); err != nil || !pending {
		t.Fatalf("HasPendingMemberCleanup = (%v, %v), want (true, nil) for live tag:server of removed member", pending, err)
	}
	if !e.svc.NeedsFastSync() {
		t.Fatal("NeedsFastSync must return true while removed member still has a live server device")
	}

	// Sync deletes the stray tag:server node and marks it removed; fast sync then backs off.
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("Sync cleanup: %v", err)
	}
	gotSrv, _ := e.st.DeviceByID(bobSrv.ID)
	if gotSrv.RemovedAt == nil {
		t.Fatalf("stray tag:server device was not marked removed by Sync")
	}
	if pending, err := e.st.HasPendingMemberCleanup(); err != nil || pending {
		t.Fatalf("HasPendingMemberCleanup after Sync = (%v, %v), want (false, nil)", pending, err)
	}
	if e.svc.NeedsFastSync() {
		t.Fatal("NeedsFastSync should return false after stray tag:server cleanup completes")
	}
}

func TestDetachedSingleFlightSyncAndPresence(t *testing.T) {
	e := newTestEnv(t)
	cli := Actor{CLI: true}
	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	e.svc.SetBaseContext(baseCtx)

	var clockMu sync.Mutex
	nowT := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	e.svc.nowFn = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return nowT
	}
	e.svc.cfg.PresenceTTL = 5 * time.Second

	if _, err := e.svc.AddMember(baseCtx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	_, aliceLaptop := e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	e.hs.mu.Lock()
	e.hs.nodes[0].Online = true
	e.hs.listNodesCalls = 0
	e.hs.mu.Unlock()

	// 1. Sync single-flight immune to caller 1 cancelling mid-flight.
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	e.hs.mu.Lock()
	e.hs.onListNodes = func(rctx context.Context) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-rctx.Done():
		}
	}
	e.hs.mu.Unlock()

	ctx1, cancel1 := context.WithCancel(context.Background())
	err1Ch := make(chan error, 1)
	err2Ch := make(chan error, 1)
	go func() { err1Ch <- e.svc.Sync(ctx1) }()
	<-started
	go func() { err2Ch <- e.svc.Sync(context.Background()) }()
	time.Sleep(15 * time.Millisecond)

	// Caller 1 cancels; shared worker MUST continue for caller 2.
	cancel1()
	if err := <-err1Ch; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller 1 err = %v, want context.Canceled", err)
	}
	close(release)
	if err := <-err2Ch; err != nil {
		t.Fatalf("caller 2 failed after caller 1 cancelled: %v", err)
	}
	e.hs.mu.Lock()
	if e.hs.listNodesCalls != 1 {
		t.Fatalf("overlapping Sync calls made %d ListNodes calls, want 1", e.hs.listNodesCalls)
	}
	e.hs.mu.Unlock()
	if e.svc.LastSyncAt().IsZero() {
		t.Fatal("LastSyncAt not updated after single-flight Sync")
	}

	// 2. PresenceSnapshot TTL caching + caller cancellation immunity + zero auth effect.
	// Note Sync() above already populated presenceByID at nowT, so immediate read makes 0 calls.
	snap := e.svc.PresenceSnapshot(context.Background())
	if !snap[aliceLaptop.HSNodeID].Online {
		t.Fatalf("cached presence missing online aliceLaptop: %+v", snap)
	}
	e.hs.mu.Lock()
	if e.hs.listNodesCalls != 1 {
		t.Fatalf("cached PresenceSnapshot hit Headscale (calls=%d want 1)", e.hs.listNodesCalls)
	}
	e.hs.mu.Unlock()

	// Advance clock past PresenceTTL; caller 1 cancels mid-flight while caller 2 receives fresh snapshot.
	clockMu.Lock()
	nowT = nowT.Add(6 * time.Second)
	clockMu.Unlock()
	started2 := make(chan struct{}, 1)
	release2 := make(chan struct{})
	e.hs.mu.Lock()
	e.hs.nodes[0].Online = false
	e.hs.onListNodes = func(rctx context.Context) {
		select {
		case started2 <- struct{}{}:
		default:
		}
		select {
		case <-release2:
		case <-rctx.Done():
		}
	}
	e.hs.mu.Unlock()

	pctx1, pcancel1 := context.WithCancel(context.Background())
	p1Ch := make(chan map[string]HSNode, 1)
	p2Ch := make(chan map[string]HSNode, 1)
	go func() { p1Ch <- e.svc.PresenceSnapshot(pctx1) }()
	<-started2
	go func() { p2Ch <- e.svc.PresenceSnapshot(context.Background()) }()
	time.Sleep(15 * time.Millisecond)
	pcancel1()
	<-p1Ch
	close(release2)
	snap2 := <-p2Ch
	if snap2[aliceLaptop.HSNodeID].Online {
		t.Fatalf("caller 2 did not get refreshed presence (Online=true, want false)")
	}
	e.hs.mu.Lock()
	if e.hs.listNodesCalls != 2 {
		t.Fatalf("PresenceSnapshot single-flight calls = %d, want 2", e.hs.listNodesCalls)
	}
	e.hs.mu.Unlock()

	// Clearing/poisoning presenceByID has ZERO effect on VerifyDirectPeer.
	e.svc.presenceMu.Lock()
	e.svc.presenceByID = map[string]HSNode{}
	e.svc.presenceMu.Unlock()
	if _, _, err := e.svc.VerifyDirectPeer(context.Background(), &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: aliceLaptop.HSNodeID, NodeKey: aliceLaptop.NodeKey,
	}); err != nil {
		t.Fatalf("VerifyDirectPeer affected by empty presence snapshot: %v", err)
	}

	// 3. Inline Sync cooldown bounds sequential unknown-peer sync amplification.
	if _, _, err := e.svc.IssueDeviceKey(baseCtx, cli, "alice", "server"); err != nil {
		t.Fatal(err)
	}
	e.hs.mu.Lock()
	e.hs.onListNodes = nil
	e.hs.listNodesCalls = 0
	e.hs.mu.Unlock()
	// Advance past inlineSyncCooldown once; 5 consecutive unknown peers trigger ONLY 1 Sync().
	clockMu.Lock()
	nowT = nowT.Add(inlineSyncCooldown + time.Second)
	clockMu.Unlock()
	for i := 0; i < 5; i++ {
		_, _, _ = e.svc.VerifyDirectPeer(context.Background(), &PeerIdentity{
			IP: "100.64.0.99", HSNodeID: "unknown-node", NodeKey: testNodeKey("unknown"),
		})
	}
	e.hs.mu.Lock()
	if e.hs.listNodesCalls != 1 {
		t.Fatalf("5 unknown peers with open key triggered %d inline Syncs, want 1", e.hs.listNodesCalls)
	}
	e.hs.mu.Unlock()

	// 4. Shutdown cancellation: cancelling service baseCtx cancels an in-flight Sync cleanly.
	started3 := make(chan struct{}, 1)
	canceledWorker := make(chan struct{}, 1)
	e.hs.mu.Lock()
	e.hs.onListNodes = func(rctx context.Context) {
		started3 <- struct{}{}
		<-rctx.Done()
		canceledWorker <- struct{}{}
	}
	e.hs.mu.Unlock()

	err3Ch := make(chan error, 1)
	go func() { err3Ch <- e.svc.Sync(context.Background()) }()
	<-started3
	cancelBase()
	select {
	case <-canceledWorker:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling baseCtx did not cancel in-flight Sync worker")
	}
	if err := <-err3Ch; err == nil {
		t.Fatal("expected Sync to return error when baseCtx cancelled")
	}
}

func TestLegacyDBMigrationBackfillsKeysOnInitialSync(t *testing.T) {
	legacyPath := filepath.Join(t.TempDir(), "legacy.db")
	rawDB, err := sql.Open("sqlite", "file:"+legacyPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	_, err = rawDB.Exec(`
		CREATE TABLE members (id INTEGER PRIMARY KEY, handle TEXT NOT NULL UNIQUE, role TEXT NOT NULL, status TEXT NOT NULL, invited_by INTEGER, hs_user_id TEXT NOT NULL, created_at INTEGER NOT NULL, removed_at INTEGER);
		CREATE TABLE devices (id INTEGER PRIMARY KEY, member_id INTEGER NOT NULL, kind TEXT NOT NULL, hs_node_id TEXT NOT NULL, name TEXT NOT NULL, ipv4 TEXT NOT NULL DEFAULT '', ipv6 TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, removed_at INTEGER);
		CREATE TABLE names (name TEXT PRIMARY KEY, member_id INTEGER NOT NULL, device_id INTEGER, held_until INTEGER, created_at INTEGER NOT NULL);
		INSERT INTO members (id, handle, role, status, hs_user_id, created_at) VALUES (1, 'alice', 'owner', 'active', '1', 1);
		INSERT INTO devices (id, member_id, kind, hs_node_id, name, ipv4, created_at) VALUES (1, 1, 'personal', '10', 'alice-lap', '100.64.0.10', 1);
	`)
	_ = rawDB.Close()
	if err != nil {
		t.Fatal(err)
	}

	st, err := OpenStore(legacyPath)
	if err != nil {
		t.Fatalf("OpenStore on legacy DB: %v", err)
	}
	defer st.Close()

	hs := newFakeHeadscale(t)
	hs.nodes = []HSNode{{
		ID:          "10",
		MachineKey:  testMachineKey("backfilled-10"),
		NodeKey:     testNodeKey("backfilled-10"),
		Name:        "alice-lap",
		GivenName:   "alice-lap",
		IPAddresses: []string{"100.64.0.10"},
		User:        &HSUser{ID: "1", Name: "alice"},
	}}
	svc, err := NewService(Config{Zone: "bobo.hogman", PublicHost: "hs.example.com", CoreIP: "100.64.0.1"}, st, NewHeadscale(hs.srv.URL, "k"))
	if err != nil {
		t.Fatal(err)
	}

	// Before initial Sync, missing node_key/machine_key fails closed.
	if _, _, err := svc.VerifyDirectPeer(context.Background(), &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: "10", NodeKey: testNodeKey("backfilled-10"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before backfill VerifyDirectPeer = %v, want ErrNotFound", err)
	}

	// Initial Sync backfills both keys without falsely auditing device.key_rotate.
	if err := svc.Sync(context.Background()); err != nil {
		t.Fatalf("initial Sync backfill: %v", err)
	}
	d, err := st.DeviceByHSNodeID("10")
	if err != nil || d.NodeKey != testNodeKey("backfilled-10") || d.MachineKey != testMachineKey("backfilled-10") {
		t.Fatalf("backfilled device = %+v err=%v", d, err)
	}
	logs, _ := st.AuditLog(10)
	for _, entry := range logs {
		if entry.Action == "device.key_rotate" {
			t.Fatalf("initial backfill should not log false device.key_rotate: %+v", entry)
		}
	}
	// After backfill, VerifyDirectPeer succeeds with 0 Headscale calls.
	hs.mu.Lock()
	hs.listNodesCalls, hs.getNodeCalls = 0, 0
	hs.mu.Unlock()
	if m, _, err := svc.VerifyDirectPeer(context.Background(), &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: "10", NodeKey: testNodeKey("backfilled-10"),
	}); err != nil || m.Handle != "alice" {
		t.Fatalf("after backfill VerifyDirectPeer = (%+v, %v)", m, err)
	}
	hs.mu.Lock()
	if hs.listNodesCalls != 0 || hs.getNodeCalls != 0 {
		t.Fatalf("after backfill VerifyDirectPeer hit Headscale")
	}
	hs.mu.Unlock()
}

func TestHeadscaleClientHardening(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/node", func(w http.ResponseWriter, r *http.Request) {
		// Write 8 MiB + 16 bytes to trigger overflow error.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxHSResponseBytes+16))
	})
	mux.HandleFunc("GET /api/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(bytes.Repeat([]byte("E"), maxHSErrorBytes+500))
	})
	mux.HandleFunc("GET /api/v1/node/{id}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("id") {
		case "42":
			_ = json.NewEncoder(w).Encode(map[string]any{"node": HSNode{ID: "99"}})
		case "404":
			http.Error(w, "node not found", http.StatusNotFound)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"node": HSNode{ID: r.PathValue("id")}})
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	hs := NewHeadscale(srv.URL, "k")

	// 1. Oversized response returns explicit overflow error.
	if _, err := hs.Nodes(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("oversized Nodes() err = %v, want overflow error", err)
	}
	// 2. Oversized error body is truncated in HSError.
	_, err := hs.Policy(context.Background())
	var he *HSError
	if !errors.As(err, &he) || !strings.HasSuffix(he.Body, "...(truncated)") || len(he.Body) > maxHSErrorBytes+32 {
		t.Fatalf("oversized error body not truncated properly: err=%v len=%d", err, len(he.Body))
	}
	// 3. Invalid IDs rejected locally (empty, dot segments, slashes).
	for _, badID := range []string{"  ", ".", "..", "1/2", "1\\2"} {
		if _, err := hs.Node(context.Background(), badID); err == nil {
			t.Fatalf("Node(%q) succeeded, want error", badID)
		}
	}
	// 4. Mismatched node ID rejected.
	if _, err := hs.Node(context.Background(), "42"); err == nil || !strings.Contains(err.Error(), "mismatched") {
		t.Fatalf("Node(42) with id=99 response: err=%v, want mismatched error", err)
	}
	// 5. 404 translated to ErrNotFound.
	if _, err := hs.Node(context.Background(), "404"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Node(404) err=%v, want ErrNotFound", err)
	}
	// 6. Valid single-node fetch succeeds.
	if n, err := hs.Node(context.Background(), "7"); err != nil || n.ID != "7" {
		t.Fatalf("Node(7) = (%+v, %v)", n, err)
	}
}

func TestEmbeddedHealthzReadinessAndServeModeValidation(t *testing.T) {
	// 1. /healthz returns 503 not-ready before ready flips true, then 200 ok.
	t.Setenv("HOME_TLS_DIR", "")
	var ready atomic.Bool
	h := embeddedHealthzHandler(&ready, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "not-ready") {
		t.Fatalf("unready /healthz = %d %q, want 503 not-ready", rec.Code, rec.Body.String())
	}

	ready.Store(true)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready /healthz = %d %q, want 200", rec.Code, rec.Body.String())
	}

	// 2. validateServeMode fail-closed matrix.
	cases := []struct {
		name       string
		tsnetDir   string
		legacyFlag string
		meshAddr   string
		wantLegacy bool
		wantErr    bool
	}{
		{"production tsnet", "/var/lib/registrar/tsnet", "", "", false, false},
		{"missing both fails closed", "", "", "unix:/run/mesh.sock", false, true},
		{"mutually exclusive", "/var/lib/registrar/tsnet", "1", "unix:/run/mesh.sock", false, true},
		{"legacy requires unix socket", "", "1", "127.0.0.1:8082", false, true},
		{"legacy empty unix path fails", "", "1", "unix:", false, true},
		{"legacy empty mesh addr fails", "", "1", "", false, true},
		{"legacy unix socket valid", "", "1", "unix:/run/mesh.sock", true, false},
	}
	for _, tc := range cases {
		legacy, err := validateServeMode(tc.tsnetDir, tc.legacyFlag, tc.meshAddr)
		if (err != nil) != tc.wantErr || legacy != tc.wantLegacy {
			t.Fatalf("%s: got (legacy=%v, err=%v), want (legacy=%v, wantErr=%v)", tc.name, legacy, err, tc.wantLegacy, tc.wantErr)
		}
	}
}

func TestErrorCooldownsEmptyPresenceCacheAndWaitBackground(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	var clockMu sync.Mutex
	nowT := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	e.svc.nowFn = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return nowT
	}
	e.svc.cfg.PresenceTTL = 5 * time.Second

	// 1. Empty Headscale node list is cached (non-nil map) instead of hammering Headscale.
	snap1 := e.svc.PresenceSnapshot(ctx)
	snap2 := e.svc.PresenceSnapshot(ctx)
	if snap1 == nil || snap2 == nil || len(snap1) != 0 {
		t.Fatalf("empty PresenceSnapshot = (%v, %v), want non-nil empty map", snap1, snap2)
	}
	e.hs.mu.Lock()
	if e.hs.listNodesCalls != 1 {
		t.Fatalf("empty PresenceSnapshot called ListNodes %d times, want 1", e.hs.listNodesCalls)
	}
	e.hs.mu.Unlock()

	// 2. Headscale 502 error in PresenceSnapshot enforces TTL cooldown (no amplification storm).
	clockMu.Lock()
	nowT = nowT.Add(6 * time.Second)
	clockMu.Unlock()
	e.hs.mu.Lock()
	e.hs.failListNodes = true
	e.hs.listNodesCalls = 0
	e.hs.mu.Unlock()
	for i := 0; i < 5; i++ {
		_ = e.svc.PresenceSnapshot(ctx)
	}
	e.hs.mu.Lock()
	if e.hs.listNodesCalls != 1 {
		t.Fatalf("5 failing PresenceSnapshot calls hit Headscale %d times, want 1 (cooldown)", e.hs.listNodesCalls)
	}
	e.hs.mu.Unlock()

	// 3. Headscale 502 error in inline Sync enforces 3s cooldown (no amplification storm).
	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.IssueDeviceKey(ctx, cli, "alice", "server"); err != nil {
		t.Fatal(err)
	}
	e.hs.mu.Lock()
	e.hs.listNodesCalls = 0
	e.hs.mu.Unlock()
	for i := 0; i < 5; i++ {
		_, _, _ = e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
			IP: "100.64.0.99", HSNodeID: "unknown-1", NodeKey: testNodeKey("unknown"),
		})
	}
	e.hs.mu.Lock()
	if e.hs.listNodesCalls != 1 {
		t.Fatalf("5 failing inline Syncs hit Headscale %d times, want 1 (error cooldown)", e.hs.listNodesCalls)
	}
	e.hs.failListNodes = false
	e.hs.mu.Unlock()

	// 4. WaitBackground waits for a detached Sync worker before returning.
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	e.hs.mu.Lock()
	e.hs.onListNodes = func(_ context.Context) {
		started <- struct{}{}
		<-release
	}
	e.hs.mu.Unlock()

	callerCtx, callerCancel := context.WithCancel(context.Background())
	go func() { _ = e.svc.Sync(callerCtx) }()
	<-started
	callerCancel()

	waited := make(chan struct{})
	go func() {
		e.svc.WaitBackground(context.Background())
		close(waited)
	}()
	select {
	case <-waited:
		t.Fatal("WaitBackground returned while detached Sync worker was still running")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitBackground did not unblock after detached Sync worker exited")
	}
	e.hs.mu.Lock()
	e.hs.onListNodes = nil
	e.hs.mu.Unlock()
}

func TestCrossProcessPolicySerialization(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	if _, err := e.svc.AddMember(ctx, cli, "owner1", "owner"); err != nil {
		t.Fatal(err)
	}
	bob, err := e.svc.AddMember(ctx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "owner1", "personal", "owner-lap", "100.64.0.10", "")
	e.addDevice(t, "bob", "personal", "bob-lap", "100.64.0.11", "")
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}

	// Open a second Store + Service on the same SQLite DB file (simulating CLI process).
	st2, err := OpenStore(filepath.Join(e.dir, "registrar.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	svc2, err := NewService(e.svc.cfg, st2, NewHeadscale(e.hs.srv.URL, "test-key"))
	if err != nil {
		t.Fatal(err)
	}

	// Suspend bob via svc2 concurrently with svc1 Sync(); final Headscale policy MUST
	// exclude bob (100.64.0.11) and policy_gen == applied_gen.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = e.svc.Sync(ctx)
	}()
	go func() {
		defer wg.Done()
		if err := svc2.Suspend(ctx, cli, "bob", "cli-suspend"); err != nil {
			t.Errorf("CLI Suspend: %v", err)
		}
	}()
	wg.Wait()

	// If svc1 ran before Suspend, Sync won't clobber; if svc1 ran after Suspend, Sync builds without bob.
	// Either way, bob must be suspended in DB and excluded from final Headscale policy.
	if gotBob, _ := e.st.MemberByID(bob.ID); gotBob.Status != "suspended" {
		t.Fatalf("bob status = %q, want suspended", gotBob.Status)
	}
	e.hs.mu.Lock()
	finalPol := e.hs.policy
	e.hs.mu.Unlock()
	if strings.Contains(finalPol, "100.64.0.11") {
		t.Fatalf("final Headscale policy still grants access to suspended bob:\n%s", finalPol)
	}
}

// TestRealHeadscale0297FixtureMatchesTailcfgNodeKey verifies that an exact
// captured GET /api/v1/node JSON response from headscale/headscale:0.29.7
// (covering both a personal node and a tag:server node with Headscale's
// tagged-devices pseudo-user 2147455555) parses cleanly through canonical
// key.NodePublic / key.MachinePublic normalization and matches tailcfg.Node.Key
// as returned by tsnet WhoIs().
func TestRealHeadscale0297FixtureMatchesTailcfgNodeKey(t *testing.T) {
	// Captured directly from an ephemeral headscale/headscale:0.29.7 container
	// with disposable synthetic tailscale/tailscale:v1.104.7 nodes.
	const capturedListNodesJSON = `{
  "nodes": [
    {
      "id": "1",
      "machineKey": "mkey:e438d44e8488876479738d2017d7738fc66b36bd8d6b85e637ed71bb2173a215",
      "nodeKey": "nodekey:b5994765e77570a3d011d39ac5050973ebc953a9041cfe7dc7246d8bb806e063",
      "discoKey": "discokey:832fda1996674b39a093e96285d19f7a7803cbeeb8325e53e2502904047bac59",
      "ipAddresses": [
        "100.64.0.1",
        "fd7a:115c:a1e0::1"
      ],
      "name": "alice-laptop",
      "user": {
        "id": "1",
        "name": "alice",
        "createdAt": "2026-11-25T14:23:32.531882212Z",
        "displayName": "",
        "email": "",
        "providerId": "",
        "provider": "",
        "profilePicUrl": ""
      },
      "lastSeen": "2026-11-25T14:23:34.710330630Z",
      "expiry": null,
      "preAuthKey": {
        "user": {
          "id": "1",
          "name": "alice",
          "createdAt": "2026-11-25T14:23:32.531882212Z",
          "displayName": "",
          "email": "",
          "providerId": "",
          "provider": "",
          "profilePicUrl": ""
        },
        "id": "1",
        "key": "hskey-auth-FIXBEkNxM-vH-***",
        "reusable": false,
        "ephemeral": false,
        "used": true,
        "expiration": "2026-11-25T15:23:33.279723046Z",
        "createdAt": "2026-11-25T14:23:33.280365087Z",
        "aclTags": []
      },
      "createdAt": "2026-11-25T14:23:33.849854421Z",
      "registerMethod": "REGISTER_METHOD_AUTH_KEY",
      "givenName": "alice-laptop",
      "online": false,
      "approvedRoutes": [],
      "availableRoutes": [],
      "subnetRoutes": [],
      "tags": []
    },
    {
      "id": "2",
      "machineKey": "mkey:1ee6564c897e325f8631ee28e929237ee135e0cbbad1e5038e4c40791ee4ec73",
      "nodeKey": "nodekey:5786c3765837a3889be946a27d4326e69dbaaaee45080623724cc43d14f27b71",
      "discoKey": "discokey:0000000000000000000000000000000000000000000000000000000000000000",
      "ipAddresses": [
        "100.64.0.2",
        "fd7a:115c:a1e0::2"
      ],
      "name": "alice-srv",
      "user": {
        "id": "2147455555",
        "name": "tagged-devices",
        "createdAt": "0001-01-01T00:00:00Z",
        "displayName": "Tagged Devices",
        "email": "",
        "providerId": "",
        "provider": "",
        "profilePicUrl": ""
      },
      "lastSeen": "2026-11-25T14:23:33.904388046Z",
      "expiry": null,
      "preAuthKey": {
        "user": null,
        "id": "2",
        "key": "hskey-auth-Rt_ng_raG3ko-***",
        "reusable": false,
        "ephemeral": false,
        "used": true,
        "expiration": "2026-11-25T15:23:33.402724004Z",
        "createdAt": "2026-11-25T14:23:33.402887379Z",
        "aclTags": [
          "tag:server"
        ]
      },
      "createdAt": "2026-11-25T14:23:33.904574963Z",
      "registerMethod": "REGISTER_METHOD_AUTH_KEY",
      "givenName": "alice-srv",
      "online": false,
      "approvedRoutes": [],
      "availableRoutes": [],
      "subnetRoutes": [],
      "tags": [
        "tag:server"
      ]
    }
  ]
}`

	var listCalls, getCalls atomic.Int32
	var rawNodes struct {
		Nodes []json.RawMessage `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(capturedListNodesJSON), &rawNodes); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/node", func(w http.ResponseWriter, r *http.Request) {
		listCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(capturedListNodesJSON))
	})
	mux.HandleFunc("GET /api/v1/node/{id}", func(w http.ResponseWriter, r *http.Request) {
		getCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.PathValue("id") {
		case "1":
			_, _ = w.Write([]byte(`{"node":` + string(rawNodes.Nodes[0]) + `}`))
		case "2":
			_, _ = w.Write([]byte(`{"node":` + string(rawNodes.Nodes[1]) + `}`))
		default:
			http.Error(w, "node not found", http.StatusNotFound)
		}
	})
	mux.HandleFunc("PUT /api/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	st, err := OpenStore(filepath.Join(dir, "registrar.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc, err := NewService(Config{Zone: "bobo.hogman", PublicHost: "hs.example.com", CoreIP: "100.64.0.10"}, st, NewHeadscale(srv.URL, "k"))
	if err != nil {
		t.Fatal(err)
	}

	alice := &Member{Handle: "alice", Role: "owner", Status: "active", HSUserID: "1"}
	if err := st.InsertMember(alice); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertDeviceKey(&DeviceKey{MemberID: alice.ID, Kind: "personal", HSKeyID: "1", ExpiresAt: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertDeviceKey(&DeviceKey{MemberID: alice.ID, Kind: "server", HSKeyID: "2", ExpiresAt: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}

	// Sync enrolls both nodes straight from the captured 0.29.7 JSON body.
	if err := svc.Sync(context.Background()); err != nil {
		t.Fatalf("Sync captured 0.29.7 fixture: %v", err)
	}
	listCalls.Store(0)
	getCalls.Store(0)

	// Construct real tailcfg.Node values using key.NodePublic.UnmarshalText,
	// identical to what tsnet LocalClient.WhoIs() produces on the wire.
	mustTailcfgNode := func(id tailcfg.NodeID, rawKey string) *tailcfg.Node {
		t.Helper()
		var k key.NodePublic
		if err := k.UnmarshalText([]byte(rawKey)); err != nil {
			t.Fatalf("key.NodePublic.UnmarshalText(%q): %v", rawKey, err)
		}
		return &tailcfg.Node{ID: id, Key: k}
	}
	pNode := mustTailcfgNode(1, "nodekey:b5994765e77570a3d011d39ac5050973ebc953a9041cfe7dc7246d8bb806e063")
	sNode := mustTailcfgNode(2, "nodekey:5786c3765837a3889be946a27d4326e69dbaaaee45080623724cc43d14f27b71")

	// Steady-state VerifyDirectPeer succeeds for BOTH personal and tag:server
	// nodes with ZERO Headscale calls.
	if m, d, err := svc.VerifyDirectPeer(context.Background(), &PeerIdentity{
		IP: "100.64.0.1", HSNodeID: "1", NodeKey: pNode.Key.String(),
	}); err != nil || m.Handle != "alice" || d.Kind != "personal" {
		t.Fatalf("personal VerifyDirectPeer on 0.29.7 fixture: m=%+v d=%+v err=%v", m, d, err)
	}
	if m, d, err := svc.VerifyDirectPeer(context.Background(), &PeerIdentity{
		IP: "100.64.0.2", HSNodeID: "2", NodeKey: sNode.Key.String(),
	}); err != nil || m.Handle != "alice" || d.Kind != "server" {
		t.Fatalf("server VerifyDirectPeer on 0.29.7 fixture: m=%+v d=%+v err=%v", m, d, err)
	}
	if listCalls.Load() != 0 || getCalls.Load() != 0 {
		t.Fatalf("0.29.7 fixture steady-state auth hit Headscale (list=%d get=%d), want 0", listCalls.Load(), getCalls.Load())
	}

	// Normalization test: uppercase hex and bare 64-hex (without prefix) normalize
	// identically to canonical key.NodePublic / key.MachinePublic strings.
	bareUpperNK := strings.ToUpper(strings.TrimPrefix(pNode.Key.String(), "nodekey:"))
	if got, ok := canonicalNodeKey(bareUpperNK); !ok || got != pNode.Key.String() {
		t.Fatalf("canonicalNodeKey(bare upper) = (%q, %v), want (%q, true)", got, ok, pNode.Key.String())
	}
	wantMK := "mkey:1ee6564c897e325f8631ee28e929237ee135e0cbbad1e5038e4c40791ee4ec73"
	bareUpperMK := strings.ToUpper(strings.TrimPrefix(wantMK, "mkey:"))
	if got, ok := canonicalMachineKey(bareUpperMK); !ok || got != wantMK {
		t.Fatalf("canonicalMachineKey(bare upper) = (%q, %v), want (%q, true)", got, ok, wantMK)
	}
	if _, ok := canonicalNodeKey("nodekey:0000000000000000000000000000000000000000000000000000000000000000"); ok {
		t.Fatal("canonicalNodeKey accepted all-zero key")
	}
	if _, ok := canonicalMachineKey("mkey:not-valid-hex"); ok {
		t.Fatal("canonicalMachineKey accepted invalid hex")
	}
}

func TestSyncDriftCircuitBreakerPreventsMassRetirement(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	_, d1 := e.addDevice(t, "alice", "personal", "alice-1", "100.64.0.10", "")
	_, d2 := e.addDevice(t, "alice", "server", "alice-2", "100.64.0.11", "")
	_, d3 := e.addDevice(t, "bob", "personal", "bob-1", "100.64.0.12", "")

	// Simulate a serialization bug / mass drift hitting 2 of 3 live devices in one pass.
	e.hs.mu.Lock()
	for i := range e.hs.nodes {
		if e.hs.nodes[i].ID == d1.HSNodeID || e.hs.nodes[i].ID == d2.HSNodeID {
			e.hs.nodes[i].MachineKey = testMachineKey("mass-drift-" + e.hs.nodes[i].ID)
		}
	}
	e.hs.mu.Unlock()

	err := e.svc.Sync(ctx)
	if err == nil || !strings.Contains(err.Error(), "circuit breaker") {
		t.Fatalf("mass drift Sync() = %v, want circuit breaker error", err)
	}
	// ALL 3 devices MUST remain live and serving (zero retirements!).
	live, err := e.st.LiveDevices()
	if err != nil || len(live) != 3 {
		t.Fatalf("live devices after circuit breaker = %d (err=%v), want 3", len(live), err)
	}
	for _, d := range []*Device{d1, d2, d3} {
		if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
			IP: d.IPv4, HSNodeID: d.HSNodeID, NodeKey: d.NodeKey,
		}); err != nil {
			t.Fatalf("device %s stopped serving after circuit breaker: %v", d.Name, err)
		}
	}
	// Audit entry sync.drift_breaker must be recorded.
	logs, _ := e.st.AuditLog(10)
	foundBreakerAudit := false
	for _, entry := range logs {
		if entry.Action == "sync.drift_breaker" {
			foundBreakerAudit = true
		}
	}
	if !foundBreakerAudit {
		t.Fatalf("missing sync.drift_breaker audit entry: %+v", logs)
	}

	// Restore d2 so only 1 device (d1) genuinely drifted: single-device retirement still works!
	e.hs.mu.Lock()
	for i := range e.hs.nodes {
		if e.hs.nodes[i].ID == d2.HSNodeID {
			e.hs.nodes[i].MachineKey = d2.MachineKey
		}
	}
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("single-device drift Sync() failed: %v", err)
	}
	got1, _ := e.st.DeviceByID(d1.ID)
	got2, _ := e.st.DeviceByID(d2.ID)
	got3, _ := e.st.DeviceByID(d3.ID)
	if got1.RemovedAt == nil || got2.RemovedAt != nil || got3.RemovedAt != nil {
		t.Fatalf("single-device drift result: d1.Removed=%v d2.Removed=%v d3.Removed=%v", got1.RemovedAt, got2.RemovedAt, got3.RemovedAt)
	}
}

func TestInlineSyncFailureReturns403AndMissingMachineKeyAlertsOnce(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.IssueDeviceKey(ctx, cli, "alice", "server"); err != nil {
		t.Fatal(err)
	}

	// 1. Inline Sync failure for an unknown peer returns ErrNotFound (HTTP 403), NOT 500.
	e.hs.mu.Lock()
	e.hs.failListNodes = true
	e.hs.mu.Unlock()
	_, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.99", HSNodeID: "unknown-403", NodeKey: testNodeKey("unknown-403"),
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("inline Sync failure returned %v, want ErrNotFound (403)", err)
	}

	// 2. Device with empty machine_key in both SQLite and Headscale triggers missingMKAlerted once.
	e.hs.mu.Lock()
	e.hs.failListNodes = false
	e.hs.mu.Unlock()
	_, d := e.addDevice(t, "alice", "personal", "legacy-no-mk", "100.64.0.33", "")
	if _, err := e.st.db.Exec(`UPDATE devices SET machine_key = '' WHERE id = ?`, d.ID); err != nil {
		t.Fatal(err)
	}
	e.hs.mu.Lock()
	for i := range e.hs.nodes {
		if e.hs.nodes[i].ID == d.HSNodeID {
			e.hs.nodes[i].MachineKey = ""
		}
	}
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("Sync missing machine_key: %v", err)
	}
	if !e.svc.missingMKAlerted[d.HSNodeID] {
		t.Fatalf("expected missingMKAlerted[%q] = true after Sync with empty machine_key", d.HSNodeID)
	}
}
