package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildPolicyIPv4OnlyCompactAndMemberInsertNoBump(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "fd7a:115c:a1e0::10")
	e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "fd7a:115c:a1e0::11")

	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	polBefore, _, err := e.svc.buildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(polBefore, "\n") {
		t.Fatalf("expected compact JSON policy without newlines, got:\n%s", polBefore)
	}
	if strings.Contains(polBefore, "fd7a:") {
		t.Fatalf("expected IPv4-only policy without IPv6 addresses, got:\n%s", polBefore)
	}
	if !strings.Contains(polBefore, `"100.64.0.10"`) || !strings.Contains(polBefore, `"100.64.0.11"`) {
		t.Fatalf("expected IPv4 addresses in policy, got:\n%s", polBefore)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(polBefore), &parsed); err != nil {
		t.Fatalf("policy must be valid JSON: %v", err)
	}

	genBefore, appliedBefore, err := e.st.PolicyGenerations()
	if err != nil {
		t.Fatal(err)
	}
	if genBefore != appliedBefore {
		t.Fatalf("expected policy_gen == applied_gen after sync, got %d vs %d", genBefore, appliedBefore)
	}
	policyCalls := func() int {
		e.hs.mu.Lock()
		defer e.hs.mu.Unlock()
		return e.hs.setPolicyCalls
	}
	pushesBefore := policyCalls()

	// Adding a brand-new member with 0 devices must NOT change buildPolicy()
	// and must NOT bump policy_gen or trigger a redundant SetPolicy push.
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	polAfter, _, err := e.svc.buildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if polAfter != polBefore {
		t.Fatalf("adding device-less member changed policy:\nbefore: %s\nafter:  %s", polBefore, polAfter)
	}
	genAfter, appliedAfter, err := e.st.PolicyGenerations()
	if err != nil {
		t.Fatal(err)
	}
	if genAfter != genBefore || appliedAfter != appliedBefore {
		t.Fatalf("adding device-less member bumped policy_gen: before=(%d,%d) after=(%d,%d)",
			genBefore, appliedBefore, genAfter, appliedAfter)
	}
	if e.svc.NeedsFastSync() {
		t.Fatal("NeedsFastSync() must stay false after adding device-less member")
	}
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("sync after device-less member: %v", err)
	}
	if got := policyCalls(); got != pushesBefore {
		t.Fatalf("SetPolicy calls = %d, want %d (no wasted push on device-less member)", got, pushesBefore)
	}
}

func TestLegacyTriggersMigratedOnOpenAndIPv6UpdateNoBump(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	st1, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an upgraded database with legacy members_policy_gen_ai and
	// legacy devices_policy_gen_au watching ipv6.
	if _, err := st1.db.Exec(`
		CREATE TRIGGER members_policy_gen_ai AFTER INSERT ON members BEGIN UPDATE sync_state SET policy_gen = policy_gen + 1 WHERE id = 1; END;
		DROP TRIGGER IF EXISTS devices_policy_gen_au;
		CREATE TRIGGER devices_policy_gen_au AFTER UPDATE OF member_id, kind, ipv4, ipv6, removed_at ON devices
		WHEN OLD.member_id IS NOT NEW.member_id OR OLD.kind IS NOT NEW.kind OR OLD.ipv4 IS NOT NEW.ipv4 OR OLD.ipv6 IS NOT NEW.ipv6 OR OLD.removed_at IS NOT NEW.removed_at
		BEGIN UPDATE sync_state SET policy_gen = policy_gen + 1 WHERE id = 1; END;
	`); err != nil {
		t.Fatalf("create legacy triggers: %v", err)
	}
	if err := st1.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st2.Close()

	var count int
	if err := st2.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = 'members_policy_gen_ai'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected legacy trigger members_policy_gen_ai to be dropped on OpenStore, count=%d", count)
	}
	var devTrigSQL string
	if err := st2.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'devices_policy_gen_au'`).Scan(&devTrigSQL); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(devTrigSQL), "ipv6") {
		t.Fatalf("expected migrated devices_policy_gen_au to drop ipv6, got: %s", devTrigSQL)
	}

	// Inserting a member must leave policy_gen untouched.
	g0, _, err := st2.PolicyGenerations()
	if err != nil {
		t.Fatal(err)
	}
	m := &Member{Handle: "carol", Role: "member", Status: "active"}
	if err := st2.InsertMember(m); err != nil {
		t.Fatal(err)
	}
	g1, _, err := st2.PolicyGenerations()
	if err != nil {
		t.Fatal(err)
	}
	if g1 != g0 {
		t.Fatalf("policy_gen changed from %d to %d after member insert", g0, g1)
	}

	// Updating only devices.ipv6 must NOT bump policy_gen, whereas updating ipv4 MUST.
	d := &Device{MemberID: m.ID, Kind: "personal", HSNodeID: "hs-carol", NodeKey: testNodeKey("carol"), MachineKey: testMachineKey("carol"), Name: "carol-lap", IPv4: "100.64.0.50", IPv6: "fd7a:115c:a1e0::50"}
	if err := st2.InsertDevice(d); err != nil {
		t.Fatal(err)
	}
	g2, _, err := st2.PolicyGenerations()
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.UpdateDevice(d.ID, "carol-lap", "100.64.0.50", "fd7a:115c:a1e0::51", d.NodeKey, d.MachineKey); err != nil {
		t.Fatal(err)
	}
	g3, _, err := st2.PolicyGenerations()
	if err != nil {
		t.Fatal(err)
	}
	if g3 != g2 {
		t.Fatalf("updating only ipv6 bumped policy_gen from %d to %d", g2, g3)
	}
	if err := st2.UpdateDevice(d.ID, "carol-lap", "100.64.0.52", "fd7a:115c:a1e0::51", d.NodeKey, d.MachineKey); err != nil {
		t.Fatal(err)
	}
	g4, _, err := st2.PolicyGenerations()
	if err != nil {
		t.Fatal(err)
	}
	if g4 <= g3 {
		t.Fatalf("updating ipv4 did not bump policy_gen (%d -> %d)", g3, g4)
	}
}

func TestSelfDeleteUnderMutexContentionInstantRevokeAndMeExclusion(t *testing.T) {
	e := newTestEnv(t)
	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	e.svc.SetBaseContext(baseCtx)
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(baseCtx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	_, dev1 := e.addDevice(t, "alice", "personal", "alice-laptop1", "100.64.0.10", "fd7a:115c:a1e0::10")
	_, dev2 := e.addDevice(t, "alice", "personal", "alice-laptop2", "100.64.0.11", "fd7a:115c:a1e0::11")
	if err := e.svc.Sync(baseCtx); err != nil {
		t.Fatalf("sync: %v", err)
	}

	h := MeshHandlerDirect(e.svc, func(_ context.Context, remoteAddr string) (*PeerIdentity, error) {
		if strings.HasPrefix(remoteAddr, "100.64.0.10:") {
			return &PeerIdentity{IP: "100.64.0.10", HSNodeID: dev1.HSNodeID, NodeKey: dev1.NodeKey}, nil
		}
		if strings.HasPrefix(remoteAddr, "100.64.0.11:") {
			return &PeerIdentity{IP: "100.64.0.11", HSNodeID: dev2.HSNodeID, NodeKey: dev2.NodeKey}, nil
		}
		return nil, ErrNotFound
	})

	// Hold s.mu to simulate a long-running Sync() under contention while dev1
	// sends DELETE /api/devices/<self> and immediately disconnects.
	e.svc.mu.Lock()
	reqCtx, cancelReq := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodDelete, "/api/devices/"+strconv.FormatInt(dev1.ID, 10), nil).WithContext(reqCtx)
	req.Host = "home.bobo.hogman"
	req.RemoteAddr = "100.64.0.10:54321"
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	t0 := time.Now()
	h.ServeHTTP(rec, req)
	elapsed := time.Since(t0)
	cancelReq()

	if rec.Code != http.StatusAccepted {
		e.svc.mu.Unlock()
		t.Fatalf("self-delete under contention status = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	if elapsed > 2*time.Second {
		e.svc.mu.Unlock()
		t.Fatalf("self-delete blocked on s.mu for %v, expected immediate 202", elapsed)
	}

	// Immediately after 202 (while s.mu is still held):
	// 1. dev1 must be immediately rejected on /api/me (403 "not enrolled").
	me1Rec := httptest.NewRecorder()
	me1Req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	me1Req.Host = "home.bobo.hogman"
	me1Req.RemoteAddr = "100.64.0.10:54322"
	h.ServeHTTP(me1Rec, me1Req)
	if me1Rec.Code != http.StatusForbidden || !strings.Contains(me1Rec.Body.String(), "not enrolled") {
		e.svc.mu.Unlock()
		t.Fatalf("post-202 GET /api/me from self-deleting device: status=%d body=%s, want 403 not enrolled", me1Rec.Code, me1Rec.Body.String())
	}

	// 2. dev2's GET /api/me must already exclude dev1 from devices (so sole-owner
	//    leave risk sees only dev2 remaining even before s.mu releases).
	me2Rec := httptest.NewRecorder()
	me2Req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	me2Req.Host = "home.bobo.hogman"
	me2Req.RemoteAddr = "100.64.0.11:54323"
	h.ServeHTTP(me2Rec, me2Req)
	if me2Rec.Code != http.StatusOK {
		e.svc.mu.Unlock()
		t.Fatalf("dev2 GET /api/me status=%d body=%s", me2Rec.Code, me2Rec.Body.String())
	}
	var me2 struct {
		Devices []Device `json:"devices"`
	}
	if err := json.Unmarshal(me2Rec.Body.Bytes(), &me2); err != nil {
		e.svc.mu.Unlock()
		t.Fatalf("decode dev2 /api/me: %v", err)
	}
	if len(me2.Devices) != 1 || me2.Devices[0].ID != dev2.ID {
		e.svc.mu.Unlock()
		t.Fatalf("dev2 /api/me devices = %+v, want only dev2 (#%d)", me2.Devices, dev2.ID)
	}

	// Release s.mu and wait for background self-delete to finish.
	e.svc.mu.Unlock()
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	e.svc.WaitBackground(waitCtx)

	got, err := e.st.DeviceByID(dev1.ID)
	if err != nil {
		t.Fatalf("DeviceByID: %v", err)
	}
	if got.RemovedAt == nil {
		t.Fatal("expected device RemovedAt != nil in SQLite after contended self-delete")
	}
	e.hs.mu.Lock()
	stillInHS := false
	for _, n := range e.hs.nodes {
		if n.ID == dev1.HSNodeID {
			stillInHS = true
			break
		}
	}
	lastPol := e.hs.policy
	e.hs.mu.Unlock()
	if stillInHS {
		t.Fatalf("expected node %s deleted from Headscale", dev1.HSNodeID)
	}
	if strings.Contains(lastPol, `"100.64.0.10"`) {
		t.Fatalf("expected removed device IP dropped from Headscale policy:\n%s", lastPol)
	}
}

func TestRemoveDeviceRespectsCallerCancelAndAvoidsMutexDoS(t *testing.T) {
	e := newTestEnv(t)
	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	e.svc.SetBaseContext(baseCtx)
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(baseCtx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	_, dev := e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")

	var hsDeletes atomic.Int32
	e.hs.mu.Lock()
	e.hs.onDeleteNode = func(http.ResponseWriter, string) bool {
		hsDeletes.Add(1)
		return false
	}
	e.hs.mu.Unlock()

	deadCtx, cancelDead := context.WithCancel(context.Background())
	cancelDead()
	err := e.svc.RemoveDevice(deadCtx, cli, dev.ID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RemoveDevice(cancelled ctx) = %v, want context.Canceled", err)
	}
	if hsDeletes.Load() != 0 {
		t.Fatalf("expected 0 Headscale DeleteNode calls for cancelled ctx, got %d", hsDeletes.Load())
	}
	got, err := e.st.DeviceByID(dev.ID)
	if err != nil || got.RemovedAt != nil {
		t.Fatalf("device should still be live after cancelled RemoveDevice: got=%+v err=%v", got, err)
	}
}

func TestSelfDeleteAcceptedProceedsAfterConcurrentSuspend(t *testing.T) {
	e := newTestEnv(t)
	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	e.svc.SetBaseContext(baseCtx)
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(baseCtx, cli, "owner", "owner"); err != nil {
		t.Fatal(err)
	}
	bob, err := e.svc.AddMember(baseCtx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, dev := e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.20", "")

	// Queue self-delete while s.mu is held, then suspend bob in SQLite before releasing s.mu.
	e.svc.mu.Lock()
	if !e.svc.ScheduleSelfDelete(Actor{Member: bob}, dev.ID) {
		e.svc.mu.Unlock()
		t.Fatal("ScheduleSelfDelete returned false")
	}
	if err := e.st.SetMemberStatus(bob.ID, "suspended"); err != nil {
		e.svc.mu.Unlock()
		t.Fatal(err)
	}
	e.svc.mu.Unlock()

	waitCtx, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	e.svc.WaitBackground(waitCtx)

	got, err := e.st.DeviceByID(dev.ID)
	if err != nil || got.RemovedAt == nil {
		t.Fatalf("expected accepted self-delete to finish despite concurrent suspend: got=%+v err=%v", got, err)
	}
}

func TestDeleteNodeTreatsHTTP500NotFoundAsGone(t *testing.T) {
	e := newTestEnv(t)
	e.hs.mu.Lock()
	e.hs.onDeleteNode = func(w http.ResponseWriter, _ string) bool {
		http.Error(w, `{"code":2,"message":"node not found"}`, http.StatusInternalServerError)
		return true
	}
	e.hs.mu.Unlock()

	if err := e.svc.hs.DeleteNode(context.Background(), "999"); err != nil {
		t.Fatalf("DeleteNode on Headscale HTTP 500 not-found = %v, want nil", err)
	}
}

func TestScheduleSelfDeleteRetriesApplyPolicyAfterDBCommit(t *testing.T) {
	e := newTestEnv(t)
	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	e.svc.SetBaseContext(baseCtx)
	cli := Actor{CLI: true}

	alice, err := e.svc.AddMember(baseCtx, cli, "alice", "owner")
	if err != nil {
		t.Fatal(err)
	}
	_, dev := e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	if err := e.svc.Sync(baseCtx); err != nil {
		t.Fatal(err)
	}

	// Fail SetPolicy once so attempt 1 commits MarkDeviceRemoved then errors in applyPolicy;
	// release failSetPolicy right after and confirm attempt 2 converges Headscale policy.
	e.hs.mu.Lock()
	e.hs.failSetPolicy = true
	e.hs.mu.Unlock()

	if !e.svc.ScheduleSelfDelete(Actor{Member: alice}, dev.ID) {
		t.Fatal("ScheduleSelfDelete returned false")
	}

	// Poll briefly until attempt 1 commits RemovedAt, then re-enable SetPolicy.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got, err := e.st.DeviceByID(dev.ID); err == nil && got.RemovedAt != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.hs.mu.Lock()
	e.hs.failSetPolicy = false
	e.hs.mu.Unlock()

	waitCtx, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	e.svc.WaitBackground(waitCtx)

	e.hs.mu.Lock()
	pol := e.hs.policy
	e.hs.mu.Unlock()
	if strings.Contains(pol, `"100.64.0.10"`) {
		t.Fatalf("expected retry to converge policy after applyPolicy failure, policy still had IP:\n%s", pol)
	}
	if e.svc.NeedsFastSync() {
		t.Fatal("expected policy_gen == applied_gen after applyPolicy retry")
	}
}

func TestBeginShutdownRefusesNewSelfDelete(t *testing.T) {
	e := newTestEnv(t)
	cli := Actor{CLI: true}
	alice, err := e.svc.AddMember(context.Background(), cli, "alice", "owner")
	if err != nil {
		t.Fatal(err)
	}
	_, dev := e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")

	e.svc.BeginShutdown()
	if e.svc.ScheduleSelfDelete(Actor{Member: alice}, dev.ID) {
		t.Fatal("expected ScheduleSelfDelete to return false after BeginShutdown")
	}

	h := MeshHandlerDirect(e.svc, func(_ context.Context, _ string) (*PeerIdentity, error) {
		return &PeerIdentity{IP: "100.64.0.10", HSNodeID: dev.HSNodeID, NodeKey: dev.NodeKey}, nil
	})
	req := httptest.NewRequest(http.MethodDelete, "/api/devices/"+strconv.FormatInt(dev.ID, 10), nil)
	req.Host = "home.bobo.hogman"
	req.RemoteAddr = "100.64.0.10:54321"
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("DELETE /api/devices/<self> during shutdown status = %d, want 503", rec.Code)
	}
}

func TestVerifyDirectPeerRejectsIPv6(t *testing.T) {
	e := newTestEnv(t)
	cli := Actor{CLI: true}
	if _, err := e.svc.AddMember(context.Background(), cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	_, dev := e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "fd7a:115c:a1e0::10")

	if _, _, err := e.svc.VerifyDirectPeer(context.Background(), &PeerIdentity{
		IP:       "fd7a:115c:a1e0::10",
		HSNodeID: dev.HSNodeID,
		NodeKey:  dev.NodeKey,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("VerifyDirectPeer over IPv6 = %v, want ErrNotFound", err)
	}
}
