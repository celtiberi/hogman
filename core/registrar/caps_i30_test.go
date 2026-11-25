package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPenCapsMembersDevicesAndRedeemGeneric409I30(t *testing.T) {
	e := newTestEnv(t)
	e.svc.cfg.MaxMembers = 3
	e.svc.cfg.MaxDevices = 3
	ctx := context.Background()
	cli := Actor{CLI: true}

	owner, err := e.svc.AddMember(ctx, cli, "owner1", "owner")
	if err != nil {
		t.Fatal(err)
	}
	aOwner := Actor{Member: owner}
	alice, err := e.svc.AddMember(ctx, aOwner, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := e.svc.AddMember(ctx, aOwner, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}
	_ = bob

	// 1. At MAX_MEMBERS=3: portal AddMember and MintInvite fail with 409.
	if _, err := e.svc.AddMember(ctx, aOwner, "carol", "member"); err == nil {
		t.Fatal("expected portal AddMember to hit MaxMembers")
	} else if p, ok := err.(*Problem); !ok || p.Status != http.StatusConflict {
		t.Fatalf("portal AddMember err = %v, want 409", err)
	}
	if _, err := e.svc.MintInvite(aOwner, "member", "", time.Hour); err == nil {
		t.Fatal("expected portal MintInvite to hit MaxMembers")
	} else if p, ok := err.(*Problem); !ok || p.Status != http.StatusConflict {
		t.Fatalf("portal MintInvite err = %v, want 409", err)
	}

	// 2. Suspended members still count toward MAX_MEMBERS.
	if err := e.svc.Suspend(ctx, cli, "bob", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, aOwner, "carol", "member"); err == nil {
		t.Fatal("suspended member must still count toward MaxMembers")
	}

	// 3. Public /hogman/v1/redeem:
	//    - Invalid invite token STILL returns 403 (never leaks fullness to unauthenticated callers).
	//    - Valid open CLI-minted invite returns generic 409 without counts or cap names.
	pub := PublicHandler(e.svc)
	postRedeem := func(tok, handle string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"token": tok, "handle": handle})
		req := httptest.NewRequest(http.MethodPost, "/hogman/v1/redeem", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.10:1234"
		rr := httptest.NewRecorder()
		pub.ServeHTTP(rr, req)
		return rr
	}
	if rr := postRedeem("hmi_not_a_real_invite_token", "carol"); rr.Code != http.StatusForbidden {
		t.Fatalf("invalid invite at cap = %d %s, want 403 (no fullness oracle)", rr.Code, rr.Body.String())
	}
	openInv, err := e.svc.MintInvite(cli, "member", "pre-minted", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rr := postRedeem(openInv.Token, "carol")
	if rr.Code != http.StatusConflict {
		t.Fatalf("valid invite at MaxMembers = %d %s, want 409", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "3") || strings.Contains(strings.ToLower(rr.Body.String()), "limit") || strings.Contains(strings.ToLower(rr.Body.String()), "device") {
		t.Fatalf("public /redeem leaked cap details: %s", rr.Body.String())
	}
	// Invite must remain open after cap rejection.
	if invAfter, err := e.st.InviteByID(openInv.ID); err != nil || invAfter.State() != "open" {
		t.Fatalf("invite state after cap refusal = %+v (err=%v), want open", invAfter, err)
	}

	// 4. Kicking/removing a member frees a member slot (even though their handle stays retired).
	if _, err := e.svc.Kick(ctx, cli, "bob", "bye"); err != nil {
		t.Fatal(err)
	}
	// Now member count is 2/3, so fill MAX_DEVICES=3 with live devices + open keys to test Redeem hitting device cap.
	e.addDevice(t, "owner1", "personal", "owner-lap", "100.64.0.10", "")
	e.addDevice(t, "alice", "personal", "alice-lap", "100.64.0.11", "")
	// 3rd slot taken by an open unused device key from alice.
	aAlice := Actor{Member: alice}
	if _, _, err := e.svc.IssueDeviceKey(ctx, aAlice, "alice", "personal"); err != nil {
		t.Fatalf("alice 3rd slot key failed: %v", err)
	}
	// 4th device key for non-owner must be refused (live=2 + open=1 == MAX_DEVICES=3).
	if _, _, err := e.svc.IssueDeviceKey(ctx, aAlice, "alice", "personal"); err == nil {
		t.Fatal("expected alice 4th device slot to hit MaxDevices")
	} else if p, ok := err.(*Problem); !ok || p.Status != http.StatusConflict {
		t.Fatalf("alice device cap err = %v, want 409", err)
	}
	// Redeem with member slot available (2/3) but device slots full (3/3) must return generic 409 and NOT create carol.
	rrDevFull := postRedeem(openInv.Token, "carol")
	if rrDevFull.Code != http.StatusConflict {
		t.Fatalf("valid invite at MaxDevices = %d %s, want 409", rrDevFull.Code, rrDevFull.Body.String())
	}
	if rrDevFull.Body.String() != rr.Body.String() {
		t.Fatalf("public /redeem body must be identical for member-cap vs device-cap: got %q vs %q", rrDevFull.Body.String(), rr.Body.String())
	}
	if _, err := e.st.MemberByHandle("carol"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("carol must not exist after device-cap redeem failure (err=%v)", err)
	}

	// 5. CLI AddMember bypasses MAX_MEMBERS (operator override).
	if _, err := e.svc.AddMember(ctx, cli, "dave", "member"); err != nil {
		t.Fatalf("CLI AddMember failed: %v", err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "erin", "member"); err != nil {
		t.Fatalf("CLI AddMember over MaxMembers should succeed: %v", err)
	}
}

func TestOwnerLockoutReserveAndCLIBypassAndGrandfatheringI30(t *testing.T) {
	e := newTestEnv(t)
	e.svc.cfg.MaxDevices = 2
	ctx := context.Background()
	cli := Actor{CLI: true}

	owner, err := e.svc.AddMember(ctx, cli, "owner1", "owner")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	aOwner := Actor{Member: owner}
	aAlice := Actor{Member: alice}

	// Fill MAX_DEVICES=2 with regular member devices.
	e.addDevice(t, "alice", "personal", "alice-1", "100.64.0.10", "")
	e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")

	// Non-owner and owner "server" device are BOTH blocked at MAX_DEVICES=2.
	if _, _, err := e.svc.IssueDeviceKey(ctx, aAlice, "alice", "personal"); err == nil {
		t.Fatal("expected alice personal key blocked at MaxDevices=2")
	}
	if _, _, err := e.svc.IssueDeviceKey(ctx, aOwner, "owner1", "server"); err == nil {
		t.Fatal("expected owner server key blocked at MaxDevices=2 (reserve is personal-only)")
	}

	// Owner personal device succeeds using D-16 reserve (+2 -> up to 4 total).
	for i := 1; i <= ownerDeviceReserve; i++ {
		keyStr, _, err := e.svc.IssueDeviceKey(ctx, aOwner, "owner1", "personal")
		if err != nil {
			t.Fatalf("owner personal reserve #%d failed: %v", i, err)
		}
		// Enroll it in fake Headscale and sync — must succeed using the same +2 reserve!
		keys, _ := e.st.PendingDeviceKeys(0)
		var hkID string
		for id := range keys {
			hkID = id
		}
		_ = keyStr
		e.hs.mu.Lock()
		e.hs.nodes = append(e.hs.nodes, HSNode{
			ID:          fmt.Sprintf("owner-node-%d", i),
			GivenName:   fmt.Sprintf("owner-phone-%d", i),
			User:        &HSUser{ID: owner.HSUserID, Name: owner.Handle},
			IPAddresses: []string{fmt.Sprintf("100.64.0.%d", 20+i)},
			PreAuthKey:  &HSPreAuthKey{ID: hkID},
			NodeKey:     testNodeKey(fmt.Sprintf("owner-res-%d", i)),
			MachineKey:  testMachineKey(fmt.Sprintf("owner-res-%d", i)),
		})
		e.hs.mu.Unlock()
		if err := e.svc.Sync(ctx); err != nil {
			t.Fatalf("sync for owner reserve #%d: %v", i, err)
		}
	}
	// Next owner personal device exceeds MaxDevices + ownerDeviceReserve (4/4) -> refused via portal.
	if _, _, err := e.svc.IssueDeviceKey(ctx, aOwner, "owner1", "personal"); err == nil {
		t.Fatal("expected owner personal key beyond +2 reserve to be refused via portal")
	}

	// Grandfathered pen (now 4 live devices > MaxDevices=2):
	// Existing devices keep syncing and updating IPs/names without disruption.
	e.hs.mu.Lock()
	for i := range e.hs.nodes {
		if e.hs.nodes[i].GivenName == "alice-1" {
			e.hs.nodes[i].GivenName = "alice-renamed"
		}
	}
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("sync on grandfathered over-cap pen failed: %v", err)
	}
	devs, _ := e.st.MemberDevices(alice.ID)
	foundRenamed := false
	for _, d := range devs {
		if d.Name == "alice-renamed" {
			foundRenamed = true
		}
	}
	if !foundRenamed {
		t.Fatal("existing device on grandfathered pen was not updated by Sync")
	}

	// CLI-issued device key sets bypass_cap=1 and enrolls even on an already over-cap pen.
	if _, _, err := e.svc.IssueDeviceKey(ctx, cli, "alice", "server"); err != nil {
		t.Fatalf("CLI IssueDeviceKey over cap failed: %v", err)
	}
	pending, _ := e.st.PendingDeviceKeys(0)
	var cliKeyID string
	for id, k := range pending {
		if k.BypassCap {
			cliKeyID = id
		}
	}
	if cliKeyID == "" {
		t.Fatal("expected CLI device key to persist bypass_cap=true")
	}
	e.hs.mu.Lock()
	e.hs.nodes = append(e.hs.nodes, HSNode{
		ID:          "cli-srv-node",
		GivenName:   "cli-srv",
		Tags:        []string{"tag:server"},
		IPAddresses: []string{"100.64.0.99"},
		PreAuthKey:  &HSPreAuthKey{ID: cliKeyID},
		NodeKey:     testNodeKey("cli-srv"),
		MachineKey:  testMachineKey("cli-srv"),
	})
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("sync for CLI bypass_cap key failed: %v", err)
	}
	if _, err := e.st.DeviceByHSNodeID("cli-srv-node"); err != nil {
		t.Fatalf("CLI bypass_cap node was not enrolled: %v", err)
	}
}

func TestSyncEnrollEnforcesDeviceCapAndNonAdminOpenKeyDefaultI30(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	// Default non-admin MaxOpenDeviceKeys is 3; admin/owner default is 10.
	if e.svc.cfg.MaxOpenDeviceKeys != 3 {
		t.Fatalf("default MaxOpenDeviceKeys = %d, want 3", e.svc.cfg.MaxOpenDeviceKeys)
	}
	if e.svc.cfg.MaxAdminOpenDeviceKeys != 10 {
		t.Fatalf("default MaxAdminOpenDeviceKeys = %d, want 10", e.svc.cfg.MaxAdminOpenDeviceKeys)
	}
	if e.svc.cfg.MaxMembers != 500 || e.svc.cfg.MaxDevices != 500 {
		t.Fatalf("default caps = (%d, %d), want (500, 500)", e.svc.cfg.MaxMembers, e.svc.cfg.MaxDevices)
	}

	owner, _ := e.svc.AddMember(ctx, cli, "owner1", "owner")
	alice, _ := e.svc.AddMember(ctx, cli, "alice", "member")
	aOwner := Actor{Member: owner}
	aAlice := Actor{Member: alice}

	// Regular member gets 3 open keys, 4th rejected.
	for i := 0; i < 3; i++ {
		if _, _, err := e.svc.IssueDeviceKey(ctx, aAlice, "alice", "personal"); err != nil {
			t.Fatalf("alice key #%d failed: %v", i+1, err)
		}
	}
	if _, _, err := e.svc.IssueDeviceKey(ctx, aAlice, "alice", "personal"); err == nil {
		t.Fatal("expected alice 4th open key to hit non-admin default cap of 3")
	}
	// Owner can hold >3 open keys (up to 10).
	for i := 0; i < 5; i++ {
		if _, _, err := e.svc.IssueDeviceKey(ctx, aOwner, "owner1", "server"); err != nil {
			t.Fatalf("owner server key #%d failed: %v", i+1, err)
		}
	}

	// Now lower MaxDevices to 1 AFTER alice already has open keys, enroll 1 live
	// device, and verify a second non-bypass key is rejected at syncOnce + deleted from Headscale.
	e.svc.cfg.MaxDevices = 1
	e.addDevice(t, "alice", "personal", "alice-1", "100.64.0.10", "")
	pending, _ := e.st.PendingDeviceKeys(0)
	var aliceKeyID string
	for id, k := range pending {
		if k.MemberID == alice.ID && !k.BypassCap {
			aliceKeyID = id
			break
		}
	}
	if aliceKeyID == "" {
		t.Fatal("expected an open non-bypass key for alice")
	}
	var deletedID string
	var delMu sync.Mutex
	e.hs.onDeleteNode = func(_ http.ResponseWriter, id string) bool {
		delMu.Lock()
		deletedID = id
		delMu.Unlock()
		return false
	}
	e.hs.mu.Lock()
	e.hs.nodes = append(e.hs.nodes, HSNode{
		ID:          "overcap-node",
		GivenName:   "overcap-laptop",
		User:        &HSUser{ID: alice.HSUserID, Name: alice.Handle},
		IPAddresses: []string{"100.64.0.44"},
		PreAuthKey:  &HSPreAuthKey{ID: aliceKeyID},
		NodeKey:     testNodeKey("overcap-node"),
		MachineKey:  testMachineKey("overcap-node"),
	})
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("Sync on over-cap enroll failed: %v", err)
	}
	if _, err := e.st.DeviceByHSNodeID("overcap-node"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("over-cap node must not be enrolled in SQLite (err=%v)", err)
	}
	delMu.Lock()
	gotDel := deletedID
	delMu.Unlock()
	if gotDel != "overcap-node" {
		t.Fatalf("expected syncOnce to delete over-cap stray node, got deleted=%q", gotDel)
	}
}

func TestSyncPendingDeleteVerifiesMachineKey1368(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	alice, _ := e.svc.AddMember(ctx, cli, "alice", "member")
	_, dev := e.addDevice(t, "alice", "personal", "alice-old", "100.64.0.10", "")

	// Commit self-delete cleanly (sets removed_at + hs_delete_pending = 1).
	if _, err := e.st.CommitSelfDelete(alice.ID, dev.ID, "alice"); err != nil {
		t.Fatalf("CommitSelfDelete: %v", err)
	}

	// Case 1: Headscale omits machineKey on that node -> fail closed (do NOT delete, keep pending).
	var hsDeletes atomic.Int32
	e.hs.onDeleteNode = func(_ http.ResponseWriter, _ string) bool {
		hsDeletes.Add(1)
		return false
	}
	e.hs.mu.Lock()
	var origMK string
	for i := range e.hs.nodes {
		if e.hs.nodes[i].ID == dev.HSNodeID {
			origMK = e.hs.nodes[i].MachineKey
			e.hs.nodes[i].MachineKey = ""
		}
	}
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("sync with missing machineKey: %v", err)
	}
	if hsDeletes.Load() != 0 {
		t.Fatalf("must not delete node when Headscale omits machineKey; got %d deletes", hsDeletes.Load())
	}
	if pending, _ := e.st.HasPendingDeviceDeletes(); !pending {
		t.Fatal("hs_delete_pending must remain true while machineKey is missing")
	}

	// Case 2: Headscale node ID was reused by a DIFFERENT machineKey -> skip delete, clear pending, preserve node!
	differentMK := testMachineKey("reused-node-id-different-machine")
	e.hs.mu.Lock()
	for i := range e.hs.nodes {
		if e.hs.nodes[i].ID == dev.HSNodeID {
			e.hs.nodes[i].MachineKey = differentMK
		}
	}
	e.hs.mu.Unlock()
	if origMK == differentMK {
		t.Fatal("test setup collision on machineKey")
	}
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("sync with mismatched machineKey: %v", err)
	}
	if hsDeletes.Load() != 0 {
		t.Fatalf("must NOT delete node with mismatched machineKey; got %d deletes", hsDeletes.Load())
	}
	if pending, _ := e.st.HasPendingDeviceDeletes(); pending {
		t.Fatal("hs_delete_pending should be cleared after machineKey mismatch skip")
	}

	// Case 3: Node already gone from Headscale -> clear pending with 0 DeleteNode calls.
	_, dev2 := e.addDevice(t, "alice", "personal", "alice-gone", "100.64.0.12", "")
	if _, err := e.st.CommitSelfDelete(alice.ID, dev2.ID, "alice"); err != nil {
		t.Fatalf("CommitSelfDelete dev2: %v", err)
	}
	e.hs.mu.Lock()
	filtered := e.hs.nodes[:0]
	for _, n := range e.hs.nodes {
		if n.ID != dev2.HSNodeID {
			filtered = append(filtered, n)
		}
	}
	e.hs.nodes = filtered
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("sync with already-gone node: %v", err)
	}
	if hsDeletes.Load() != 0 {
		t.Fatalf("already-gone node should not trigger DeleteNode RPC; got %d", hsDeletes.Load())
	}
	if pending, _ := e.st.HasPendingDeviceDeletes(); pending {
		t.Fatal("hs_delete_pending should clear when node is already absent from Headscale")
	}
}

func TestRedTeamRegressionsCapsSyncAndSelfDelete(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	owner, _ := e.svc.AddMember(ctx, cli, "owner1", "owner")
	alice, _ := e.svc.AddMember(ctx, cli, "alice", "member")
	bob, _ := e.svc.AddMember(ctx, cli, "bob", "member")
	aOwner := Actor{Member: owner}

	// 1. InsertMemberCapped checks handle uniqueness BEFORE cap (no false cap rollback on duplicate handle).
	if err := e.st.InsertMemberCapped(&Member{Handle: "alice", Role: "member", Status: "active", HSUserID: "u99"}, 1); err == nil || errors.Is(err, ErrMemberCapReached) {
		t.Fatalf("duplicate handle at cap = %v, want handle-taken conflict (not ErrMemberCapReached)", err)
	}

	// 2. EnrollDeviceCapped checks already-enrolled BEFORE cap so overlapping serve+CLI syncs
	//    at slot MAX_DEVICES return ErrDeviceAlreadyEnrolled instead of deleting the live node.
	_, d1 := e.addDevice(t, "alice", "personal", "alice-1", "100.64.0.10", "")
	if err := e.st.EnrollDeviceCapped(&Device{
		MemberID: alice.ID, Kind: "personal", HSNodeID: d1.HSNodeID, Name: "alice-1", IPv4: "100.64.0.10",
	}, 0, 1, 0); !errors.Is(err, ErrDeviceAlreadyEnrolled) {
		t.Fatalf("EnrollDeviceCapped for existing live node at cap = %v, want ErrDeviceAlreadyEnrolled", err)
	}

	// 3. syncOnce over-cap rejection REVOKES the key (leaving HasJoined=false) and retries
	//    DeleteNode on the next sync if pass 1 failed transiently!
	e.svc.cfg.MaxDevices = 1
	bobKey, _, err := e.svc.IssueDeviceKey(ctx, cli, "bob", "personal")
	if err != nil {
		t.Fatal(err)
	}
	_ = bobKey
	// Flip bypass_cap=0 on bob's key to simulate a pre-existing non-CLI key when cap became full.
	if _, err := e.st.db.Exec(`UPDATE device_keys SET bypass_cap = 0 WHERE member_id = ?`, bob.ID); err != nil {
		t.Fatal(err)
	}
	pending, _ := e.st.PendingDeviceKeys(0)
	var bobKeyID string
	for id, k := range pending {
		if k.MemberID == bob.ID {
			bobKeyID = id
		}
	}
	var failFirstDelete atomic.Bool
	failFirstDelete.Store(true)
	var deleteAttempts atomic.Int32
	e.hs.onDeleteNode = func(w http.ResponseWriter, id string) bool {
		if id == "bob-overcap" {
			deleteAttempts.Add(1)
			if failFirstDelete.Swap(false) {
				http.Error(w, "transient 503", http.StatusServiceUnavailable)
				return true
			}
		}
		return false
	}
	e.hs.mu.Lock()
	e.hs.nodes = append(e.hs.nodes, HSNode{
		ID:          "bob-overcap",
		GivenName:   "bob-lap",
		User:        &HSUser{ID: bob.HSUserID, Name: bob.Handle},
		IPAddresses: []string{"100.64.0.55"},
		PreAuthKey:  &HSPreAuthKey{ID: bobKeyID},
		NodeKey:     testNodeKey("bob-overcap"),
		MachineKey:  testMachineKey("bob-overcap"),
	})
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("sync pass 1: %v", err)
	}
	if joined, err := e.st.HasJoined(bob.ID); err != nil || joined {
		t.Fatalf("over-cap rejected device must leave HasJoined=false, got (%v, %v)", joined, err)
	}
	// Pass 2 must retry DeleteNode because key was revoked (not marked used).
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("sync pass 2: %v", err)
	}
	if deleteAttempts.Load() < 2 {
		t.Fatalf("expected transient over-cap DeleteNode to retry on pass 2; attempts=%d", deleteAttempts.Load())
	}
	e.hs.onDeleteNode = nil

	// 4. D-16 per-owner floor on a grandfathered pen well above MaxDevices + 2,
	//    plus addDeviceReserve(math.MaxInt) overflow guard.
	if addDeviceReserve(math.MaxInt) != math.MaxInt {
		t.Fatalf("addDeviceReserve(MaxInt) overflowed: %d", addDeviceReserve(math.MaxInt))
	}
	e.addDevice(t, "alice", "server", "alice-s1", "100.64.0.11", "")
	e.addDevice(t, "alice", "server", "alice-s2", "100.64.0.12", "")
	e.addDevice(t, "alice", "server", "alice-s3", "100.64.0.13", "")
	// Now 4 live devices vs MaxDevices=1 (> MaxDevices+2=3), owner1 has 0 personal devices:
	// owner1 must still be able to add up to ownerDeviceReserve (2) personal devices!
	if _, _, err := e.svc.IssueDeviceKey(ctx, aOwner, "owner1", "personal"); err != nil {
		t.Fatalf("owner personal key #1 on grandfathered pen must succeed: %v", err)
	}
	if _, _, err := e.svc.IssueDeviceKey(ctx, aOwner, "owner1", "personal"); err != nil {
		t.Fatalf("owner personal key #2 on grandfathered pen must succeed: %v", err)
	}
	if _, _, err := e.svc.IssueDeviceKey(ctx, aOwner, "owner1", "personal"); err == nil {
		t.Fatal("owner personal key #3 on grandfathered pen should hit floor cap")
	}

	// 5. finishSelfDelete verifies machineKey + hs_delete_pending and NEVER deletes a reused node ID.
	_, dSelf := e.addDevice(t, "alice", "personal", "alice-self", "100.64.0.70", "")
	if _, err := e.st.CommitSelfDelete(alice.ID, dSelf.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	e.hs.mu.Lock()
	for i := range e.hs.nodes {
		if e.hs.nodes[i].ID == dSelf.HSNodeID {
			e.hs.nodes[i].MachineKey = testMachineKey("reused-in-finishSelfDelete")
		}
	}
	e.hs.mu.Unlock()
	var finishDeletes atomic.Int32
	e.hs.onDeleteNode = func(_ http.ResponseWriter, id string) bool {
		if id == dSelf.HSNodeID {
			finishDeletes.Add(1)
		}
		return false
	}
	e.svc.finishSelfDelete(dSelf.ID, dSelf.HSNodeID)
	if finishDeletes.Load() != 0 {
		t.Fatalf("finishSelfDelete deleted node despite machineKey mismatch (%d calls)", finishDeletes.Load())
	}
	if pending, _ := e.st.DeviceHSDeletePending(dSelf.ID); pending {
		t.Fatal("finishSelfDelete should clear hs_delete_pending on machineKey mismatch")
	}
	e.hs.onDeleteNode = nil

	// 6. Deferred pending delete (missing Headscale machineKey) must NOT pin NeedsFastSync to permanent true!
	//    Also expire open keys first so NeedsFastSync isolates pendingDel.
	_, _ = e.st.db.Exec(`UPDATE device_keys SET revoked_at = 1 WHERE revoked_at IS NULL AND used_at IS NULL`)
	_, dDef := e.addDevice(t, "alice", "personal", "alice-def", "100.64.0.71", "")
	if _, err := e.st.CommitSelfDelete(alice.ID, dDef.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	e.hs.mu.Lock()
	for i := range e.hs.nodes {
		if e.hs.nodes[i].ID == dDef.HSNodeID {
			e.hs.nodes[i].MachineKey = ""
		}
	}
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if e.svc.NeedsFastSync() {
		t.Fatal("deferred pending delete must not pin NeedsFastSync() to 3s loop")
	}

	// 7. releaseLeafNamesOfDevice retires private=1 random site names (D-21) instead of hard-deleting them.
	_, dPriv := e.addDevice(t, "alice", "server", "alice-priv-srv", "100.64.0.72", "")
	if _, err := e.st.db.Exec(`INSERT INTO names (name, member_id, device_id, note, private, created_at) VALUES ('priv-rand-abc', ?, ?, 'secret', 1, ?)`, alice.ID, dPriv.ID, now()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CommitSelfDelete(alice.ID, dPriv.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	var heldUntil *int64
	var devID *int64
	if err := e.st.db.QueryRow(`SELECT device_id, held_until FROM names WHERE name = 'priv-rand-abc'`).Scan(&devID, &heldUntil); err != nil {
		t.Fatalf("private name row must remain retired (not hard-deleted) on device removal: %v", err)
	}
	if devID != nil || heldUntil == nil {
		t.Fatalf("private name must be unpointed and retired (held_until != nil), got device_id=%v held_until=%v", devID, heldUntil)
	}
}
