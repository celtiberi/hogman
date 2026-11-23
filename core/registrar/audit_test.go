package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type auditStubACME struct {
	txtCalls int
	eabCalls int
}

func (f *auditStubACME) SetTXT(ctx context.Context, fqdn, value string) error {
	f.txtCalls++
	return nil
}

func (f *auditStubACME) DeleteTXT(ctx context.Context, fqdn, value string) error {
	return nil
}

func (f *auditStubACME) MintEAB(ctx context.Context) (*EABPair, error) {
	f.eabCalls++
	return &EABPair{KID: "kid-1", HMACB64URL: "hmac-1", Contact: "ops@example.com"}, nil
}

func TestAuditSubdomainHijackPrevented(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := e.svc.AddMember(ctx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}

	// Enroll two servers for alice and one for bob.
	s1 := &Device{MemberID: alice.ID, Kind: "server", HSNodeID: "hs-s1", Name: "srv1", IPv4: "100.64.0.10"}
	s2 := &Device{MemberID: alice.ID, Kind: "server", HSNodeID: "hs-s2", Name: "srv2", IPv4: "100.64.0.11"}
	b1 := &Device{MemberID: bob.ID, Kind: "server", HSNodeID: "hs-b1", Name: "bsrv", IPv4: "100.64.0.12"}
	for _, d := range []*Device{s1, s2, b1} {
		if err := e.st.InsertDevice(d); err != nil {
			t.Fatal(err)
		}
		e.hs.mu.Lock()
		e.hs.nodes = append(e.hs.nodes, HSNode{ID: d.HSNodeID, Name: d.Name, IPAddresses: []string{d.IPv4}})
		e.hs.mu.Unlock()
	}

	if _, err := e.svc.Claim(Actor{Member: alice}, "alice", "corp", s1.ID, nil); err != nil {
		t.Fatalf("alice claim corp: %v", err)
	}
	if _, err := e.svc.Claim(Actor{Member: alice}, "alice", "auth.corp", s2.ID, nil); err != nil {
		t.Fatalf("alice claim auth.corp: %v", err)
	}

	// Removing s1 must unpoint corp (preserving alice's ownership) while auth.corp stays on s2.
	if err := e.svc.RemoveDevice(ctx, Actor{Member: alice}, s1.ID); err != nil {
		t.Fatalf("remove s1: %v", err)
	}
	corpRow, err := e.st.NameByName("corp")
	if err != nil {
		t.Fatalf("corp should still exist while auth.corp is active: %v", err)
	}
	if corpRow.MemberID != alice.ID || corpRow.DeviceID != nil {
		t.Fatalf("corp = %+v, want MemberID=%d DeviceID=nil", corpRow, alice.ID)
	}

	// Bob must not be able to claim corp.
	if _, err := e.svc.Claim(Actor{Member: bob}, "bob", "corp", b1.ID, nil); err == nil {
		t.Fatal("bob claimed alice's unpointed parent corp")
	}

	// Defense in depth: even if corp were deleted directly, bob still cannot claim corp while alice owns auth.corp.
	if err := e.st.DeleteName("corp"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(Actor{Member: bob}, "bob", "corp", b1.ID, nil); err == nil {
		t.Fatal("bob claimed orphaned parent corp while alice owns auth.corp")
	}

	// Defense in depth: even if bob somehow owned corp while alice owned auth.corp, releaseLocked must refuse deleting alice's child.
	if err := e.st.UpsertName("corp", bob.ID, &b1.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Release(Actor{Member: bob}, "corp"); err == nil {
		t.Fatal("bob released corp despite alice owning auth.corp")
	}
	if _, err := e.st.NameByName("auth.corp"); err != nil {
		t.Fatalf("alice's auth.corp was deleted: %v", err)
	}
}

func TestAuditLifecycleLockOrderAndNoResurrection(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	_, err := e.svc.AddMember(ctx, cli, "owner1", "owner")
	if err != nil {
		t.Fatal(err)
	}
	adm, err := e.svc.AddMember(ctx, cli, "adm1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := e.svc.AddMember(ctx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Kicked member cannot be resurrected via SetMemberStatus.
	if _, err := e.svc.Kick(ctx, cli, "bob", "bye"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetMemberStatus(bob.ID, "active"); err == nil {
		t.Fatal("SetMemberStatus resurrected a removed member")
	}
	if err := e.st.SetMemberStatus(bob.ID, "suspended"); err == nil {
		t.Fatal("SetMemberStatus transitioned a removed member to suspended")
	}

	// 2. Stale admin Actor snapshot is rejected after demotion in SQLite.
	staleAdminActor := Actor{Member: &Member{ID: adm.ID, Handle: adm.Handle, Role: "admin", Status: "active"}}
	if err := e.svc.SetRole(cli, "adm1", "member"); err != nil {
		t.Fatal(err)
	}
	carol, err := e.svc.AddMember(ctx, cli, "carol", "member")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Suspend(ctx, staleAdminActor, "carol", "stale"); err == nil {
		t.Fatal("demoted admin succeeded with stale Actor in Suspend")
	}
	if _, err := e.svc.MintInvite(staleAdminActor, "member", "stale", time.Hour); err == nil {
		t.Fatal("demoted admin succeeded with stale Actor in MintInvite")
	}

	// 3. Suspended member cannot enroll a device via Sync even with an unrevoked key.
	if err := e.svc.Suspend(ctx, cli, "carol", "pause"); err != nil {
		t.Fatal(err)
	}
	// Simulate a racing key inserted just before revocation finished.
	dk := &DeviceKey{MemberID: carol.ID, Kind: "personal", HSKeyID: "k-race", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if err := e.st.InsertDeviceKey(dk); err != nil {
		t.Fatal(err)
	}
	e.hs.mu.Lock()
	e.hs.nodes = append(e.hs.nodes, HSNode{
		ID:          "node-race",
		Name:        "carol-laptop",
		IPAddresses: []string{"100.64.0.77"},
		PreAuthKey:  &HSPreAuthKey{ID: "k-race"},
	})
	e.hs.mu.Unlock()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	e.hs.mu.Lock()
	stillPresent := false
	for _, n := range e.hs.nodes {
		if n.ID == "node-race" {
			stillPresent = true
		}
	}
	e.hs.mu.Unlock()
	if stillPresent {
		t.Fatal("Sync enrolled a node for a suspended member instead of deleting it")
	}
	if devs, _ := e.st.MemberDevices(carol.ID); len(devs) != 0 {
		t.Fatalf("suspended carol has %d devices, want 0", len(devs))
	}
}

func TestAuditACMERateLimitAndAuditActor(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	stub := &auditStubACME{}
	e.svc.acme = stub
	e.svc.cfg.MaxServerEABPerDay = 2
	e.svc.cfg.MaxMemberEABPerDay = 3
	e.svc.cfg.MaxMemberACMETXTPerHour = 2

	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	// Client-controlled device name tries to spoof "owner@cli".
	s1 := &Device{MemberID: alice.ID, Member: alice.Handle, Kind: "server", HSNodeID: "hs-1", Name: "owner@cli", IPv4: "100.64.0.20"}
	s2 := &Device{MemberID: alice.ID, Member: alice.Handle, Kind: "server", HSNodeID: "hs-2", Name: "srv2", IPv4: "100.64.0.21"}
	for _, d := range []*Device{s1, s2} {
		if err := e.st.InsertDevice(d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.Claim(Actor{Member: alice}, "alice", "app1", s1.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(Actor{Member: alice}, "alice", "app2", s2.ID, nil); err != nil {
		t.Fatal(err)
	}

	// Server cap = 2/day: 3rd call on s1 fails with 429 and does not reach challenge-dns.
	for i := 0; i < 2; i++ {
		if _, err := e.svc.ServerMintACMEEAB(ctx, s1); err != nil {
			t.Fatalf("s1 EAB #%d: %v", i+1, err)
		}
	}
	_, err = e.svc.ServerMintACMEEAB(ctx, s1)
	var prob *Problem
	if !errors.As(err, &prob) || prob.Status != 429 || prob.RetryAfter < 1 {
		t.Fatalf("3rd s1 EAB = %v, want 429 with RetryAfter", err)
	}
	if stub.eabCalls != 2 {
		t.Fatalf("eabCalls = %d, want 2", stub.eabCalls)
	}

	// Member cap = 3/day across s1+s2: 1st call on s2 succeeds (total 3), 2nd on s2 fails 429.
	if _, err := e.svc.ServerMintACMEEAB(ctx, s2); err != nil {
		t.Fatalf("s2 EAB #1: %v", err)
	}
	_, err = e.svc.ServerMintACMEEAB(ctx, s2)
	if !errors.As(err, &prob) || prob.Status != 429 {
		t.Fatalf("4th member EAB = %v, want 429", err)
	}

	// Audit log must record member handle "alice", never spoofed device name "owner@cli".
	entries, err := e.st.AuditLog(20)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Action == "acme.eab" && entry.Actor != "alice" {
			t.Fatalf("acme.eab audit actor = %q, want %q", entry.Actor, "alice")
		}
	}

	// Per-member TXT write cap = 2/hr.
	val := "abcdefghijklmnopqrstuvwxyz012345"
	for i := 0; i < 2; i++ {
		if _, err := e.svc.ServerSetACMETXT(ctx, s1, "app1", val); err != nil {
			t.Fatalf("SetACMETXT #%d: %v", i+1, err)
		}
	}
	_, err = e.svc.ServerSetACMETXT(ctx, s1, "app1", val)
	if !errors.As(err, &prob) || prob.Status != 429 {
		t.Fatalf("3rd SetACMETXT = %v, want 429", err)
	}
}

func TestAuditCrossOriginGETBlockedAndSanitization(t *testing.T) {
	e := newTestEnv(t)
	h := MeshHandler(e.svc)

	// Cross-origin and same-site GETs must be rejected with 403 before identify() even checks XFF.
	for _, sfs := range []string{"cross-site", "same-site"} {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Sec-Fetch-Site", sfs)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), "cross-origin") {
			t.Fatalf("GET /api/me Sec-Fetch-Site=%s: %d %s, want 403 cross-origin", sfs, rec.Code, rec.Body.String())
		}
	}

	// Invite notes must drop ANSI ESC / control chars.
	inv, err := e.svc.MintInvite(Actor{CLI: true}, "member", "for\x1b[31m alice\x00\t\nline2", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(inv.Note, "\x1b\x00\t\r\n") {
		t.Fatalf("unsanitized invite note: %q", inv.Note)
	}

	// normaliseName must reject ns[0-9]* labels (ns1, sub.ns2).
	for _, badName := range []string{"ns1", "sub.ns2", "ns0"} {
		if _, err := e.svc.normaliseName(badName); err == nil {
			t.Fatalf("normaliseName(%q) succeeded, want forbidden", badName)
		}
	}
}

func TestAuditKickAndSyncClearHSUserIDWithoutRetryLoop(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "owner", "owner"); err != nil {
		t.Fatal(err)
	}
	bob, err := e.svc.AddMember(ctx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Kick(ctx, cli, "bob", "bye"); err != nil {
		t.Fatalf("Kick bob: %v", err)
	}
	e.hs.mu.Lock()
	afterKick := e.hs.deleteUserCalls
	e.hs.mu.Unlock()
	if afterKick != 1 {
		t.Fatalf("deleteUserCalls after Kick = %d, want 1", afterKick)
	}

	// Five subsequent Syncs (and a restarted Service) must make zero extra DeleteUser calls.
	for i := 0; i < 5; i++ {
		if err := e.svc.Sync(ctx); err != nil {
			t.Fatalf("Sync %d: %v", i, err)
		}
	}
	svc2, err := NewService(e.svc.cfg, e.st, e.svc.hs)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc2.Sync(ctx); err != nil {
		t.Fatalf("restarted Sync: %v", err)
	}
	e.hs.mu.Lock()
	afterSyncs := e.hs.deleteUserCalls
	e.hs.mu.Unlock()
	if afterSyncs != 1 {
		t.Fatalf("deleteUserCalls after 5 Syncs + restart = %d, want 1", afterSyncs)
	}

	// Simulate an upgraded DB where a previously removed member still has a stale
	// hs_user_id whose Headscale user is already gone (404): first Sync clears it,
	// subsequent Syncs make zero further calls.
	if _, err := e.st.db.Exec(`UPDATE members SET hs_user_id = '99999' WHERE id = ?`, bob.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc2.Sync(ctx); err != nil {
		t.Fatalf("Sync stale 404: %v", err)
	}
	if err := svc2.Sync(ctx); err != nil {
		t.Fatalf("Sync after clear: %v", err)
	}
	e.hs.mu.Lock()
	finalCalls := e.hs.deleteUserCalls
	e.hs.mu.Unlock()
	if finalCalls != 2 {
		t.Fatalf("deleteUserCalls after 404 clear + follow-up Sync = %d, want 2", finalCalls)
	}
}
