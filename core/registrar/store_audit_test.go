package main

import (
	"path/filepath"
	"testing"
)

func TestStoreTransactionalAuditAtomicity(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// 1. InsertMemberCappedAudited commits member + audit atomically; failure writes zero audit rows.
	owner := &Member{Handle: "alice", Role: "owner", Status: "active", HSUserID: "u1"}
	if err := st.InsertMemberCappedAudited(owner, 1, &AuditRecord{
		Actor: "owner@cli", Action: "member.add", Target: "alice", Detail: "role=owner",
	}); err != nil {
		t.Fatal(err)
	}
	// Duplicate handle fails and must NOT append an audit entry.
	dup := &Member{Handle: "alice", Role: "member", Status: "active", HSUserID: "u2"}
	if err := st.InsertMemberCappedAudited(dup, 10, &AuditRecord{
		Actor: "owner@cli", Action: "member.add", Target: "alice", Detail: "role=member",
	}); err == nil {
		t.Fatal("expected duplicate handle error")
	}
	entries, err := st.AuditLog(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "member.add" {
		t.Fatalf("expected 1 audit entry after failed duplicate insert, got %+v", entries)
	}

	// 2. DemoteOwnerAudited on sole owner returns false and writes zero audit entries.
	demoted, err := st.DemoteOwnerAudited(owner.ID, "admin", true, AuditRecord{
		Actor: "owner@cli", Action: "member.role", Target: "alice", Detail: "owner -> admin",
	})
	if err != nil || demoted {
		t.Fatalf("sole-owner DemoteOwnerAudited = (%v, %v), want (false, nil)", demoted, err)
	}
	entries, err = st.AuditLog(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("failed DemoteOwnerAudited should not write audit row, got %d entries", len(entries))
	}

	// 3. UpsertNameWithPrivateAudited on retired name fails and writes zero audit entries.
	dev := &Device{MemberID: owner.ID, Kind: "server", HSNodeID: "n1", Name: "srv", IPv4: "100.64.0.10"}
	if err := st.InsertDevice(dev); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNameWithPrivateAudited("blog", owner.ID, &dev.ID, "first", false, &AuditRecord{
		Actor: "alice", Action: "name.claim", Target: "blog.bobo.hogman", Detail: "member=alice",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RetireName("blog"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNameWithPrivateAudited("blog", owner.ID, &dev.ID, "retry", false, &AuditRecord{
		Actor: "alice", Action: "name.claim", Target: "blog.bobo.hogman", Detail: "should-not-write",
	}); err == nil {
		t.Fatal("expected retired name upsert to fail")
	}
	entries, err = st.AuditLog(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("retired name failure should not write audit row, got %d entries", len(entries))
	}

	// 4. CommitDeviceRemoval atomically releases leaf names, removes device, and audits.
	if err := st.UpsertName("site", owner.ID, &dev.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CommitDeviceRemoval(dev.ID, AuditRecord{
		Actor: "alice", Action: "device.remove", Target: "alice/srv#1",
	}); err != nil {
		t.Fatal(err)
	}
	gotDev, err := st.DeviceByID(dev.ID)
	if err != nil || gotDev.RemovedAt == nil {
		t.Fatalf("device should be marked removed, got (%+v, %v)", gotDev, err)
	}
	if _, err := st.NameByName("site"); err != ErrNotFound {
		t.Fatalf("leaf name should be released on CommitDeviceRemoval, got err=%v", err)
	}
	entries, err = st.AuditLog(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].Action != "device.remove" {
		t.Fatalf("expected device.remove audit entry at head, got %+v", entries)
	}
}
