package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type fakeHeadscale struct {
	mu            sync.Mutex
	nextUserID    int
	nextKeyID     int
	users         map[string]HSUser
	keys          map[string]HSPreAuthKey
	nodes         []HSNode
	policy        string
	failCreateKey bool
	srv           *httptest.Server
}

func newFakeHeadscale(t *testing.T) *fakeHeadscale {
	t.Helper()
	f := &fakeHeadscale{
		users: map[string]HSUser{},
		keys:  map[string]HSPreAuthKey{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		name := r.URL.Query().Get("name")
		var out []HSUser
		for _, u := range f.users {
			if name == "" || u.Name == name {
				out = append(out, u)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"users": out})
	})
	mux.HandleFunc("POST /api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Name string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.nextUserID++
		u := HSUser{ID: strconv.Itoa(f.nextUserID), Name: in.Name}
		f.users[u.ID] = u
		_ = json.NewEncoder(w).Encode(map[string]any{"user": u})
	})
	mux.HandleFunc("DELETE /api/v1/user/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.users, r.PathValue("id"))
		w.WriteHeader(200)
	})
	mux.HandleFunc("POST /api/v1/preauthkey", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failCreateKey {
			http.Error(w, "headscale down", http.StatusServiceUnavailable)
			return
		}
		var in struct {
			ACLTags []string `json:"aclTags"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.nextKeyID++
		id := strconv.Itoa(f.nextKeyID)
		k := HSPreAuthKey{ID: id, Key: "hskey-test-" + id, ACLTags: in.ACLTags}
		f.keys[id] = k
		_ = json.NewEncoder(w).Encode(map[string]any{"preAuthKey": k})
	})
	mux.HandleFunc("POST /api/v1/preauthkey/expire", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	mux.HandleFunc("GET /api/v1/node", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"nodes": f.nodes})
	})
	mux.HandleFunc("DELETE /api/v1/node/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := r.PathValue("id")
		kept := f.nodes[:0]
		for _, n := range f.nodes {
			if n.ID != id {
				kept = append(kept, n)
			}
		}
		f.nodes = kept
		w.WriteHeader(200)
	})
	mux.HandleFunc("GET /api/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"policy": f.policy})
	})
	mux.HandleFunc("PUT /api/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Policy string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.policy = in.Policy
		f.mu.Unlock()
		w.WriteHeader(200)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHeadscale) userExists(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.users[id]
	return ok
}

type testEnv struct {
	svc *Service
	st  *Store
	hs  *fakeHeadscale
	dir string
}

func writeTestRootCA(t *testing.T, path string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bobo.hogman Root CA"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root_ca.crt")
	writeTestRootCA(t, rootPath)
	st, err := OpenStore(filepath.Join(dir, "registrar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.db.Close() })
	hs := newFakeHeadscale(t)
	cfg := Config{
		Zone:         "bobo.hogman",
		PublicHost:   "hs.example.com",
		CoreIP:       "100.64.0.1",
		CAIP:         "100.64.0.2",
		RootCAFile:   rootPath,
		NameHold:     90 * 24 * time.Hour,
		InviteTTL:    7 * 24 * time.Hour,
		DeviceKeyTTL: time.Hour,
	}
	svc, err := NewService(cfg, st, NewHeadscale(hs.srv.URL, "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{svc: svc, st: st, hs: hs, dir: dir}
}

func (e *testEnv) addDevice(t *testing.T, handle, kind, name, ipv4, ipv6 string) (*Member, *Device) {
	t.Helper()
	m, err := e.st.MemberByHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	d := &Device{
		MemberID: m.ID,
		Kind:     kind,
		HSNodeID: fmt.Sprintf("node-%d-%s", m.ID, name),
		Name:     name,
		IPv4:     ipv4,
		IPv6:     ipv6,
	}
	if err := e.st.InsertDevice(d); err != nil {
		t.Fatal(err)
	}
	var ips []string
	if ipv4 != "" {
		ips = append(ips, ipv4)
	}
	if ipv6 != "" {
		ips = append(ips, ipv6)
	}
	e.hs.mu.Lock()
	e.hs.nodes = append(e.hs.nodes, HSNode{
		ID:          d.HSNodeID,
		Name:        name,
		GivenName:   name,
		IPAddresses: ips,
	})
	e.hs.mu.Unlock()
	return m, d
}

func TestRedeemRollbackOnPreAuthKeyFailure(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	inv, err := e.svc.MintInvite(cli, "member", "alice invite", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	e.hs.mu.Lock()
	e.hs.failCreateKey = true
	e.hs.mu.Unlock()

	if _, err := e.svc.Redeem(ctx, inv.Token, "alice"); err == nil {
		t.Fatal("expected Redeem to fail when Headscale key creation fails")
	}

	gotInv, err := e.st.InviteByID(inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotInv.State() != "open" {
		t.Fatalf("invite state = %q, want open after rollback", gotInv.State())
	}
	if _, err := e.st.MemberByHandle("alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("member alice should have been rolled back, got err=%v", err)
	}
	if e.hs.userExists("1") {
		t.Fatal("Headscale user 1 should have been deleted on rollback")
	}

	e.hs.mu.Lock()
	e.hs.failCreateKey = false
	e.hs.mu.Unlock()

	enr, err := e.svc.Redeem(ctx, inv.Token, "alice")
	if err != nil {
		t.Fatalf("retry Redeem after Headscale recovery failed: %v", err)
	}
	if enr.Handle != "alice" || enr.AuthKey == "" {
		t.Fatalf("unexpected enrolment: %+v", enr)
	}
}

func TestRedeemRejectsSuspendedMinter(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	alice, err := e.svc.AddMember(ctx, cli, "alice", "admin")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := e.svc.MintInvite(Actor{Member: alice}, "member", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Suspend(ctx, cli, "alice", "timeout"); err != nil {
		t.Fatal(err)
	}

	_, err = e.svc.Redeem(ctx, inv.Token, "bob")
	var prob *Problem
	if !errors.As(err, &prob) || prob.Status != 403 {
		t.Fatalf("want 403 forbidden for suspended minter, got %v", err)
	}
	gotInv, _ := e.st.InviteByID(inv.ID)
	if gotInv.State() != "open" {
		t.Fatalf("invite state = %q, want open", gotInv.State())
	}
}

func TestClaimOwnerSeizeAndConcurrency(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	owner, err := e.svc.AddMember(ctx, cli, "root", "owner")
	if err != nil {
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
	_, ownerSrv := e.addDevice(t, "root", "server", "root-srv", "100.64.0.10", "")
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")
	_, bobSrv := e.addDevice(t, "bob", "server", "bob-srv", "100.64.0.12", "")

	if _, err := e.svc.Claim(Actor{Member: alice}, "alice", "alice", aliceSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(Actor{Member: bob}, "bob", "alice", bobSrv.ID, nil); err == nil {
		t.Fatal("bob should not be able to claim alice's name")
	}

	if _, err := e.svc.Claim(cli, "root", "alice", ownerSrv.ID, nil); err != nil {
		t.Fatalf("owner should be able to seize active name: %v", err)
	}
	n, err := e.st.NameByName("alice")
	if err != nil || n.MemberID != owner.ID || n.DeviceID == nil || *n.DeviceID != ownerSrv.ID {
		t.Fatalf("expected name alice to belong to root server, got %+v (err=%v)", n, err)
	}

	// Concurrent claims for the same unclaimed name: exactly one succeeds, one gets 409.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := e.svc.Claim(Actor{Member: alice}, "alice", "contested", aliceSrv.ID, nil)
		errs <- err
	}()
	go func() {
		defer wg.Done()
		_, err := e.svc.Claim(Actor{Member: bob}, "bob", "contested", bobSrv.ID, nil)
		errs <- err
	}()
	wg.Wait()
	close(errs)

	var successes, conflicts int
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		var prob *Problem
		if errors.As(err, &prob) && prob.Status == 409 {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent claim error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("want 1 success and 1 conflict, got successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestResolvableNameIPv6AndConcurrency(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, srv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.20", "fd7a:115c:a1e0::20")
	if _, err := e.svc.Claim(Actor{Member: alice}, "alice", "alice", srv.ID, nil); err != nil {
		t.Fatal(err)
	}

	got, err := e.st.ResolvableName("alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.IPv4 != "100.64.0.20" || got.IPv6 != "fd7a:115c:a1e0::20" {
		t.Fatalf("got v4=%q v6=%q", got.IPv4, got.IPv6)
	}

	// Simulate concurrent readers (DNS queries across separate store handles) alongside claims.
	dbPath := filepath.Join(e.dir, "registrar.db")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st2, err := OpenStore(dbPath)
			if err != nil {
				errs <- err
				return
			}
			defer st2.db.Close()
			if i%2 == 0 {
				if _, err := st2.ResolvableName("alice"); err != nil {
					errs <- err
					return
				}
			} else {
				if _, err := st2.HasResolvableChild("alice"); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent store DNS query failed: %v", err)
		}
	}
}

func TestRBACAdminRestrictions(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	owner, err := e.svc.AddMember(ctx, cli, "root", "owner")
	if err != nil {
		t.Fatal(err)
	}
	admin1, err := e.svc.AddMember(ctx, cli, "alice", "admin")
	if err != nil {
		t.Fatal(err)
	}
	admin2, err := e.svc.AddMember(ctx, cli, "carol", "admin")
	if err != nil {
		t.Fatal(err)
	}
	member1, err := e.svc.AddMember(ctx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, ownerSrv := e.addDevice(t, "root", "server", "root-srv", "100.64.0.10", "")
	_, admin2Dev := e.addDevice(t, "carol", "personal", "carol-laptop", "100.64.0.11", "")
	_, admin2Srv := e.addDevice(t, "carol", "server", "carol-srv", "100.64.0.12", "")
	_, memberDev := e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.13", "")
	_, memberSrv := e.addDevice(t, "bob", "server", "bob-srv", "100.64.0.14", "")

	if _, err := e.svc.Claim(Actor{Member: owner}, "root", "root-site", ownerSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(Actor{Member: admin2}, "carol", "carol-site", admin2Srv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(Actor{Member: member1}, "bob", "bob-site", memberSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	// Kick a member to put a held name in place.
	_, err = e.svc.AddMember(ctx, cli, "gary", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, garySrv := e.addDevice(t, "gary", "server", "gary-srv", "100.64.0.15", "")
	if _, err := e.svc.Claim(cli, "gary", "gary-site", garySrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Kick(ctx, cli, "gary", "bad pig"); err != nil {
		t.Fatal(err)
	}

	a1 := Actor{Member: admin1}

	// Admin cannot remove another admin's or owner's device, but can remove a member's device.
	for _, devID := range []int64{ownerSrv.ID, admin2Dev.ID} {
		err := e.svc.RemoveDevice(ctx, a1, devID)
		var prob *Problem
		if !errors.As(err, &prob) || prob.Status != 403 {
			t.Fatalf("admin RemoveDevice(%d): got %v, want 403", devID, err)
		}
	}
	if err := e.svc.RemoveDevice(ctx, a1, memberDev.ID); err != nil {
		t.Fatalf("admin RemoveDevice(memberDev): %v", err)
	}

	// Admin cannot release owner's name, another admin's name, or a held name.
	for _, name := range []string{"root-site", "carol-site", "gary-site"} {
		err := e.svc.Release(a1, name)
		var prob *Problem
		if !errors.As(err, &prob) || prob.Status != 403 {
			t.Fatalf("admin Release(%q): got %v, want 403", name, err)
		}
	}
	// Admin can release a regular member's active name, and owner can release held names.
	if err := e.svc.Release(a1, "bob-site"); err != nil {
		t.Fatalf("admin Release(bob-site): %v", err)
	}
	if err := e.svc.Release(Actor{Member: owner}, "gary-site"); err != nil {
		t.Fatalf("owner Release(gary-site): %v", err)
	}

	// Admin cannot issue device keys or claim names for owner or another admin.
	for _, target := range []string{"root", "carol"} {
		_, _, err := e.svc.IssueDeviceKey(ctx, a1, target, "personal")
		var prob *Problem
		if !errors.As(err, &prob) || prob.Status != 403 {
			t.Fatalf("admin IssueDeviceKey(%s): got %v, want 403", target, err)
		}
	}
	if _, err := e.svc.Claim(a1, "carol", "hijack", admin2Srv.ID, nil); err == nil {
		t.Fatal("admin should not claim names for another admin")
	}
}

func TestClaimSeizeCleansUpChildSubdomains(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "root", "owner"); err != nil {
		t.Fatal(err)
	}
	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, rootSrv := e.addDevice(t, "root", "server", "root-srv", "100.64.0.10", "")
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")

	if _, err := e.svc.Claim(Actor{Member: alice}, "alice", "alice", aliceSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(Actor{Member: alice}, "alice", "blog.alice", aliceSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(cli, "root", "alice", rootSrv.ID, nil); err != nil {
		t.Fatalf("owner seize failed: %v", err)
	}
	if _, err := e.st.NameByName("blog.alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("child name blog.alice should be deleted on parent seize, got err=%v", err)
	}
	dnsSrv, err := NewDNSServer(e.svc)
	if err != nil {
		t.Fatal(err)
	}
	if got := mustResolveA(t, dnsSrv, "alice.bobo.hogman."); got != "100.64.0.10" {
		t.Fatalf("alice = %q want 100.64.0.10", got)
	}
	resp, _ := dnsSrv.HandlePacket(buildDNSQuery(t, 1, "blog.alice.bobo.hogman.", dnsmessage.TypeA, false, 0), false)
	hdr, _, _, _ := parseDNSResp(t, resp)
	if hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("blog.alice still resolves after seize: rcode=%v", hdr.RCode)
	}
}

func TestQuotasAndSuspendExpiresKeys(t *testing.T) {
	e := newTestEnv(t)
	e.svc.cfg.MaxOpenDeviceKeys = 2
	e.svc.cfg.MaxNamesPerMember = 2
	e.svc.cfg.MaxOpenInvites = 2
	e.svc.cfg.MaxInviteNoteLen = 16
	e.svc.cfg.MembersCanInvite = true

	ctx := context.Background()
	cli := Actor{CLI: true}
	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")
	aAlice := Actor{Member: alice}

	// Open device key quota + PendingDeviceKeys filtering.
	for i := 0; i < 2; i++ {
		if _, _, err := e.svc.IssueDeviceKey(ctx, aAlice, "alice", "personal"); err != nil {
			t.Fatalf("IssueDeviceKey #%d: %v", i, err)
		}
	}
	if _, _, err := e.svc.IssueDeviceKey(ctx, aAlice, "alice", "personal"); err == nil {
		t.Fatal("expected 3rd open device key to hit quota")
	}

	// Suspend expires & revokes open device keys.
	if err := e.svc.Suspend(ctx, cli, "alice", "pause"); err != nil {
		t.Fatal(err)
	}
	openKeys, err := e.st.OpenDeviceKeys(alice.ID)
	if err != nil || len(openKeys) != 0 {
		t.Fatalf("expected 0 open keys after suspend, got %d (err=%v)", len(openKeys), err)
	}
	if err := e.svc.Resume(ctx, cli, "alice"); err != nil {
		t.Fatal(err)
	}
	// After suspend revoked old keys, alice can issue keys again; also verify PendingDeviceKeys filters old/used rows.
	if _, _, err := e.svc.IssueDeviceKey(ctx, aAlice, "alice", "personal"); err != nil {
		t.Fatalf("IssueDeviceKey after suspend/resume: %v", err)
	}
	if err := e.st.InsertDeviceKey(&DeviceKey{MemberID: alice.ID, Kind: "personal", HSKeyID: "old-exp", ExpiresAt: now() - 100000}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.InsertDeviceKey(&DeviceKey{MemberID: alice.ID, Kind: "personal", HSKeyID: "used-one", ExpiresAt: now() + 3600}); err != nil {
		t.Fatal(err)
	}
	allKeys, _ := e.st.PendingDeviceKeys(now() - 86400)
	if _, ok := allKeys["old-exp"]; ok {
		t.Fatal("PendingDeviceKeys should exclude old expired keys")
	}
	if dk := allKeys["used-one"]; dk != nil {
		_ = e.st.MarkDeviceKeyUsed(dk.ID)
	}
	allKeys, _ = e.st.PendingDeviceKeys(now() - 86400)
	if _, ok := allKeys["used-one"]; ok {
		t.Fatal("PendingDeviceKeys should exclude used keys")
	}

	// Invite note length & open invite quota.
	if _, err := e.svc.MintInvite(aAlice, "member", strings.Repeat("x", 17), time.Hour); err == nil {
		t.Fatal("expected oversized invite note to be rejected")
	}
	for i := 0; i < 2; i++ {
		if _, err := e.svc.MintInvite(aAlice, "member", "ok", time.Hour); err != nil {
			t.Fatalf("MintInvite #%d: %v", i, err)
		}
	}
	if _, err := e.svc.MintInvite(aAlice, "member", "ok", time.Hour); err == nil {
		t.Fatal("expected 3rd open invite to hit quota")
	}

	// Name quota.
	for _, nm := range []string{"n1", "n2"} {
		if _, err := e.svc.Claim(aAlice, "alice", nm, aliceSrv.ID, nil); err != nil {
			t.Fatalf("Claim(%s): %v", nm, err)
		}
	}
	if _, err := e.svc.Claim(aAlice, "alice", "n3", aliceSrv.ID, nil); err == nil {
		t.Fatal("expected 3rd name to hit quota")
	}
}

func TestCASharesCoreMeshIPAndPort9000(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root_ca.crt")
	writeTestRootCA(t, rootPath)
	st, err := OpenStore(filepath.Join(dir, "registrar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.db.Close() })
	hs := newFakeHeadscale(t)
	cfg := Config{
		Zone:       "bobo.hogman",
		PublicHost: "hs.example.com",
		CoreIP:     "100.64.0.10",
		RootCAFile: rootPath,
	}
	svc, err := NewService(cfg, st, NewHeadscale(hs.srv.URL, "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if svc.cfg.CAIP != "100.64.0.10" {
		t.Fatalf("CAIP=%q want 100.64.0.10", svc.cfg.CAIP)
	}
	dnsSrv, err := NewDNSServer(svc)
	if err != nil {
		t.Fatal(err)
	}
	if got := mustResolveA(t, dnsSrv, "ca.bobo.hogman."); got != "100.64.0.10" {
		t.Fatalf("ca.bobo.hogman. = %q want 100.64.0.10", got)
	}
	pol, err := svc.buildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pol, `"9000"`) {
		t.Fatalf("policy missing CA port 9000:\n%s", pol)
	}
}
