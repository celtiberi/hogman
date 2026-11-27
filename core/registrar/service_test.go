package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"hogman/registrar/internal/api"
	"hogman/registrar/internal/dns"
	"hogman/registrar/internal/headscale"
	"hogman/registrar/internal/registrar"
	"hogman/registrar/internal/store"
)

type fakeHeadscale struct {
	mu              sync.Mutex
	nextUserID      int
	nextKeyID       int
	users           map[string]headscale.User
	keys            map[string]headscale.PreAuthKey
	nodes           []headscale.Node
	policy          string
	failCreateKey   bool
	failSetPolicy   bool
	failListNodes   bool
	deleteUserCalls int
	listNodesCalls  int
	getNodeCalls    int
	setPolicyCalls  int
	onListNodes     func(context.Context)
	onGetNode       func(context.Context, string)
	onDeleteNode    func(http.ResponseWriter, string) bool
	srv             *httptest.Server
}

func newFakeHeadscale(t *testing.T) *fakeHeadscale {
	t.Helper()
	f := &fakeHeadscale{
		users: map[string]headscale.User{},
		keys:  map[string]headscale.PreAuthKey{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		name := r.URL.Query().Get("name")
		var out []headscale.User
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
		u := headscale.User{ID: strconv.Itoa(f.nextUserID), Name: in.Name}
		f.users[u.ID] = u
		_ = json.NewEncoder(w).Encode(map[string]any{"user": u})
	})
	mux.HandleFunc("DELETE /api/v1/user/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.deleteUserCalls++
		id := r.PathValue("id")
		if _, ok := f.users[id]; !ok {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		delete(f.users, id)
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
		k := headscale.PreAuthKey{ID: id, Key: "hskey-test-" + id, ACLTags: in.ACLTags}
		f.keys[id] = k
		_ = json.NewEncoder(w).Encode(map[string]any{"preAuthKey": k})
	})
	mux.HandleFunc("POST /api/v1/preauthkey/expire", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	mux.HandleFunc("GET /api/v1/node", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.listNodesCalls++
		hook := f.onListNodes
		f.mu.Unlock()
		if hook != nil {
			hook(r.Context())
			if r.Context().Err() != nil {
				return
			}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failListNodes {
			http.Error(w, "headscale nodes error", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"nodes": f.nodes})
	})
	mux.HandleFunc("GET /api/v1/node/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		f.mu.Lock()
		f.getNodeCalls++
		hook := f.onGetNode
		f.mu.Unlock()
		if hook != nil {
			hook(r.Context(), id)
			if r.Context().Err() != nil {
				return
			}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, n := range f.nodes {
			if n.ID == id {
				_ = json.NewEncoder(w).Encode(map[string]any{"node": n})
				return
			}
		}
		http.Error(w, "node not found", http.StatusNotFound)
	})
	mux.HandleFunc("DELETE /api/v1/node/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := r.PathValue("id")
		if f.onDeleteNode != nil && f.onDeleteNode(w, id) {
			return
		}
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
		defer f.mu.Unlock()
		f.setPolicyCalls++
		if f.failSetPolicy {
			http.Error(w, "policy error", http.StatusServiceUnavailable)
			return
		}
		f.policy = in.Policy
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
	svc      *registrar.Service
	st       *store.Store
	hs       *fakeHeadscale
	hsClient *headscale.Client
	dir      string
}

func newTestEnv(t *testing.T) *testEnv {
	return newTestEnvWithConfig(t, nil)
}

func newTestEnvWithConfig(t *testing.T, tweak func(*registrar.Config)) *testEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "registrar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	hs := newFakeHeadscale(t)
	hsClient := headscale.New(hs.srv.URL, "test-key")
	cfg := registrar.Config{
		Zone:         "bobo.hogman",
		PublicHost:   "hs.example.com",
		CoreIP:       "100.64.0.1",
		InviteTTL:    7 * 24 * time.Hour,
		DeviceKeyTTL: time.Hour,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	svc, err := registrar.NewService(cfg, st, hsClient)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{svc: svc, st: st, hs: hs, hsClient: hsClient, dir: dir}
}

func newTestDNSServer(s *registrar.Service) (*dns.Server, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s.CoreIP()))
	if err != nil {
		return nil, err
	}
	return dns.NewServer(s.Zone(), ip, s)
}

func testNodeKey(seed string) string {
	sum := sha256.Sum256([]byte("nodekey:" + seed))
	return "nodekey:" + hex.EncodeToString(sum[:])
}

func testMachineKey(seed string) string {
	sum := sha256.Sum256([]byte("mkey:" + seed))
	return "mkey:" + hex.EncodeToString(sum[:])
}

// peerResolver simulates tsnet LocalClient.WhoIs against the fake Headscale
// node table so HTTP tests exercise production MeshHandlerDirect.
func (e *testEnv) peerResolver() func(context.Context, string) (*registrar.PeerIdentity, error) {
	return func(_ context.Context, remoteAddr string) (*registrar.PeerIdentity, error) {
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			return nil, errors.New("malformed remoteAddr")
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return nil, errors.New("invalid peer ip")
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			return nil, errors.New("non-ipv4 peer")
		}
		canon := addr.String()
		e.hs.mu.Lock()
		defer e.hs.mu.Unlock()
		for _, n := range e.hs.nodes {
			for _, ip := range n.IPAddresses {
				if ip == canon {
					nk := n.NodeKey
					if nk == "" {
						nk = testNodeKey("hs-" + n.ID)
					}
					return &registrar.PeerIdentity{
						IP:       canon,
						HSNodeID: n.ID,
						NodeKey:  nk,
					}, nil
				}
			}
		}
		return nil, errors.New("unknown peer")
	}
}

func (e *testEnv) meshHandler(svc *registrar.Service) http.Handler {
	return api.MeshHandlerDirect(svc, e.peerResolver())
}

func (e *testEnv) addDevice(t *testing.T, handle, kind, name, ipv4, ipv6 string) (*store.Member, *store.Device) {
	t.Helper()
	m, err := e.st.MemberByHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	seed := fmt.Sprintf("%d-%s", m.ID, name)
	d := &store.Device{
		MemberID:   m.ID,
		Kind:       kind,
		HSNodeID:   fmt.Sprintf("node-%d-%s", m.ID, name),
		NodeKey:    testNodeKey(seed),
		MachineKey: testMachineKey(seed),
		Name:       name,
		IPv4:       ipv4,
		IPv6:       ipv6,
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
	hsNode := headscale.Node{
		ID:          d.HSNodeID,
		MachineKey:  d.MachineKey,
		NodeKey:     d.NodeKey,
		Name:        name,
		GivenName:   name,
		IPAddresses: ips,
	}
	if kind == "server" {
		hsNode.Tags = []string{"tag:server"}
	} else {
		hsNode.User = &headscale.User{ID: m.HSUserID, Name: m.Handle}
	}
	e.hs.mu.Lock()
	e.hs.nodes = append(e.hs.nodes, hsNode)
	e.hs.mu.Unlock()
	return m, d
}

func TestRedeemRollbackOnPreAuthKeyFailure(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := registrar.Actor{CLI: true}

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
	if _, err := e.st.MemberByHandle("alice"); !errors.Is(err, store.ErrNotFound) {
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
	cli := registrar.Actor{CLI: true}

	alice, err := e.svc.AddMember(ctx, cli, "alice", "admin")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := e.svc.MintInvite(registrar.Actor{Member: alice}, "member", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Suspend(ctx, cli, "alice", "timeout"); err != nil {
		t.Fatal(err)
	}

	_, err = e.svc.Redeem(ctx, inv.Token, "bob")
	var de *registrar.Error
	if !errors.As(err, &de) || de.Kind != registrar.KindForbidden {
		t.Fatalf("want KindForbidden for suspended minter, got %v", err)
	}
	gotInv, _ := e.st.InviteByID(inv.ID)
	if gotInv.State() != "open" {
		t.Fatalf("invite state = %q, want open", gotInv.State())
	}
}

func TestClaimOwnerSeizeAndConcurrency(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := registrar.Actor{CLI: true}

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

	if _, err := e.svc.Claim(registrar.Actor{Member: alice}, "alice", "alice", aliceSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(registrar.Actor{Member: bob}, "bob", "alice", bobSrv.ID, nil); err == nil {
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
		_, err := e.svc.Claim(registrar.Actor{Member: alice}, "alice", "contested", aliceSrv.ID, nil)
		errs <- err
	}()
	go func() {
		defer wg.Done()
		_, err := e.svc.Claim(registrar.Actor{Member: bob}, "bob", "contested", bobSrv.ID, nil)
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
		var de *registrar.Error
		if errors.As(err, &de) && de.Kind == registrar.KindConflict {
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
	cli := registrar.Actor{CLI: true}

	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, srv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.20", "fd7a:115c:a1e0::20")
	if _, err := e.svc.Claim(registrar.Actor{Member: alice}, "alice", "alice", srv.ID, nil); err != nil {
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
			st2, err := store.Open(dbPath)
			if err != nil {
				errs <- err
				return
			}
			defer st2.DB().Close()
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
	cli := registrar.Actor{CLI: true}

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

	if _, err := e.svc.Claim(registrar.Actor{Member: owner}, "root", "root-site", ownerSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(registrar.Actor{Member: admin2}, "carol", "carol-site", admin2Srv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(registrar.Actor{Member: member1}, "bob", "bob-site", memberSrv.ID, nil); err != nil {
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

	a1 := registrar.Actor{Member: admin1}

	// Admin cannot remove another admin's or owner's device, but can remove a member's device.
	for _, devID := range []int64{ownerSrv.ID, admin2Dev.ID} {
		err := e.svc.RemoveDevice(ctx, a1, devID)
		var de *registrar.Error
		if !errors.As(err, &de) || de.Kind != registrar.KindForbidden {
			t.Fatalf("admin RemoveDevice(%d): got %v, want KindForbidden", devID, err)
		}
	}
	if err := e.svc.RemoveDevice(ctx, a1, memberDev.ID); err != nil {
		t.Fatalf("admin RemoveDevice(memberDev): %v", err)
	}

	// Admin cannot release owner's name or another admin's name.
	for _, name := range []string{"root-site", "carol-site"} {
		err := e.svc.Release(a1, name)
		var de *registrar.Error
		if !errors.As(err, &de) || de.Kind != registrar.KindForbidden {
			t.Fatalf("admin Release(%q): got %v, want KindForbidden", name, err)
		}
	}
	// Nobody (admin, owner, or CLI) can release a permanently retired name.
	for _, actor := range []registrar.Actor{a1, {Member: owner}, cli} {
		err := e.svc.Release(actor, "gary-site")
		var de *registrar.Error
		if !errors.As(err, &de) || de.Kind != registrar.KindConflict {
			t.Fatalf("%s Release(gary-site): got %v, want KindConflict", actor, err)
		}
	}
	// Admin can still release a regular active member's name.
	if err := e.svc.Release(a1, "bob-site"); err != nil {
		t.Fatalf("admin Release(bob-site): %v", err)
	}

	// Admin cannot issue device keys or claim names for owner or another admin.
	for _, target := range []string{"root", "carol"} {
		_, _, err := e.svc.IssueDeviceKey(ctx, a1, target, "personal")
		var de *registrar.Error
		if !errors.As(err, &de) || de.Kind != registrar.KindForbidden {
			t.Fatalf("admin IssueDeviceKey(%s): got %v, want KindForbidden", target, err)
		}
	}
	if _, err := e.svc.Claim(a1, "carol", "hijack", admin2Srv.ID, nil); err == nil {
		t.Fatal("admin should not claim names for another admin")
	}
}

func TestClaimSeizeCleansUpChildSubdomains(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := registrar.Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "root", "owner"); err != nil {
		t.Fatal(err)
	}
	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, rootSrv := e.addDevice(t, "root", "server", "root-srv", "100.64.0.10", "")
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")

	if _, err := e.svc.Claim(registrar.Actor{Member: alice}, "alice", "alice", aliceSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(registrar.Actor{Member: alice}, "alice", "blog.alice", aliceSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(cli, "root", "alice", rootSrv.ID, nil); err != nil {
		t.Fatalf("owner seize failed: %v", err)
	}
	if _, err := e.st.NameByName("blog.alice"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("child name blog.alice should be deleted on parent seize, got err=%v", err)
	}
	dnsSrv, err := newTestDNSServer(e.svc)
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
	e := newTestEnvWithConfig(t, func(c *registrar.Config) {
		c.MaxOpenDeviceKeys = 2
		c.MaxNamesPerMember = 2
		c.MaxOpenInvites = 2
		c.MaxInviteNoteLen = 16
		c.MembersCanInvite = true
	})

	ctx := context.Background()
	cli := registrar.Actor{CLI: true}
	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")
	aAlice := registrar.Actor{Member: alice}

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
	nowUnix := time.Now().Unix()
	if err := e.st.InsertDeviceKey(&store.DeviceKey{MemberID: alice.ID, Kind: "personal", HSKeyID: "old-exp", ExpiresAt: nowUnix - 100000}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.InsertDeviceKey(&store.DeviceKey{MemberID: alice.ID, Kind: "personal", HSKeyID: "used-one", ExpiresAt: nowUnix + 3600}); err != nil {
		t.Fatal(err)
	}
	allKeys, _ := e.st.PendingDeviceKeys(nowUnix - 86400)
	if _, ok := allKeys["old-exp"]; ok {
		t.Fatal("PendingDeviceKeys should exclude old expired keys")
	}
	if dk := allKeys["used-one"]; dk != nil {
		_ = e.st.MarkDeviceKeyUsed(dk.ID)
	}
	allKeys, _ = e.st.PendingDeviceKeys(nowUnix - 86400)
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

func TestNoCARecordOrPort9000(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "registrar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DB().Close() })
	hs := newFakeHeadscale(t)
	cfg := registrar.Config{
		Zone:       "bobo.pens.example.com",
		PublicHost: "bobo.gate.example.com",
		CoreIP:     "100.64.0.10",
	}
	svc, err := registrar.NewService(cfg, st, headscale.New(hs.srv.URL, "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	dnsSrv, err := newTestDNSServer(svc)
	if err != nil {
		t.Fatal(err)
	}
	resp, ok := dnsSrv.HandlePacket(buildDNSQuery(t, 1, "ca.bobo.pens.example.com.", dnsmessage.TypeA, true, 0), false)
	if !ok {
		t.Fatal("expected DNS response for ca.<zone>")
	}
	hdr, ans, _, _ := parseDNSResp(t, resp)
	if hdr.RCode != dnsmessage.RCodeNameError || len(ans) != 0 {
		t.Fatalf("ca.<zone> got rcode=%v ans=%d, want NXDOMAIN", hdr.RCode, len(ans))
	}
	if _, err := svc.NormaliseName("ca"); err != nil {
		t.Fatalf("expected label ca to be unreserved: %v", err)
	}
	pol, _, err := svc.BuildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pol, `"9000"`) {
		t.Fatalf("policy still allows retired CA port 9000:\n%s", pol)
	}
	if !strings.Contains(pol, `"53"`) || !strings.Contains(pol, `"443"`) {
		t.Fatalf("policy missing DNS/HTTPS ports:\n%s", pol)
	}
}

func TestBuildPolicyIsolatesServersFromEachOther(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.svc.AddMember(context.Background(), registrar.Actor{CLI: true}, "alice", "member"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	e.addDevice(t, "alice", "server", "alice-srv1", "100.64.0.11", "")
	e.addDevice(t, "alice", "server", "alice-srv2", "100.64.0.12", "")

	pol, _, err := e.svc.BuildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Grants []struct {
			Src []string `json:"src"`
			Dst []string `json:"dst"`
			IP  []string `json:"ip"`
		} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(pol), &parsed); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	if len(parsed.Grants) != 2 {
		t.Fatalf("grants count = %d, want 2:\n%s", len(parsed.Grants), pol)
	}
	infraGrant := parsed.Grants[0]
	srvGrant := parsed.Grants[1]

	has := func(list []string, want string) bool {
		for _, v := range list {
			if v == want {
				return true
			}
		}
		return false
	}
	// Servers must still reach tag:infra (DNS + registrar/certs).
	if !has(infraGrant.Src, "100.64.0.10") || !has(infraGrant.Src, "100.64.0.11") || !has(infraGrant.Src, "100.64.0.12") {
		t.Fatalf("infra grant missing expected devices: %+v", infraGrant.Src)
	}
	if !has(infraGrant.IP, "53") || !has(infraGrant.IP, "443") || len(infraGrant.IP) != 2 {
		t.Fatalf("infra grant ports = %+v, want [53 443]", infraGrant.IP)
	}
	// Personal devices reach servers on 443, but servers cannot reach other servers
	// or personal devices.
	if !has(srvGrant.Src, "100.64.0.10") || !has(srvGrant.Src, "tag:infra") {
		t.Fatalf("servers grant missing personal device or tag:infra: %+v", srvGrant.Src)
	}
	if has(srvGrant.Src, "100.64.0.11") || has(srvGrant.Src, "100.64.0.12") {
		t.Fatalf("servers grant must exclude server devices from src: %+v", srvGrant.Src)
	}
	if !has(srvGrant.Dst, "100.64.0.11") || !has(srvGrant.Dst, "100.64.0.12") || has(srvGrant.Dst, "100.64.0.10") {
		t.Fatalf("servers grant destinations unexpected: %+v", srvGrant.Dst)
	}
	if !has(srvGrant.IP, "443") || len(srvGrant.IP) != 1 {
		t.Fatalf("servers grant ports = %+v, want [443]", srvGrant.IP)
	}
	for _, g := range parsed.Grants {
		if has(g.Dst, "100.64.0.10") {
			t.Fatalf("personal device must never appear in any grant dst: %+v", g)
		}
	}
}

func TestStoreConcurrentSubprocesses(t *testing.T) {
	if dbPath := os.Getenv("GO_TEST_STORE_HELPER_DB"); dbPath != "" {
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("OpenStore: %v", err)
		}
		defer st.Close()

		ds, err := st.LiveDevices()
		if err != nil {
			t.Fatalf("LiveDevices: %v", err)
		}
		found := false
		for _, d := range ds {
			if d.Name == "bob-laptop" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("bob-laptop missing from LiveDevices (%d rows)", len(ds))
		}
		if _, err := st.AuditLog(50); err != nil {
			t.Fatalf("AuditLog: %v", err)
		}
		st.Audit("cli", "member.check", "bob", os.Getenv("GO_TEST_STORE_HELPER_ID"))
		return
	}

	dbPath := filepath.Join(t.TempDir(), "registrar.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer st.Close()

	bob := &store.Member{Handle: "bob", Role: "member", Status: "active", HSUserID: "u-bob"}
	if err := st.InsertMember(bob); err != nil {
		t.Fatalf("InsertMember: %v", err)
	}
	if err := st.InsertDevice(&store.Device{
		MemberID: bob.ID,
		Kind:     "personal",
		HSNodeID: "n-bob",
		Name:     "bob-laptop",
		IPv4:     "100.64.0.2",
	}); err != nil {
		t.Fatalf("InsertDevice: %v", err)
	}
	st.Audit("cli", "member.init", "bob", "seed")

	stop := make(chan struct{})
	var writerErr atomic.Value
	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		tkr := time.NewTicker(5 * time.Millisecond)
		defer tkr.Stop()
		statuses := []string{"suspended", "active"}
		for i := 0; ; i++ {
			status := statuses[i%2]
			if err := st.SetMemberStatus(bob.ID, status); err != nil {
				writerErr.Store(fmt.Errorf("SetMemberStatus(%s): %w", status, err))
				return
			}
			st.Audit("cli", "member."+status, "bob", fmt.Sprintf("iter-%d", i))
			select {
			case <-stop:
				return
			case <-tkr.C:
			}
		}
	}()

	const workers = 6
	const perWorker = 4
	var childWG sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		childWG.Add(1)
		go func(worker int) {
			defer childWG.Done()
			for j := 0; j < perWorker; j++ {
				id := fmt.Sprintf("w%d-j%d", worker, j)
				cmd := exec.Command(os.Args[0], "-test.run=^TestStoreConcurrentSubprocesses$")
				cmd.Env = append(os.Environ(),
					"GO_TEST_STORE_HELPER_DB="+dbPath,
					"GO_TEST_STORE_HELPER_ID="+id,
				)
				out, err := cmd.CombinedOutput()
				if err != nil {
					errs <- fmt.Errorf("subprocess %s failed: %w\n%s", id, err, string(out))
				} else if strings.Contains(string(out), "audit ") {
					errs <- fmt.Errorf("subprocess %s logged audit error:\n%s", id, string(out))
				}
			}
		}(w)
	}
	childWG.Wait()
	close(stop)
	writerWG.Wait()
	close(errs)

	if v := writerErr.Load(); v != nil {
		t.Fatalf("background writer failed: %v", v.(error))
	}
	for err := range errs {
		t.Fatal(err)
	}

	entries, err := st.AuditLog(1000000)
	if err != nil {
		t.Fatalf("AuditLog: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Action == "member.check" && e.Target == "bob" {
			seen[e.Detail] = true
		}
	}
	if len(seen) != workers*perWorker {
		t.Fatalf("got %d member.check audit entries, want %d", len(seen), workers*perWorker)
	}
}

// D-16: no account recovery. Nobody makes a personal device key for someone
// else, except the server's tool for a member's very first device.
func TestNoAccountRecoveryKeys(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := registrar.Actor{CLI: true}
	root, err := e.svc.AddMember(ctx, cli, "root", "owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	// First device: the server's tool may (how a new pen's owner gets in).
	if _, _, err := e.svc.IssueDeviceKey(ctx, cli, "root", "personal"); err != nil {
		t.Fatalf("first device for root: %v", err)
	}
	e.addDevice(t, "root", "personal", "root-laptop", "100.64.0.10", "")
	e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.13", "")
	// Once joined, never again, not even from the server.
	for _, h := range []string{"root", "bob"} {
		if _, _, err := e.svc.IssueDeviceKey(ctx, cli, h, "personal"); err == nil {
			t.Fatalf("server tool made a personal key for %s, who has joined", h)
		}
	}
	// An owner can't make one for someone else either; a server key is fine.
	owner := registrar.Actor{Member: root}
	if _, _, err := e.svc.IssueDeviceKey(ctx, owner, "bob", "personal"); err == nil {
		t.Fatal("owner made a personal key for bob")
	}
	if _, _, err := e.svc.IssueDeviceKey(ctx, owner, "bob", "server"); err != nil {
		t.Fatalf("owner server key for bob: %v", err)
	}
	// Your own next device still works.
	if _, _, err := e.svc.IssueDeviceKey(ctx, owner, "root", "personal"); err != nil {
		t.Fatalf("root's own next device: %v", err)
	}
}

// H7 (audit 2026-11): two owners demoting each other at the same moment must
// never leave the pen with no owner, because there is no recovery (D-16).
func TestOwnersCannotAllBeDemoted(t *testing.T) {
	for round := 0; round < 20; round++ {
		e := newTestEnv(t)
		ctx := context.Background()
		cli := registrar.Actor{CLI: true}
		a, err := e.svc.AddMember(ctx, cli, "ann", "owner")
		if err != nil {
			t.Fatal(err)
		}
		b, err := e.svc.AddMember(ctx, cli, "bea", "owner")
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = e.svc.SetRole(ctx, registrar.Actor{Member: a}, "bea", "admin") }()
		go func() { defer wg.Done(); _ = e.svc.SetRole(ctx, registrar.Actor{Member: b}, "ann", "admin") }()
		wg.Wait()
		if n, _ := e.st.CountOwners(); n < 1 {
			t.Fatalf("round %d: pen left with %d owners", round, n)
		}
	}
}

// H7: an invite carries its maker's authority, so it stops working when the
// maker loses the role that let them make it.
func TestInvitesFollowTheirMakersRole(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := registrar.Actor{CLI: true}
	if _, err := e.svc.AddMember(ctx, cli, "root", "owner"); err != nil {
		t.Fatal(err)
	}
	carol, err := e.svc.AddMember(ctx, cli, "carol", "owner")
	if err != nil {
		t.Fatal(err)
	}
	dan, err := e.svc.AddMember(ctx, cli, "dan", "admin")
	if err != nil {
		t.Fatal(err)
	}
	adminInv, err := e.svc.MintInvite(registrar.Actor{Member: carol}, "admin", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	memberInv, err := e.svc.MintInvite(registrar.Actor{Member: dan}, "member", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Carol is demoted: her open invites are revoked straight away.
	if err := e.svc.SetRole(ctx, cli, "carol", "member"); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.st.InviteByID(adminInv.ID); got.State() != "revoked" {
		t.Fatalf("carol's admin invite is %q after demotion, want revoked", got.State())
	}
	if _, err := e.svc.Redeem(ctx, adminInv.Token, "eve"); err == nil {
		t.Fatal("an admin invite from a demoted owner still worked")
	}

	// Even an invite that somehow stayed open is checked at redemption.
	if err := e.st.SetMemberRole(dan.ID, "member"); err != nil { // bypasses SetRole's revoke
		t.Fatal(err)
	}
	if _, err := e.svc.Redeem(ctx, memberInv.Token, "fay"); err == nil {
		t.Fatal("a member invite from someone who can no longer invite still worked")
	}
}

func TestKickedNamesPermanentlyRetired(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := registrar.Actor{CLI: true}

	owner, err := e.svc.AddMember(ctx, cli, "root", "owner")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := e.svc.AddMember(ctx, cli, "ada", "admin")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := e.svc.AddMember(ctx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := e.svc.AddMember(ctx, cli, "alice", "member")
	if err != nil {
		t.Fatal(err)
	}

	_, ownerSrv := e.addDevice(t, "root", "server", "root-srv", "100.64.0.10", "")
	_, adminSrv := e.addDevice(t, "ada", "server", "ada-srv", "100.64.0.11", "")
	_, bobSrv := e.addDevice(t, "bob", "server", "bob-srv", "100.64.0.12", "")
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.13", "")

	if _, err := e.svc.Claim(registrar.Actor{Member: alice}, "alice", "photos", aliceSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(registrar.Actor{Member: alice}, "alice", "raw.photos", aliceSrv.ID, nil); err != nil {
		t.Fatal(err)
	}

	rep, err := e.svc.Kick(ctx, cli, "alice", "left")
	if err != nil {
		t.Fatal(err)
	}
	if rep.NamesRetired != 2 {
		t.Fatalf("NamesRetired = %d, want 2", rep.NamesRetired)
	}
	if res, err := e.st.ResolvableNames(); err != nil || len(res) != 0 {
		t.Fatalf("ResolvableNames after kick = %d (err=%v), want 0", len(res), err)
	}

	// Simulate an existing DB row whose old 90-day held_until timestamp is in the past.
	if _, err := e.st.DB().Exec(`UPDATE names SET held_until = 1 WHERE name IN ('photos', 'raw.photos')`); err != nil {
		t.Fatal(err)
	}

	assertConflict := func(label string, err error) {
		t.Helper()
		var de *registrar.Error
		if !errors.As(err, &de) || de.Kind != registrar.KindConflict {
			t.Fatalf("%s: got %v, want KindConflict", label, err)
		}
	}

	// Nobody — member, admin, owner, CLI, or share server — can reclaim a retired name or subdomain under it.
	_, err = e.svc.Claim(registrar.Actor{Member: bob}, "bob", "photos", bobSrv.ID, nil)
	assertConflict("member Claim retired name", err)
	_, err = e.svc.Claim(registrar.Actor{Member: admin}, "ada", "photos", adminSrv.ID, nil)
	assertConflict("admin Claim retired name", err)
	_, err = e.svc.Claim(registrar.Actor{Member: owner}, "root", "photos", ownerSrv.ID, nil)
	assertConflict("owner Claim retired name", err)
	_, err = e.svc.Claim(cli, "root", "photos", ownerSrv.ID, nil)
	assertConflict("CLI Claim retired name", err)
	_, err = e.svc.ServerClaim(registrar.Actor{Member: bob}, bobSrv, "photos", nil)
	assertConflict("server Claim retired name", err)
	_, err = e.svc.ServerClaim(registrar.Actor{Member: owner}, ownerSrv, "photos", nil)
	assertConflict("owner server Claim retired name", err)
	_, err = e.svc.Claim(cli, "root", "new.photos", ownerSrv.ID, nil)
	assertConflict("CLI Claim subdomain under retired name", err)
	_, err = e.svc.ServerClaim(registrar.Actor{Member: bob}, bobSrv, "new.photos", nil)
	assertConflict("server Claim subdomain under retired name", err)

	// Nobody — member, admin, owner, or CLI — can release a retired name.
	for _, actor := range []registrar.Actor{{Member: bob}, {Member: admin}, {Member: owner}, cli} {
		assertConflict(actor.String()+" Release retired name", e.svc.Release(actor, "photos"))
		assertConflict(actor.String()+" Release retired child", e.svc.Release(actor, "raw.photos"))
	}

	// Defense in depth at the store layer: UpsertName refuses and DeleteName leaves retired rows intact.
	if err := e.st.UpsertName("photos", owner.ID, &ownerSrv.ID, ""); err == nil {
		t.Fatal("UpsertName overwrote retired name")
	}
	if err := e.st.DeleteName("photos"); err != nil {
		t.Fatalf("DeleteName: %v", err)
	}
	if got, err := e.st.NameByName("photos"); err != nil || got.RetiredAt == nil {
		t.Fatalf("retired name should remain in store after DeleteName, got %+v err=%v", got, err)
	}

	// Active members can still voluntarily release their own active names for reuse.
	if _, err := e.svc.Claim(registrar.Actor{Member: bob}, "bob", "temp", bobSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Release(registrar.Actor{Member: bob}, "temp"); err != nil {
		t.Fatalf("active member Release(temp): %v", err)
	}
	if _, err := e.svc.Claim(registrar.Actor{Member: owner}, "root", "temp", ownerSrv.ID, nil); err != nil {
		t.Fatalf("reclaim voluntarily released active name: %v", err)
	}
}

func TestCLIStrconvValidation(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	for _, args := range [][]string{
		{"invite", "revoke", "abc"},
		{"invite", "revoke", "0"},
		{"invite", "revoke", "-5"},
		{"device", "rm", "notanid"},
		{"device", "rm", "0"},
		{"name", "claim", "alice", "web", "notanid"},
		{"name", "claim", "alice", "web", "-1"},
		{"audit", "nope"},
		{"audit", "0"},
		{"audit", "-3"},
	} {
		err := cli(ctx, e.svc, args)
		var de *registrar.Error
		if !errors.As(err, &de) || de.Kind != registrar.KindInvalid {
			t.Errorf("cli(%v) = %v, want KindInvalid", args, err)
		}
	}
}

func TestReleaseNamesAndMarkDeviceRemoved(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cliActor := registrar.Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cliActor, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	_, srv := e.addDevice(t, "alice", "server", "srv1", "100.64.0.11", "")
	if _, err := e.svc.Claim(cliActor, "alice", "blog", srv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(cliActor, "alice", "img.blog", srv.ID, nil); err != nil {
		t.Fatal(err)
	}
	privFQDN, err := e.svc.ClaimPrivate(cliActor, "alice", srv.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	privLabel := strings.TrimSuffix(privFQDN, "."+e.svc.Zone())
	if err := e.svc.Release(cliActor, privLabel); err != nil {
		t.Fatalf("Release private: %v", err)
	}
	gotPriv, err := e.st.NameByName(privLabel)
	if err != nil || gotPriv.RetiredAt == nil {
		t.Fatalf("private name after Release = %+v, err=%v; want retired", gotPriv, err)
	}
	// Multi-row non-private release deletes both parent and child atomically.
	if err := e.svc.Release(cliActor, "blog"); err != nil {
		t.Fatalf("Release blog subtree: %v", err)
	}
	for _, n := range []string{"blog", "img.blog"} {
		if _, err := e.st.NameByName(n); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("released non-private %q still present: err=%v", n, err)
		}
	}
	// Re-claim blog to verify MarkDeviceRemoved unpoints names aimed at the removed device.
	if _, err := e.svc.Claim(cliActor, "alice", "blog", srv.ID, nil); err != nil {
		t.Fatal(err)
	}

	if err := e.st.MarkDeviceRemoved(srv.ID); err != nil {
		t.Fatalf("MarkDeviceRemoved: %v", err)
	}
	gotDev, err := e.st.DeviceByID(srv.ID)
	if err != nil || gotDev.RemovedAt == nil {
		t.Fatalf("removed device after MarkDeviceRemoved = %+v, err=%v; want RemovedAt != nil", gotDev, err)
	}
	live, err := e.st.LiveDevices()
	if err != nil || len(live) != 0 {
		t.Fatalf("LiveDevices after MarkDeviceRemoved = %+v, err=%v; want empty", live, err)
	}
	gotBlog, err := e.st.NameByName("blog")
	if err != nil || gotBlog.DeviceID != nil {
		t.Fatalf("name after MarkDeviceRemoved = %+v, err=%v; want unpointed", gotBlog, err)
	}
}
