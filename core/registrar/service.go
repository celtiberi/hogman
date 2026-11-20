package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Zone              string // bobo.hogman
	PublicHost        string // control server hostname
	CoreIP            string // mesh IP of the core node (DNS, portal)
	CAIP              string // mesh IP of the CA
	ZoneFile          string
	RootCAFile        string
	NameHold          time.Duration
	InviteTTL         time.Duration
	DeviceKeyTTL      time.Duration
	MembersCanInvite  bool
	MaxOpenDeviceKeys int
	MaxNamesPerMember int
	MaxOpenInvites    int
	MaxInviteNoteLen  int
}

// Actor is whoever is performing an action: a member over the mesh API,
// or the owner at the server's command line.
type Actor struct {
	Member *Member
	CLI    bool
}

func (a Actor) String() string {
	if a.CLI {
		return "owner@cli"
	}
	return a.Member.Handle
}

func (a Actor) Role() string {
	if a.CLI {
		return "owner"
	}
	return a.Member.Role
}

func (a Actor) IsAdmin() bool { r := a.Role(); return r == "owner" || r == "admin" }
func (a Actor) IsOwner() bool { return a.Role() == "owner" }
func (a Actor) Is(m *Member) bool {
	return !a.CLI && a.Member != nil && a.Member.ID == m.ID
}

// Problem is an error meant for the caller, with an HTTP status.
type Problem struct {
	Status int
	Msg    string
}

func (p *Problem) Error() string { return p.Msg }

func bad(f string, a ...any) error       { return &Problem{400, fmt.Sprintf(f, a...)} }
func forbidden(f string, a ...any) error { return &Problem{403, fmt.Sprintf(f, a...)} }
func missing(f string, a ...any) error   { return &Problem{404, fmt.Sprintf(f, a...)} }
func conflict(f string, a ...any) error  { return &Problem{409, fmt.Sprintf(f, a...)} }

type Service struct {
	cfg     Config
	st      *Store
	hs      *Headscale
	rootPEM string
	rootFP  string

	mu         sync.Mutex // serialises changes that touch Headscale, policy or DNS
	lastPolicy string
	lastZone   string
	orphans    map[string]bool
}

func NewService(cfg Config, st *Store, hs *Headscale) (*Service, error) {
	if cfg.MaxOpenDeviceKeys <= 0 {
		cfg.MaxOpenDeviceKeys = 10
	}
	if cfg.MaxNamesPerMember <= 0 {
		cfg.MaxNamesPerMember = 50
	}
	if cfg.MaxOpenInvites <= 0 {
		cfg.MaxOpenInvites = 25
	}
	if cfg.MaxInviteNoteLen <= 0 {
		cfg.MaxInviteNoteLen = 256
	}
	s := &Service{cfg: cfg, st: st, hs: hs, orphans: map[string]bool{}}
	raw, err := os.ReadFile(cfg.RootCAFile)
	if err != nil {
		return nil, fmt.Errorf("root CA: %w", err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("root CA: not PEM")
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		return nil, fmt.Errorf("root CA: %w", err)
	}
	sum := sha256.Sum256(blk.Bytes)
	s.rootPEM = string(raw)
	s.rootFP = strings.ToUpper(hex.EncodeToString(sum[:]))
	return s, nil
}

func (s *Service) LoginServer() string { return "https://" + s.cfg.PublicHost }

type NetworkInfo struct {
	Zone            string `json:"zone"`
	LoginServer     string `json:"login_server"`
	RootCA          string `json:"root_ca"`
	RootFingerprint string `json:"root_fingerprint"`
	Portal          string `json:"portal"`
	// Mesh address of the pen's DNS server. Only reachable from inside the
	// mesh; side-by-side clients resolve pen names through it.
	DNSServer string `json:"dns_server"`
}

func (s *Service) NetworkInfo() NetworkInfo {
	return NetworkInfo{Zone: s.cfg.Zone, LoginServer: s.LoginServer(), RootCA: s.rootPEM,
		RootFingerprint: s.rootFP, Portal: "https://home." + s.cfg.Zone, DNSServer: s.cfg.CoreIP}
}

// Links handed to people. The part after # never reaches any server: the
// join page and join tool read it locally.
//
//	invite: https://<host>/join#t=<invite token>&fp=<root fingerprint>
//	device: https://<host>/join#k=<device key>&fp=<root fingerprint>
func (s *Service) InviteLink(token string) string {
	return fmt.Sprintf("https://%s/join#t=%s&fp=%s", s.cfg.PublicHost, token, s.rootFP)
}

func (s *Service) DeviceLink(key string) string {
	return fmt.Sprintf("https://%s/join#k=%s&fp=%s", s.cfg.PublicHost, key, s.rootFP)
}

// ------------------------------------------------------------- validation --

var (
	handleRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	labelRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reserved = map[string]bool{"home": true, "ca": true, "ns": true, "registrar": true,
		"search": true, "nodes": true, "www": true, "join": true, "admin": true}
	validRoles = map[string]bool{"owner": true, "admin": true, "member": true}
	serialRE   = regexp.MustCompile(`SOA[^(]*\(\s*(\d+)`)
)

// normaliseName turns "Blog.Alice.bobo.hogman." into "blog.alice" and checks it.
func (s *Service) normaliseName(raw string) (string, error) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	n = strings.TrimSuffix(n, "."+s.cfg.Zone)
	if n == "" || n == s.cfg.Zone {
		return "", bad("name is empty")
	}
	labels := strings.Split(n, ".")
	if len(labels) > 4 {
		return "", bad("name %q has too many levels", raw)
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return "", bad("name %q: labels are letters, digits and dashes", raw)
		}
	}
	if reserved[labels[len(labels)-1]] {
		return "", forbidden("%q is reserved by the network", labels[len(labels)-1])
	}
	return n, nil
}

func topLabel(name string) string {
	i := strings.LastIndex(name, ".")
	return name[i+1:]
}

func (s *Service) member(handle string) (*Member, error) {
	m, err := s.st.MemberByHandle(handle)
	if errors.Is(err, ErrNotFound) {
		return nil, missing("no member %q", handle)
	}
	return m, err
}

// --------------------------------------------------------------- members --

// AddMember creates a member directly, without an invite. Used to create the
// owner, and by admins who want to skip the invite step.
func (s *Service) AddMember(ctx context.Context, a Actor, handle, role string) (*Member, error) {
	if !a.IsAdmin() {
		return nil, forbidden("only admins can add members directly")
	}
	if !validRoles[role] {
		return nil, bad("role must be owner, admin or member")
	}
	if role != "member" && !a.IsOwner() {
		return nil, forbidden("only the owner can create admins or owners")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.createMember(ctx, handle, role, a.memberID())
	if err != nil {
		return nil, err
	}
	s.st.Audit(a.String(), "member.add", handle, "role="+role)
	return m, nil
}

func (a Actor) memberID() *int64 {
	if a.CLI || a.Member == nil {
		return nil
	}
	return &a.Member.ID
}

func (s *Service) createMember(ctx context.Context, handle, role string, invitedBy *int64) (*Member, error) {
	if !handleRE.MatchString(handle) {
		return nil, bad("handle must be 2-32 lowercase letters, digits or dashes, starting with a letter")
	}
	if _, err := s.st.MemberByHandle(handle); err == nil {
		return nil, conflict("handle %q is taken", handle)
	}
	u, err := s.hs.EnsureUser(ctx, handle)
	if err != nil {
		return nil, err
	}
	m := &Member{Handle: handle, Role: role, Status: "active", InvitedBy: invitedBy, HSUserID: u.ID}
	if err := s.st.InsertMember(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (s *Service) SetRole(a Actor, handle, role string) error {
	if !a.IsOwner() {
		return forbidden("only the owner can change roles")
	}
	if !validRoles[role] {
		return bad("role must be owner, admin or member")
	}
	m, err := s.member(handle)
	if err != nil {
		return err
	}
	if m.Status == "removed" {
		return conflict("%s has been removed", handle)
	}
	if m.Role == "owner" && role != "owner" {
		if n, _ := s.st.CountOwners(); n <= 1 {
			return conflict("%s is the only owner", handle)
		}
	}
	if err := s.st.SetMemberRole(m.ID, role); err != nil {
		return err
	}
	s.st.Audit(a.String(), "member.role", handle, m.Role+" -> "+role)
	return nil
}

// canRemove applies DESIGN.md section 9, "Protecting the owner".
func canRemove(a Actor, m *Member) error {
	switch {
	case !a.IsAdmin():
		return forbidden("only admins can do that")
	case m.Role == "owner":
		return forbidden("the owner cannot be suspended or removed")
	case m.Role == "admin" && !a.IsOwner():
		return forbidden("only the owner can suspend or remove an admin")
	case a.Is(m):
		return forbidden("you cannot do that to yourself")
	}
	return nil
}

func (s *Service) revokeOpenKeys(ctx context.Context, memberID int64, action string) int {
	keys, err := s.st.OpenDeviceKeys(memberID)
	if err != nil {
		log.Printf("%s: list device keys: %v", action, err)
		return 0
	}
	count := 0
	for _, k := range keys {
		if err := s.hs.ExpireKey(ctx, k.HSKeyID); err != nil {
			log.Printf("%s: expire key %s: %v", action, k.HSKeyID, err)
		}
		_ = s.st.RevokeDeviceKey(k.ID)
		count++
	}
	return count
}

func (s *Service) Suspend(ctx context.Context, a Actor, handle, reason string) error {
	m, err := s.member(handle)
	if err != nil {
		return err
	}
	if err := canRemove(a, m); err != nil {
		return err
	}
	if m.Status != "active" {
		return conflict("%s is %s", handle, m.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.st.SetMemberStatus(m.ID, "suspended"); err != nil {
		return err
	}
	s.revokeOpenKeys(ctx, m.ID, "suspend "+handle)
	s.st.Audit(a.String(), "member.suspend", handle, reason)
	return s.applyPolicy(ctx) // their devices drop out of every grant
}

func (s *Service) Resume(ctx context.Context, a Actor, handle string) error {
	m, err := s.member(handle)
	if err != nil {
		return err
	}
	if err := canRemove(a, m); err != nil {
		return err
	}
	if m.Status != "suspended" {
		return conflict("%s is %s, not suspended", handle, m.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.st.SetMemberStatus(m.ID, "active"); err != nil {
		return err
	}
	s.st.Audit(a.String(), "member.resume", handle, "")
	return s.applyPolicy(ctx)
}

type KickReport struct {
	Devices   int   `json:"devices_removed"`
	Keys      int   `json:"keys_revoked"`
	Invites   int   `json:"invites_revoked"`
	NamesHeld int   `json:"names_held"`
	HeldUntil int64 `json:"held_until"`
}

// Kick ends a membership. Order matters: mark removed and drop from policy
// first (instant cut-off), then delete their devices from the mesh.
func (s *Service) Kick(ctx context.Context, a Actor, handle, reason string) (*KickReport, error) {
	m, err := s.member(handle)
	if err != nil {
		return nil, err
	}
	if err := canRemove(a, m); err != nil {
		return nil, err
	}
	if m.Status == "removed" {
		return nil, conflict("%s has already been removed", handle)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := &KickReport{}

	// 1. From now on the registrar refuses them everything.
	if err := s.st.SetMemberStatus(m.ID, "removed"); err != nil {
		return nil, err
	}
	// 2. Cut them out of the access policy straight away.
	if err := s.applyPolicy(ctx); err != nil {
		log.Printf("kick %s: policy: %v", handle, err)
	}
	// 3. Unused device keys and invites they minted.
	rep.Keys = s.revokeOpenKeys(ctx, m.ID, "kick "+handle)
	n, err := s.st.RevokeOpenInvitesBy(m.ID)
	if err != nil {
		log.Printf("kick %s: revoke invites: %v", handle, err)
	}
	rep.Invites = int(n)
	// 4. Delete every device they own, personal and server.
	devs, err := s.st.MemberDevices(m.ID)
	if err != nil {
		log.Printf("kick %s: list devices: %v", handle, err)
	}
	for _, d := range devs {
		if err := s.hs.DeleteNode(ctx, d.HSNodeID); err != nil {
			log.Printf("kick %s: delete node %s: %v (sync will retry)", handle, d.HSNodeID, err)
			continue
		}
		_ = s.st.MarkDeviceRemoved(d.ID)
		rep.Devices++
	}
	// 5. Their Headscale user. Fails harmlessly if a device deletion failed; sync retries the devices.
	if err := s.hs.DeleteUser(ctx, m.HSUserID); err != nil {
		log.Printf("kick %s: delete user: %v", handle, err)
	}
	// 6. Withdraw their names and hold them so nobody can impersonate their sites.
	rep.HeldUntil = time.Now().Add(s.cfg.NameHold).Unix()
	held, err := s.st.HoldNames(m.ID, rep.HeldUntil)
	if err != nil {
		log.Printf("kick %s: hold names: %v", handle, err)
	}
	rep.NamesHeld = int(held)
	if err := s.writeZone(); err != nil {
		log.Printf("kick %s: zone: %v", handle, err)
	}
	// 7. Audit.
	detail, _ := json.Marshal(rep)
	if reason != "" {
		detail = append(detail, []byte(" reason: "+reason)...)
	}
	s.st.Audit(a.String(), "member.kick", handle, string(detail))
	return rep, nil
}

// --------------------------------------------------------------- invites --

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "hmi_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

type MintedInvite struct {
	*Invite
	Token string `json:"token"`
	URL   string `json:"url"`
}

func (s *Service) MintInvite(a Actor, role, note string, ttl time.Duration) (*MintedInvite, error) {
	if role == "" {
		role = "member"
	}
	switch {
	case role != "member" && role != "admin":
		return nil, bad("invites can be for members or admins")
	case role == "admin" && !a.IsOwner():
		return nil, forbidden("only the owner can invite admins")
	case !a.IsAdmin() && !s.cfg.MembersCanInvite:
		return nil, forbidden("on this network only admins can invite")
	}
	if !a.CLI && a.Member.Status != "active" {
		return nil, forbidden("your membership is %s", a.Member.Status)
	}
	if ttl <= 0 {
		ttl = s.cfg.InviteTTL
	}
	if ttl > 30*24*time.Hour {
		return nil, bad("invites can last at most 30 days")
	}
	if len(note) > s.cfg.MaxInviteNoteLen {
		return nil, bad("invite note must be at most %d characters", s.cfg.MaxInviteNoteLen)
	}
	if !a.IsAdmin() && a.memberID() != nil {
		n, err := s.st.CountOpenInvites(*a.memberID())
		if err != nil {
			return nil, err
		}
		if n >= s.cfg.MaxOpenInvites {
			return nil, conflict("too many open invites")
		}
	}
	tok := newToken()
	inv := &Invite{MintedBy: a.memberID(), Role: role, Note: note, CreatedAt: now(), ExpiresAt: time.Now().Add(ttl).Unix()}
	if err := s.st.InsertInvite(hashToken(tok), inv); err != nil {
		return nil, err
	}
	s.st.Audit(a.String(), "invite.mint", fmt.Sprintf("invite#%d", inv.ID), "role="+role)
	return &MintedInvite{Invite: inv, Token: tok, URL: s.InviteLink(tok)}, nil
}

func (s *Service) RevokeInvite(a Actor, id int64) error {
	inv, err := s.st.InviteByID(id)
	if errors.Is(err, ErrNotFound) {
		return missing("no invite %d", id)
	} else if err != nil {
		return err
	}
	mine := inv.MintedBy != nil && a.memberID() != nil && *inv.MintedBy == *a.memberID()
	if !a.IsAdmin() && !mine {
		return forbidden("not your invite")
	}
	if inv.State() != "open" {
		return conflict("invite %d is %s", id, inv.State())
	}
	if err := s.st.RevokeInvite(id); err != nil {
		return err
	}
	s.st.Audit(a.String(), "invite.revoke", fmt.Sprintf("invite#%d", id), "")
	return nil
}

type Enrolment struct {
	Handle          string `json:"handle"`
	Zone            string `json:"zone"`
	LoginServer     string `json:"login_server"`
	AuthKey         string `json:"auth_key"`
	AuthKeyExpires  int64  `json:"auth_key_expires"`
	RootCA          string `json:"root_ca"`
	RootFingerprint string `json:"root_fingerprint"`
	Portal          string `json:"portal"`
}

// Redeem turns an invite into a membership plus a key for the first device.
// This is the only operation reachable from the public internet.
func (s *Service) Redeem(ctx context.Context, token, handle string) (*Enrolment, error) {
	tok := strings.TrimSpace(token)
	if !strings.HasPrefix(tok, "hmi_") {
		return nil, forbidden("invite not valid")
	}
	hash := hashToken(tok)
	inv, err := s.st.InviteByHash(hash)
	if errors.Is(err, ErrNotFound) {
		return nil, forbidden("invite not valid")
	} else if err != nil {
		return nil, err
	}
	if st := inv.State(); st != "open" {
		return nil, forbidden("invite %s", st)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	inv, err = s.st.InviteByHash(hash)
	if errors.Is(err, ErrNotFound) {
		return nil, forbidden("invite not valid")
	} else if err != nil {
		return nil, err
	}
	if st := inv.State(); st != "open" {
		return nil, forbidden("invite %s", st)
	}
	if inv.MintedBy != nil {
		if minter, err := s.st.MemberByID(*inv.MintedBy); err != nil || minter.Status != "active" {
			return nil, forbidden("invite not valid")
		}
	}
	m, err := s.createMember(ctx, handle, inv.Role, inv.MintedBy)
	if err != nil {
		return nil, err
	}
	if ok, err := s.st.ClaimInvite(inv.ID, m.ID); err != nil || !ok {
		if derr := s.st.DeleteMember(m.ID); derr != nil {
			log.Printf("redeem rollback member %d: %v", m.ID, derr)
		}
		if herr := s.hs.DeleteUser(ctx, m.HSUserID); herr != nil {
			log.Printf("redeem rollback headscale user %s: %v", m.HSUserID, herr)
		}
		return nil, forbidden("invite not valid")
	}
	key, exp, err := s.issueKey(ctx, m, "personal")
	if err != nil {
		if uerr := s.st.UnclaimInvite(inv.ID, m.ID); uerr != nil {
			log.Printf("redeem rollback invite %d: %v", inv.ID, uerr)
		}
		if derr := s.st.DeleteMember(m.ID); derr != nil {
			log.Printf("redeem rollback member %d: %v", m.ID, derr)
		}
		if herr := s.hs.DeleteUser(ctx, m.HSUserID); herr != nil {
			log.Printf("redeem rollback headscale user %s: %v", m.HSUserID, herr)
		}
		return nil, err
	}
	s.st.Audit(handle, "invite.redeem", fmt.Sprintf("invite#%d", inv.ID), "")
	return &Enrolment{
		Handle: handle, Zone: s.cfg.Zone, LoginServer: s.LoginServer(),
		AuthKey: key, AuthKeyExpires: exp, RootCA: s.rootPEM, RootFingerprint: s.rootFP,
		Portal: "https://home." + s.cfg.Zone,
	}, nil
}

// --------------------------------------------------------------- devices --

func (s *Service) IssueDeviceKey(ctx context.Context, a Actor, handle, kind string) (string, int64, error) {
	m, err := s.member(handle)
	if err != nil {
		return "", 0, err
	}
	if !a.Is(m) {
		if !a.IsAdmin() {
			return "", 0, forbidden("you can only add your own devices")
		}
		if (m.Role == "owner" || m.Role == "admin") && !a.IsOwner() {
			return "", 0, forbidden("only the owner can add devices for an owner or admin")
		}
	}
	if m.Status != "active" {
		return "", 0, conflict("%s is %s", handle, m.Status)
	}
	if kind != "personal" && kind != "server" {
		return "", 0, bad("kind must be personal or server")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !a.CLI {
		open, err := s.st.CountOpenDeviceKeys(m.ID)
		if err != nil {
			return "", 0, err
		}
		if open >= s.cfg.MaxOpenDeviceKeys {
			return "", 0, conflict("too many unused device keys; wait for existing keys to be used or expire")
		}
	}
	key, exp, err := s.issueKey(ctx, m, kind)
	if err == nil {
		s.st.Audit(a.String(), "device.key", handle, kind)
	}
	return key, exp, err
}

func (s *Service) issueKey(ctx context.Context, m *Member, kind string) (string, int64, error) {
	var k *HSPreAuthKey
	var err error
	if kind == "server" {
		k, err = s.hs.CreateKey(ctx, "", []string{"tag:server"}, s.cfg.DeviceKeyTTL)
	} else {
		k, err = s.hs.CreateKey(ctx, m.HSUserID, nil, s.cfg.DeviceKeyTTL)
	}
	if err != nil {
		return "", 0, err
	}
	dk := &DeviceKey{MemberID: m.ID, Kind: kind, HSKeyID: k.ID, ExpiresAt: time.Now().Add(s.cfg.DeviceKeyTTL).Unix()}
	if err := s.st.InsertDeviceKey(dk); err != nil {
		_ = s.hs.ExpireKey(ctx, k.ID)
		return "", 0, err
	}
	return k.Key, dk.ExpiresAt, nil
}

func (s *Service) RemoveDevice(ctx context.Context, a Actor, id int64) error {
	d, err := s.st.DeviceByID(id)
	if errors.Is(err, ErrNotFound) || (err == nil && d.RemovedAt != nil) {
		return missing("no device %d", id)
	} else if err != nil {
		return err
	}
	owner, err := s.st.MemberByID(d.MemberID)
	if err != nil {
		return err
	}
	if !a.Is(owner) {
		if !a.IsAdmin() {
			return forbidden("not your device")
		}
		if (owner.Role == "owner" || owner.Role == "admin") && !a.IsOwner() {
			return forbidden("only the owner can remove devices of an owner or admin")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.hs.DeleteNode(ctx, d.HSNodeID); err != nil {
		return err
	}
	if err := s.st.MarkDeviceRemoved(d.ID); err != nil {
		return err
	}
	s.st.Audit(a.String(), "device.remove", fmt.Sprintf("%s/%s#%d", owner.Handle, d.Name, d.ID), "")
	if err := s.applyPolicy(ctx); err != nil {
		return err
	}
	return s.writeZone()
}

// WhoIs maps a mesh source address to the device and member behind it.
func (s *Service) WhoIs(ip string) (*Member, *Device, error) {
	d, err := s.st.DeviceByIP(ip)
	if err != nil {
		return nil, nil, err
	}
	m, err := s.st.MemberByID(d.MemberID)
	return m, d, err
}

func nodeMatchesDevice(nodes []HSNode, nodeID string, addr netip.Addr) bool {
	for _, n := range nodes {
		if n.ID != nodeID {
			continue
		}
		for _, raw := range n.IPAddresses {
			if parsed, err := netip.ParseAddr(raw); err == nil && parsed == addr {
				return true
			}
		}
	}
	return false
}

// VerifyLiveCaller maps a mesh source IP to an enrolled device and verifies
// against Headscale that the exact Headscale node still owns that IP. If a
// node left and Headscale reassigned its IP before the periodic Sync tick,
// VerifyLiveCaller refreshes the ledger once and re-checks.
func (s *Service) VerifyLiveCaller(ctx context.Context, src string) (*Member, *Device, error) {
	addr, err := netip.ParseAddr(src)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	canon := addr.String()
	m, d, err := s.WhoIs(canon)
	if err != nil {
		return nil, nil, err
	}
	nodes, err := s.hs.Nodes(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("verify caller: %w", err)
	}
	if nodeMatchesDevice(nodes, d.HSNodeID, addr) {
		return m, d, nil
	}
	if err := s.Sync(ctx); err != nil {
		return nil, nil, err
	}
	m, d, err = s.WhoIs(canon)
	if err != nil {
		return nil, nil, err
	}
	nodes, err = s.hs.Nodes(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("verify caller: %w", err)
	}
	if !nodeMatchesDevice(nodes, d.HSNodeID, addr) {
		return nil, nil, ErrNotFound
	}
	return m, d, nil
}

// ----------------------------------------------------------------- names --

func (s *Service) Claim(a Actor, handle, rawName string, deviceID int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.member(handle)
	if err != nil {
		return "", err
	}
	if !a.Is(m) {
		if !a.IsAdmin() {
			return "", forbidden("you can only claim names for yourself")
		}
		if (m.Role == "owner" || m.Role == "admin") && !a.IsOwner() {
			return "", forbidden("only the owner can claim names for an owner or admin")
		}
	}
	if m.Status != "active" {
		return "", conflict("%s is %s", handle, m.Status)
	}
	name, err := s.normaliseName(rawName)
	if err != nil {
		return "", err
	}
	existing, err := s.st.NameByName(name)
	if err == nil {
		if existing.HeldUntil != nil && *existing.HeldUntil > now() && !a.IsOwner() {
			return "", conflict("%s is held until %s", name, time.Unix(*existing.HeldUntil, 0).UTC().Format("2006-01-02"))
		}
		if existing.HeldUntil == nil && existing.MemberID != m.ID && !a.IsOwner() {
			return "", conflict("%s belongs to %s", name, existing.Member)
		}
	} else if !errors.Is(err, ErrNotFound) {
		return "", err
	} else {
		existing = nil
	}
	if !a.IsOwner() && (existing == nil || existing.MemberID != m.ID || existing.HeldUntil != nil) {
		count, err := s.st.CountMemberNames(m.ID)
		if err != nil {
			return "", err
		}
		if count >= s.cfg.MaxNamesPerMember {
			return "", conflict("too many names claimed")
		}
	}
	if top := topLabel(name); top != name {
		parent, err := s.st.NameByName(top)
		if err != nil || parent.MemberID != m.ID || parent.HeldUntil != nil {
			return "", forbidden("claim %s first; names under it belong to whoever owns it", top)
		}
	}
	d, err := s.st.DeviceByID(deviceID)
	if err != nil || d.RemovedAt != nil || d.MemberID != m.ID {
		return "", bad("device %d is not one of %s's devices", deviceID, handle)
	}
	if d.Kind != "server" {
		return "", bad("device %d is a personal device; names point at servers (personal devices accept no connections)", deviceID)
	}
	if existing != nil && existing.MemberID != m.ID && topLabel(name) == name {
		all, err := s.st.Names()
		if err != nil {
			return "", err
		}
		for _, x := range all {
			if strings.HasSuffix(x.Name, "."+name) && x.MemberID != m.ID {
				if err := s.st.DeleteName(x.Name); err != nil {
					return "", err
				}
			}
		}
	}
	if err := s.st.UpsertName(name, m.ID, &d.ID); err != nil {
		return "", err
	}
	s.st.Audit(a.String(), "name.claim", name+"."+s.cfg.Zone, fmt.Sprintf("member=%s device=%d", handle, d.ID))
	return name + "." + s.cfg.Zone, s.writeZone()
}

// Release frees a name and everything under it.
func (s *Service) Release(a Actor, rawName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rawName)), "."), "."+s.cfg.Zone)
	n, err := s.st.NameByName(name)
	if errors.Is(err, ErrNotFound) {
		return missing("%s is not claimed", name)
	} else if err != nil {
		return err
	}
	if n.HeldUntil != nil && *n.HeldUntil > now() && !a.IsOwner() {
		return forbidden("only the owner can release a held name")
	}
	if !a.IsOwner() {
		owner, err := s.st.MemberByID(n.MemberID)
		if err != nil {
			return err
		}
		switch {
		case a.Member != nil && a.Member.ID == n.MemberID && n.HeldUntil == nil:
			// members and admins may release their own active names
		case a.IsAdmin() && owner.Role == "member" && n.HeldUntil == nil:
			// admins may release regular members' active names
		case a.IsAdmin():
			return forbidden("only the owner can release names belonging to an owner or admin")
		default:
			return forbidden("%s is not yours", name)
		}
	}
	all, _ := s.st.Names()
	for _, x := range all {
		if x.Name == name || strings.HasSuffix(x.Name, "."+name) {
			_ = s.st.DeleteName(x.Name)
		}
	}
	s.st.Audit(a.String(), "name.release", name+"."+s.cfg.Zone, "")
	return s.writeZone()
}

// ---------------------------------------------------------- sync, policy --

// Sync reconciles Headscale with the ledger: records devices that joined with
// keys we issued, notices devices that disappeared, finishes interrupted
// removals, then rewrites the access policy and DNS zone if they changed.
func (s *Service) Sync(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	nodes, err := s.hs.Nodes(ctx)
	if err != nil {
		return err
	}
	keys, err := s.st.PendingDeviceKeys(now() - 86400)
	if err != nil {
		return err
	}
	live, err := s.st.LiveDevices()
	if err != nil {
		return err
	}
	byNode := map[string]*Device{}
	for _, d := range live {
		byNode[d.HSNodeID] = d
	}
	members := map[int64]*Member{}
	memberOf := func(id int64) *Member {
		if m, ok := members[id]; ok {
			return m
		}
		m, _ := s.st.MemberByID(id)
		members[id] = m
		return m
	}

	seen := map[string]bool{}
	for _, n := range nodes {
		seen[n.ID] = true
		if n.HasTag("tag:infra") {
			continue
		}
		v4, v6 := splitIPs(n.IPAddresses)
		name := n.GivenName
		if name == "" {
			name = n.Name
		}
		if d, ok := byNode[n.ID]; ok {
			if m := memberOf(d.MemberID); m != nil && m.Status == "removed" {
				s.deleteStray(ctx, n, d, "member removed")
				continue
			}
			if d.IPv4 != v4 || d.IPv6 != v6 || d.Name != name {
				_ = s.st.UpdateDevice(d.ID, name, v4, v6)
			}
			continue
		}
		var k *DeviceKey
		if n.PreAuthKey != nil {
			k = keys[n.PreAuthKey.ID]
		}
		if k == nil {
			if !s.orphans[n.ID] {
				log.Printf("node %s (%s) was not enrolled through the registrar; it gets no access", n.ID, name)
				s.orphans[n.ID] = true
			}
			continue
		}
		m := memberOf(k.MemberID)
		if m == nil || m.Status == "removed" || k.RevokedAt != nil {
			s.deleteStray(ctx, n, nil, "key revoked or member removed")
			continue
		}
		d := &Device{MemberID: k.MemberID, Kind: k.Kind, HSNodeID: n.ID, Name: name, IPv4: v4, IPv6: v6}
		if err := s.st.InsertDevice(d); err != nil {
			return err
		}
		_ = s.st.MarkDeviceKeyUsed(k.ID)
		s.st.Audit("registrar", "device.join", fmt.Sprintf("%s/%s#%d", m.Handle, name, d.ID), k.Kind+" "+v4)
	}
	for _, d := range live {
		if !seen[d.HSNodeID] {
			_ = s.st.MarkDeviceRemoved(d.ID)
			s.st.Audit("registrar", "device.gone", fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID), "no longer in headscale")
		}
	}
	if err := s.applyPolicy(ctx); err != nil {
		return err
	}
	return s.writeZone()
}

func (s *Service) deleteStray(ctx context.Context, n HSNode, d *Device, why string) {
	if err := s.hs.DeleteNode(ctx, n.ID); err != nil {
		log.Printf("delete node %s (%s): %v", n.ID, why, err)
		return
	}
	if d != nil {
		_ = s.st.MarkDeviceRemoved(d.ID)
	}
	s.st.Audit("registrar", "device.reject", n.ID+" "+n.GivenName, why)
}

func splitIPs(ips []string) (v4, v6 string) {
	for _, s := range ips {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if a.Is4() && v4 == "" {
			v4 = a.String()
		} else if a.Is6() && v6 == "" {
			v6 = a.String()
		}
	}
	return
}

// buildPolicy is the default-deny policy of DESIGN.md section 8, expressed
// over the addresses of devices whose members are active. Suspended and
// removed members' devices appear nowhere, so they can reach nothing.
func (s *Service) buildPolicy() (string, error) {
	live, err := s.st.LiveDevices()
	if err != nil {
		return "", err
	}
	status := map[int64]string{}
	ms, err := s.st.Members()
	if err != nil {
		return "", err
	}
	for _, m := range ms {
		status[m.ID] = m.Status
	}
	src := []string{}
	servers := []string{}
	for _, d := range live {
		if status[d.MemberID] != "active" {
			continue
		}
		for _, ip := range []string{d.IPv4, d.IPv6} {
			if ip == "" {
				continue
			}
			src = append(src, ip)
			if d.Kind == "server" {
				servers = append(servers, ip)
			}
		}
	}
	sort.Strings(src)
	sort.Strings(servers)
	src = append(src, "tag:infra") // the CA validates certs on servers; the portal on itself

	type grant struct {
		Src []string `json:"src"`
		Dst []string `json:"dst"`
		IP  []string `json:"ip"`
	}
	grants := []grant{{Src: src, Dst: []string{"tag:infra"}, IP: []string{"53", "80", "443"}}}
	if len(servers) > 0 {
		grants = append(grants, grant{Src: src, Dst: servers, IP: []string{"*"}})
	}
	pol := map[string]any{
		"tagOwners": map[string][]string{"tag:infra": {}, "tag:server": {}},
		"grants":    grants,
	}
	b, err := json.MarshalIndent(pol, "", "  ")
	return string(b), err
}

func (s *Service) applyPolicy(ctx context.Context) error {
	pol, err := s.buildPolicy()
	if err != nil {
		return err
	}
	if pol == s.lastPolicy {
		return nil
	}
	if err := s.hs.SetPolicy(ctx, pol); err != nil {
		return fmt.Errorf("set policy: %w", err)
	}
	s.lastPolicy = pol
	return nil
}

// writeZone renders the network's DNS zone from claimed names. CoreDNS
// reloads it when the serial changes.
func (s *Service) writeZone() error {
	names, err := s.st.ResolvableNames()
	if err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "$TTL 60\n")
	fmt.Fprintf(&b, "@     IN NS  ns.%s.\n", s.cfg.Zone)
	fmt.Fprintf(&b, "; core services\n")
	fmt.Fprintf(&b, "ns    IN A   %s\n", s.cfg.CoreIP)
	fmt.Fprintf(&b, "home  IN A   %s\n", s.cfg.CoreIP)
	fmt.Fprintf(&b, "ca    IN A   %s\n", s.cfg.CAIP)
	fmt.Fprintf(&b, "; member names (written by the registrar)\n")
	for _, n := range names {
		if n.IPv4 != "" {
			fmt.Fprintf(&b, "%s IN A %s ; %s\n", n.Name, n.IPv4, n.Member)
		}
		if n.IPv6 != "" {
			fmt.Fprintf(&b, "%s IN AAAA %s ; %s\n", n.Name, n.IPv6, n.Member)
		}
	}
	body := b.String()
	if body == s.lastZone {
		return nil
	}
	// CoreDNS reloads only when the serial grows, so never reuse one, even if
	// two writes (server and CLI) land in the same second.
	serial := time.Now().Unix()
	if old, err := os.ReadFile(s.cfg.ZoneFile); err == nil {
		if m := serialRE.FindSubmatch(old); m != nil {
			var cur int64
			fmt.Sscan(string(m[1]), &cur)
			if serial <= cur {
				serial = cur + 1
			}
		}
	}
	head := fmt.Sprintf("$ORIGIN %s.\n@     IN SOA ns.%s. owner.%s. ( %d 3600 600 86400 60 )\n",
		s.cfg.Zone, s.cfg.Zone, s.cfg.Zone, serial)
	f, err := os.CreateTemp(filepath.Dir(s.cfg.ZoneFile), ".db.zone.*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.WriteString(head + body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.cfg.ZoneFile); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	s.lastZone = body
	return nil
}
