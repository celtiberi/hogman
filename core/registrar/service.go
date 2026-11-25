package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"tailscale.com/types/key"
)

const (
	defaultMaxMembers             = 500
	defaultMaxDevices             = 500
	defaultMaxOpenDeviceKeys      = 3
	defaultMaxAdminOpenDeviceKeys = 10
	// Extra personal-device slots above MaxDevices reserved strictly for active
	// owners so an owner can replace or add a personal device to manage the pen
	// even when the pen is at MAX_DEVICES (D-16).
	ownerDeviceReserve = 2
)

func addDeviceReserve(maxDevices int) int {
	if maxDevices <= 0 {
		return 0
	}
	if maxDevices > math.MaxInt-ownerDeviceReserve {
		return math.MaxInt
	}
	return maxDevices + ownerDeviceReserve
}

type Config struct {
	Zone                    string // bobo.pens.hogman.network
	PublicHost              string // control server hostname
	CoreIP                  string // mesh IP of the core node (DNS, portal)
	Theme                   string // optional UI theme: "" (default) or "work"
	InviteTTL               time.Duration
	DeviceKeyTTL            time.Duration
	MembersCanInvite        bool
	BillingStatusPath       string
	MaxMembers              int
	MaxDevices              int
	MaxOpenDeviceKeys       int
	MaxAdminOpenDeviceKeys  int
	MaxNamesPerMember       int
	MaxOpenInvites          int
	MaxInviteNoteLen        int
	MaxServerEABPerDay      int
	MaxMemberEABPerDay      int
	MaxMemberACMETXTPerHour int
	PresenceTTL             time.Duration
	ACMEBackend             ACMEBackend
}

// normaliseTheme validates the pen UI theme against the strict allowlist.
// Empty or "default" resolves to "" (omitted in JSON); only "work" is set.
func normaliseTheme(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "default":
		return "", nil
	case "work":
		return "work", nil
	default:
		return "", fmt.Errorf("unknown theme %q (want default or work)", raw)
	}
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
	Status     int
	Msg        string
	RetryAfter int // optional seconds for Retry-After response header
}

func (p *Problem) Error() string { return p.Msg }

func bad(f string, a ...any) error       { return &Problem{Status: 400, Msg: fmt.Sprintf(f, a...)} }
func forbidden(f string, a ...any) error { return &Problem{Status: 403, Msg: fmt.Sprintf(f, a...)} }
func missing(f string, a ...any) error   { return &Problem{Status: 404, Msg: fmt.Sprintf(f, a...)} }
func conflict(f string, a ...any) error  { return &Problem{Status: 409, Msg: fmt.Sprintf(f, a...)} }

const (
	inlineSyncCooldown = 3 * time.Second
	keyRotateCooldown  = 10 * time.Second
	keyRotateMaxConc   = 4
	syncFlightTimeout  = 30 * time.Second
	presenceTimeout    = 15 * time.Second
)

type syncCall struct {
	done chan struct{}
	err  error
}

type rotateCall struct {
	done chan struct{}
	err  error
}

type presenceCall struct {
	done  chan struct{}
	nodes map[string]HSNode
}

type Service struct {
	cfg  Config
	st   *Store
	hs   *Headscale
	acme ACMEBackend

	mu               sync.Mutex // serialises changes that touch Headscale or policy
	lastPolicy       string
	orphans          map[string]bool
	missingMKAlerted map[string]bool

	baseCtxMu    sync.RWMutex
	baseCtx      context.Context
	bgMu         sync.Mutex
	shuttingDown bool
	bgWG         sync.WaitGroup

	syncMu            sync.Mutex
	syncFlight        *syncCall
	lastSyncAt        time.Time
	lastSyncAttemptAt time.Time
	lastRenewOnly     bool
	syncedOnce        bool

	// Per-device single-flight, cooldown, and bounded concurrency for
	// single-node Headscale verification on WireGuard node key rotation.
	rotateMu       sync.Mutex
	rotateCooldown map[string]time.Time
	rotateFlight   map[string]*rotateCall
	rotateSem      chan struct{}

	// Display-only node presence snapshot (GET /api/directory and
	// GET /api/admin/devices). No authorization, identity, or ACL policy
	// decision may ever read this snapshot.
	presenceMu        sync.RWMutex
	presenceByID      map[string]HSNode
	presenceAt        time.Time
	presenceAttemptAt time.Time
	presenceFlight    *presenceCall

	deferredDelMu      sync.Mutex
	deferredPendingDel map[int64]bool

	acmeMu         sync.Mutex
	serverEABHits  map[int64][]time.Time
	memberEABHits  map[int64][]time.Time
	memberTXTHits  map[int64][]time.Time
	nowFn          func() time.Time
	privateLabelFn func() (string, error)
}

func (s *Service) SetBaseContext(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.baseCtxMu.Lock()
	s.baseCtx = ctx
	s.baseCtxMu.Unlock()
}

func (s *Service) baseContext() context.Context {
	s.baseCtxMu.RLock()
	ctx := s.baseCtx
	s.baseCtxMu.RUnlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// BeginShutdown prevents new detached background workers from spawning so
// WaitBackground can drain in-flight jobs without racing bgWG.Add against Wait.
func (s *Service) BeginShutdown() {
	s.bgMu.Lock()
	s.shuttingDown = true
	s.bgMu.Unlock()
}

func (s *Service) startBackground(fn func()) bool {
	s.bgMu.Lock()
	if s.shuttingDown {
		s.bgMu.Unlock()
		return false
	}
	s.bgWG.Add(1)
	s.bgMu.Unlock()
	go func() {
		defer s.bgWG.Done()
		fn()
	}()
	return true
}

// WaitBackground waits for detached Sync, PresenceSnapshot, key-rotation, and
// self-delete workers to finish (or until ctx expires) before closing SQLite.
func (s *Service) WaitBackground(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		s.bgWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (s *Service) clock() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

// checkWindow prunes expired entries for key and reports whether another hit is
// permitted without recording one (so failed upstream calls do not burn budget).
func checkWindow(m map[int64][]time.Time, key int64, limit int, window time.Duration, ts time.Time) (bool, int) {
	if limit <= 0 {
		return true, 0
	}
	prev := m[key]
	kept := prev[:0]
	for _, t := range prev {
		if ts.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	m[key] = kept
	if len(kept) >= limit {
		rem := kept[0].Add(window).Sub(ts)
		secs := int((rem + time.Second - 1) / time.Second)
		if secs < 1 {
			secs = 1
		}
		return false, secs
	}
	return true, 0
}

func recordWindow(m map[int64][]time.Time, key int64, ts time.Time) {
	m[key] = append(m[key], ts)
}

func NewService(cfg Config, st *Store, hs *Headscale) (*Service, error) {
	theme, err := normaliseTheme(cfg.Theme)
	if err != nil {
		return nil, err
	}
	cfg.Theme = theme
	if cfg.MaxMembers <= 0 {
		cfg.MaxMembers = defaultMaxMembers
	}
	if cfg.MaxDevices <= 0 {
		cfg.MaxDevices = defaultMaxDevices
	}
	if cfg.MaxOpenDeviceKeys <= 0 {
		cfg.MaxOpenDeviceKeys = defaultMaxOpenDeviceKeys
	}
	if cfg.MaxAdminOpenDeviceKeys <= 0 {
		cfg.MaxAdminOpenDeviceKeys = defaultMaxAdminOpenDeviceKeys
	}
	if cfg.MaxAdminOpenDeviceKeys < cfg.MaxOpenDeviceKeys {
		cfg.MaxAdminOpenDeviceKeys = cfg.MaxOpenDeviceKeys
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
	if cfg.MaxServerEABPerDay <= 0 {
		cfg.MaxServerEABPerDay = 2
	}
	if cfg.MaxMemberEABPerDay <= 0 {
		cfg.MaxMemberEABPerDay = 4
	}
	if cfg.MaxMemberACMETXTPerHour <= 0 {
		cfg.MaxMemberACMETXTPerHour = 60
	}
	if cfg.PresenceTTL <= 0 {
		cfg.PresenceTTL = 5 * time.Second
	}
	return &Service{
		cfg:              cfg,
		st:               st,
		hs:               hs,
		acme:             cfg.ACMEBackend,
		orphans:          map[string]bool{},
		missingMKAlerted: map[string]bool{},
		baseCtx:          context.Background(),
		rotateCooldown:   map[string]time.Time{},
		rotateFlight:       map[string]*rotateCall{},
		rotateSem:          make(chan struct{}, keyRotateMaxConc),
		deferredPendingDel: map[int64]bool{},
		serverEABHits:      map[int64][]time.Time{},
		memberEABHits:    map[int64][]time.Time{},
		memberTXTHits:    map[int64][]time.Time{},
	}, nil
}

func (s *Service) LoginServer() string { return "https://" + s.cfg.PublicHost }

type NetworkInfo struct {
	Zone        string `json:"zone"`
	LoginServer string `json:"login_server"`
	CertMode    string `json:"cert_mode"`
	Portal      string `json:"portal"`
	// Mesh address of the pen's DNS server. Only reachable from inside the
	// mesh; side-by-side clients resolve pen names through it.
	DNSServer string `json:"dns_server"`
	// Optional UI theme for join-page and portal ("work"); omitted when default.
	Theme string `json:"theme,omitempty"`
}

func (s *Service) NetworkInfo() NetworkInfo {
	return NetworkInfo{
		Zone:        s.cfg.Zone,
		LoginServer: s.LoginServer(),
		CertMode:    "public",
		Portal:      "https://home." + s.cfg.Zone,
		DNSServer:   s.cfg.CoreIP,
		Theme:       s.cfg.Theme,
	}
}

// Links handed to people. The part after # never reaches any server: the
// join page and join tool read it locally.
//
//	invite: https://<host>/join#t=<invite token>
//	device: https://<host>/join#k=<device key>
func (s *Service) InviteLink(token string) string {
	return fmt.Sprintf("https://%s/join#t=%s", s.cfg.PublicHost, token)
}

// DeviceLink is the one-time link for a device key. A server key's link is
// marked for=share: server links only put things in the pen with
// `hogman share`, they don't join a whole computer (D-11).
func (s *Service) DeviceLink(key, kind string) string {
	link := fmt.Sprintf("https://%s/join#k=%s", s.cfg.PublicHost, key)
	if kind == "server" {
		link += "&for=share"
	}
	return link
}

// ------------------------------------------------------------- validation --

var (
	handleRE          = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	labelRE           = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reservedNSLabelRE = regexp.MustCompile(`^ns[0-9]*$`)
	reserved          = map[string]bool{"home": true, "ns": true, "registrar": true,
		"search": true, "nodes": true, "www": true, "join": true, "admin": true}
	validRoles = map[string]bool{"owner": true, "admin": true, "member": true}
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
		if l == "_acme-challenge" || reservedNSLabelRE.MatchString(l) {
			return "", forbidden("%q is reserved by the network", l)
		}
		if !labelRE.MatchString(l) {
			return "", bad("name %q: labels are letters, digits and dashes", raw)
		}
	}
	if reserved[labels[len(labels)-1]] {
		return "", forbidden("%q is reserved by the network", labels[len(labels)-1])
	}
	return n, nil
}

// refreshActorLocked reloads a non-CLI actor from SQLite under s.mu so racing
// kicks, suspensions, or role demotions take effect before authorizing mutations.
func (s *Service) refreshActorLocked(a Actor) (Actor, error) {
	if a.CLI {
		return a, nil
	}
	if a.Member == nil {
		return Actor{}, forbidden("not authenticated")
	}
	m, err := s.st.MemberByID(a.Member.ID)
	if err != nil {
		return Actor{}, forbidden("membership not found")
	}
	if m.Status != "active" {
		return Actor{}, forbidden("membership %s", m.Status)
	}
	return Actor{Member: m}, nil
}

// RefreshActor reloads a non-CLI actor from SQLite under s.mu so endpoints
// that authorize privileged actions outside Service methods (e.g. token minting)
// never act on stale role or status snapshots.
func (s *Service) RefreshActor(a Actor) (Actor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshActorLocked(a)
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
	if !validRoles[role] {
		return nil, bad("role must be owner, admin or member")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return nil, err
	}
	if !a.IsAdmin() {
		return nil, forbidden("only admins can add members directly")
	}
	if role != "member" && !a.IsOwner() {
		return nil, forbidden("only the owner can create admins or owners")
	}
	maxMembers := s.cfg.MaxMembers
	if a.CLI {
		maxMembers = 0 // operator CLI override (D-16)
	}
	if unlock, lockErr := s.st.lockMemberFile(); lockErr == nil {
		defer unlock()
	} else {
		log.Printf("member lock: %v", lockErr)
	}
	m, err := s.createMember(ctx, handle, role, a.memberID(), maxMembers)
	if err != nil {
		if errors.Is(err, ErrMemberCapReached) {
			return nil, conflict("this network has reached its member limit (%d)", s.cfg.MaxMembers)
		}
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

func (s *Service) createMember(ctx context.Context, handle, role string, invitedBy *int64, maxMembers int) (*Member, error) {
	if !handleRE.MatchString(handle) {
		return nil, bad("handle must be 2-32 lowercase letters, digits or dashes, starting with a letter")
	}
	if _, err := s.st.MemberByHandle(handle); err == nil {
		return nil, conflict("handle %q is taken", handle)
	}
	if maxMembers > 0 {
		count, err := s.st.CountActiveMembers()
		if err != nil {
			return nil, err
		}
		if count >= maxMembers {
			return nil, ErrMemberCapReached
		}
	}
	u, err := s.hs.EnsureUser(ctx, handle)
	if err != nil {
		return nil, err
	}
	m := &Member{Handle: handle, Role: role, Status: "active", InvitedBy: invitedBy, HSUserID: u.ID}
	if err := s.st.InsertMemberCapped(m, maxMembers); err != nil {
		if errors.Is(err, ErrMemberCapReached) {
			rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			if herr := s.hs.DeleteUser(rbCtx, u.ID); herr != nil {
				log.Printf("createMember cap rollback headscale user %s: %v", u.ID, herr)
			}
			rbCancel()
		}
		return nil, err
	}
	return m, nil
}

func (s *Service) SetRole(ctx context.Context, a Actor, handle, role string) error {
	if !validRoles[role] {
		return bad("role must be owner, admin or member")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
	if !a.IsOwner() {
		return forbidden("only the owner can change roles")
	}
	m, err := s.member(handle)
	if err != nil {
		return err
	}
	if m.Status == "removed" {
		return conflict("%s has been removed", handle)
	}
	if m.Role == "owner" && role != "owner" {
		ok, err := s.st.DemoteOwner(m.ID, role)
		if err != nil {
			return err
		}
		if !ok {
			return conflict("%s is the only owner", handle)
		}
	} else if err := s.st.SetMemberRole(m.ID, role); err != nil {
		return err
	}
	s.st.Audit(a.String(), "member.role", handle, m.Role+" -> "+role)
	// Invites carry their maker's authority. When that shrinks, the invites
	// they left open go too (Redeem also re-checks the maker's role).
	if roleRank[role] < roleRank[m.Role] {
		if n, err := s.st.RevokeOpenInvitesBy(m.ID); err == nil && n > 0 {
			s.st.Audit(a.String(), "invite.revoke", handle, fmt.Sprintf("%d open, after role change", n))
		}
	}
	// In renew_only mode, policy depends on owner/admin role membership.
	if s.isRenewOnly() {
		return s.applyPolicy(ctx)
	}
	return nil
}

var roleRank = map[string]int{"member": 0, "admin": 1, "owner": 2}

// mayMint reports whether a member, as they are now, may hand out an invite
// for this role. MintInvite applies the same rules when the invite is made.
func (s *Service) mayMint(m *Member, role string) bool {
	switch role {
	case "admin":
		return m.Role == "owner"
	case "member":
		return m.Role == "owner" || m.Role == "admin" || s.cfg.MembersCanInvite
	}
	return false
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
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
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
	if err := s.st.SetMemberStatus(m.ID, "suspended"); err != nil {
		return err
	}
	s.revokeOpenKeys(ctx, m.ID, "suspend "+handle)
	s.st.Audit(a.String(), "member.suspend", handle, reason)
	return s.applyPolicy(ctx) // their devices drop out of every grant
}

func (s *Service) Resume(ctx context.Context, a Actor, handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
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
	if err := s.st.SetMemberStatus(m.ID, "active"); err != nil {
		return err
	}
	s.st.Audit(a.String(), "member.resume", handle, "")
	return s.applyPolicy(ctx)
}

type KickReport struct {
	Devices      int `json:"devices_removed"`
	Keys         int `json:"keys_revoked"`
	Invites      int `json:"invites_revoked"`
	NamesRetired int `json:"names_retired"`
}

// Kick ends a membership. Order matters: mark removed and drop from policy
// first (instant cut-off), then delete their devices from the mesh.
func (s *Service) Kick(ctx context.Context, a Actor, handle, reason string) (*KickReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return nil, err
	}
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
	if m.HSUserID != "" {
		if err := s.hs.DeleteUser(ctx, m.HSUserID); err == nil || isHSNotFound(err) {
			_ = s.st.ClearMemberHSUserID(m.ID)
		} else {
			log.Printf("kick %s: delete user: %v", handle, err)
		}
	}
	// 6. Withdraw their names and retire them permanently so nobody can impersonate their sites.
	retired, err := s.st.RetireNames(m.ID)
	if err != nil {
		log.Printf("kick %s: retire names: %v", handle, err)
	}
	rep.NamesRetired = int(retired)
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

func cleanInviteNote(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r == '\r' || r == '\n' || r == '\t' || r == '\u2028' || r == '\u2029':
			b.WriteByte(' ')
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			continue
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func (s *Service) MintInvite(a Actor, role, note string, ttl time.Duration) (*MintedInvite, error) {
	if role == "" {
		role = "member"
	}
	if role != "member" && role != "admin" {
		return nil, bad("invites can be for members or admins")
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
	note = cleanInviteNote(note)
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return nil, err
	}
	switch {
	case role == "admin" && !a.IsOwner():
		return nil, forbidden("only the owner can invite admins")
	case !a.IsAdmin() && !s.cfg.MembersCanInvite:
		return nil, forbidden("on this network only admins can invite")
	}
	if !a.CLI {
		count, err := s.st.CountActiveMembers()
		if err != nil {
			return nil, err
		}
		if count >= s.cfg.MaxMembers {
			return nil, conflict("this network has reached its member limit (%d)", s.cfg.MaxMembers)
		}
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
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
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
	Handle         string `json:"handle"`
	Zone           string `json:"zone"`
	LoginServer    string `json:"login_server"`
	AuthKey        string `json:"auth_key"`
	AuthKeyExpires int64  `json:"auth_key_expires"`
	Portal         string `json:"portal"`
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
		minter, err := s.st.MemberByID(*inv.MintedBy)
		if err != nil || minter.Status != "active" || !s.mayMint(minter, inv.Role) {
			return nil, forbidden("invite not valid")
		}
	}
	// Check pen-wide caps only AFTER invite & minter validation so callers
	// without a valid open invite cannot probe pen fullness. Never leak counts
	// or which cap was hit on this public endpoint.
	const redeemFullMsg = "this network cannot accept new members right now"
	if count, err := s.st.CountActiveMembers(); err != nil {
		return nil, err
	} else if count >= s.cfg.MaxMembers {
		return nil, conflict(redeemFullMsg)
	}
	if live, openKeys, err := s.st.CountDeviceSlots(); err != nil {
		return nil, err
	} else if live+openKeys >= s.cfg.MaxDevices {
		return nil, conflict(redeemFullMsg)
	}

	// Serialize Headscale user creation/rollback across serve and CLI processes
	// so a cap-rollback DeleteUser can never delete a user adopted by a concurrent add.
	if unlock, lockErr := s.st.lockMemberFile(); lockErr == nil {
		defer unlock()
	} else {
		log.Printf("member lock: %v", lockErr)
	}

	m, err := s.createMember(ctx, handle, inv.Role, inv.MintedBy, s.cfg.MaxMembers)
	if err != nil {
		if errors.Is(err, ErrMemberCapReached) {
			return nil, conflict(redeemFullMsg)
		}
		return nil, err
	}
	if ok, err := s.st.ClaimInvite(inv.ID, m.ID); err != nil || !ok {
		rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		if herr := s.hs.DeleteUser(rbCtx, m.HSUserID); herr != nil {
			log.Printf("redeem rollback headscale user %s: %v", m.HSUserID, herr)
		}
		rbCancel()
		if derr := s.st.DeleteMember(m.ID); derr != nil {
			log.Printf("redeem rollback member %d: %v", m.ID, derr)
		}
		return nil, forbidden("invite not valid")
	}
	key, exp, err := s.issueKeyCapped(ctx, m, "personal", s.cfg.MaxDevices, 0, 0, false)
	if err != nil {
		// Delete Headscale user BEFORE removing the SQLite member row (while
		// still holding lockMemberFile) so no concurrent CLI member add can
		// adopt m.HSUserID before DeleteUser runs.
		rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		if herr := s.hs.DeleteUser(rbCtx, m.HSUserID); herr != nil {
			log.Printf("redeem rollback headscale user %s: %v", m.HSUserID, herr)
		}
		rbCancel()
		if rerr := s.st.RollbackRedeem(inv.ID, m.ID); rerr != nil {
			log.Printf("redeem rollback invite %d / member %d: %v", inv.ID, m.ID, rerr)
		}
		if errors.Is(err, ErrDeviceCapReached) {
			return nil, conflict(redeemFullMsg)
		}
		return nil, err
	}
	s.st.Audit(handle, "invite.redeem", fmt.Sprintf("invite#%d", inv.ID), "")
	return &Enrolment{
		Handle: handle, Zone: s.cfg.Zone, LoginServer: s.LoginServer(),
		AuthKey: key, AuthKeyExpires: exp,
		Portal: "https://home." + s.cfg.Zone,
	}, nil
}

// --------------------------------------------------------------- devices --

func (s *Service) IssueDeviceKey(ctx context.Context, a Actor, handle, kind string) (string, int64, error) {
	if kind != "personal" && kind != "server" {
		return "", 0, bad("kind must be personal or server")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return "", 0, err
	}
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
		// No account recovery (D-16): a personal key joins a device as that
		// member, so nobody makes one for someone else. The one exception is
		// the server's own tool giving a member their very first device, which
		// is how a new pen's owner gets in. Anyone who has ever joined and
		// loses every device starts again with a new invite.
		if kind == "personal" {
			if !a.CLI {
				return "", 0, forbidden("you can only add your own devices")
			}
			joined, err := s.st.HasJoined(m.ID)
			if err != nil {
				return "", 0, err
			}
			if joined {
				return "", 0, forbidden("%s has already joined a device, and there is no account recovery: invite them again as a new member", handle)
			}
		}
	}
	if m.Status != "active" {
		return "", 0, conflict("%s is %s", handle, m.Status)
	}
	maxOpen := 0
	maxDevices := 0
	ownerFloor := 0
	bypassCap := a.CLI
	if !a.CLI {
		maxOpen = s.cfg.MaxOpenDeviceKeys
		if a.IsAdmin() {
			maxOpen = s.cfg.MaxAdminOpenDeviceKeys
			if maxOpen < s.cfg.MaxOpenDeviceKeys {
				maxOpen = s.cfg.MaxOpenDeviceKeys
			}
		}
		maxDevices = s.cfg.MaxDevices
		if m.Role == "owner" && kind == "personal" {
			maxDevices = addDeviceReserve(s.cfg.MaxDevices)
			ownerFloor = ownerDeviceReserve
		}
		// Fast pre-checks before creating a Headscale pre-auth key; atomic
		// enforcement runs inside InsertDeviceKeyCapped (BEGIN IMMEDIATE).
		open, err := s.st.CountOpenDeviceKeys(m.ID)
		if err != nil {
			return "", 0, err
		}
		if open >= maxOpen {
			return "", 0, conflict("too many unused device keys; wait for existing keys to be used or expire")
		}
		live, totalOpen, err := s.st.CountDeviceSlots()
		if err != nil {
			return "", 0, err
		}
		if live+totalOpen >= maxDevices {
			allowedByFloor := false
			if ownerFloor > 0 {
				if ownerSlots, oerr := s.st.CountMemberPersonalSlots(m.ID); oerr == nil && ownerSlots < ownerFloor {
					allowedByFloor = true
				}
			}
			if !allowedByFloor {
				return "", 0, conflict("this network has reached its device limit (%d)", s.cfg.MaxDevices)
			}
		}
	}
	key, exp, err := s.issueKeyCapped(ctx, m, kind, maxDevices, maxOpen, ownerFloor, bypassCap)
	if err != nil {
		switch {
		case errors.Is(err, ErrOpenKeyCapReached):
			return "", 0, conflict("too many unused device keys; wait for existing keys to be used or expire")
		case errors.Is(err, ErrDeviceCapReached):
			return "", 0, conflict("this network has reached its device limit (%d)", s.cfg.MaxDevices)
		default:
			return "", 0, err
		}
	}
	s.st.Audit(a.String(), "device.key", handle, kind)
	return key, exp, nil
}

func (s *Service) issueKeyCapped(ctx context.Context, m *Member, kind string, maxDevices, maxOpenForMember, ownerPersonalFloor int, bypassCap bool) (string, int64, error) {
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
	dk := &DeviceKey{
		MemberID:  m.ID,
		Kind:      kind,
		HSKeyID:   k.ID,
		ExpiresAt: time.Now().Add(s.cfg.DeviceKeyTTL).Unix(),
		BypassCap: bypassCap,
	}
	if err := s.st.InsertDeviceKeyCapped(dk, maxDevices, maxOpenForMember, ownerPersonalFloor); err != nil {
		rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = s.hs.ExpireKey(rbCtx, k.ID)
		rbCancel()
		return "", 0, err
	}
	return k.Key, dk.ExpiresAt, nil
}

const (
	removeDeviceTimeout        = 30 * time.Second
	removeDeviceCleanupTimeout = 15 * time.Second
)

func (s *Service) RemoveDevice(ctx context.Context, a Actor, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Bail immediately if the caller already disconnected or timed out while
	// waiting on s.mu (prevents cancelled non-self delete bursts from piling up
	// Headscale calls under s.mu).
	if err := ctx.Err(); err != nil {
		return err
	}
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
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
	// Derive the Headscale DeleteNode timeout AFTER acquiring s.mu so waiting
	// behind a long Sync() does not starve Headscale, while still honoring caller
	// ctx cancellation for synchronous non-self deletes.
	opCtx, cancel := context.WithTimeout(ctx, removeDeviceTimeout)
	defer cancel()
	if err := s.hs.DeleteNode(opCtx, d.HSNodeID); err != nil {
		return err
	}
	// Once Headscale deleted the node, finish SQLite cleanup and policy push on
	// a detached lifecycle context so a late caller disconnect cannot split-brain
	// SQLite/Headscale state or leak leaf DNS names.
	cleanupCtx, cleanupCancel := context.WithTimeout(s.baseContext(), removeDeviceCleanupTimeout)
	defer cleanupCancel()
	// Removing a device on purpose gives back the leaf names it served (a share's
	// name, say), so they aren't stuck, while preserving parent names that still
	// have subdomains on other devices. A kick holds names instead (Kick).
	if err := s.st.DeleteNamesOfDevice(d.ID); err != nil {
		return err
	}
	if err := s.st.MarkDeviceRemoved(d.ID); err != nil {
		return err
	}
	s.st.Audit(a.String(), "device.remove", fmt.Sprintf("%s/%s#%d", owner.Handle, d.Name, d.ID), "")
	return s.applyPolicy(cleanupCtx)
}

// SelfRemoveDevice commits an authenticated device's own removal durably in
// SQLite BEFORE the HTTP handler answers 202 Accepted (no Headscale call and
// no s.mu wait), then kicks off best-effort background Headscale DeleteNode +
// SetPolicy cleanup. Because removed_at, leaf-name release, policy_gen bump,
// and hs_delete_pending = 1 are committed first, portal auth and /api/me deny
// immediately and syncOnce() durably converges both Headscale node deletion
// and ACL policy across mutex contention, Headscale outages, or restarts (I-34).
func (s *Service) SelfRemoveDevice(a Actor, id int64) error {
	if a.CLI || a.Member == nil {
		return forbidden("not a member device")
	}
	d, err := s.st.CommitSelfDelete(a.Member.ID, id, a.String())
	if err != nil {
		return err
	}
	// Best-effort fast path: delete from Headscale and push policy promptly.
	// If shutting down (startBackground returns false) or Headscale is briefly
	// unavailable, durable hs_delete_pending + dirty policy_gen guarantee
	// syncOnce() finishes cleanup automatically.
	s.startBackground(func() {
		s.finishSelfDelete(d.ID, d.HSNodeID)
	})
	return nil
}

type pendingDeleteAction int

const (
	pendingDeleteProceed pendingDeleteAction = iota
	pendingDeleteSkipClear
	pendingDeleteDefer
)

// verifyPendingDeleteTarget checks whether a Headscale node still matches a
// removed device row before deleting it, preventing node-ID reuse from ever
// deleting a different machine, a live re-enrolled device, or tag:infra.
func verifyPendingDeleteTarget(d *Device, n HSNode, liveDev *Device) (pendingDeleteAction, string) {
	if n.HasTag("tag:infra") {
		return pendingDeleteSkipClear, "headscale node is tag:infra"
	}
	if liveDev != nil && liveDev.ID != d.ID {
		return pendingDeleteSkipClear, fmt.Sprintf("hs_node_id belongs to live device #%d", liveDev.ID)
	}
	dMachKey, dHasMK := canonicalMachineKey(d.MachineKey)
	if d.MachineKey != "" && !dHasMK {
		return pendingDeleteDefer, "unparseable stored machine_key"
	}
	nMachKey, nHasMK := canonicalMachineKey(n.MachineKey)
	if dHasMK && nHasMK && dMachKey != nMachKey {
		return pendingDeleteSkipClear, "headscale node machine_key mismatch"
	}
	if dHasMK && !nHasMK {
		return pendingDeleteDefer, "headscale missing machine_key"
	}
	return pendingDeleteProceed, ""
}

func (s *Service) finishSelfDelete(id int64, hsNodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	opCtx, cancel := context.WithTimeout(s.baseContext(), removeDeviceTimeout)
	defer cancel()
	if opCtx.Err() != nil {
		return
	}
	// Re-check durable hs_delete_pending after acquiring s.mu: syncOnce may
	// already have deleted the node or cleared pending after a machineKey mismatch.
	pending, err := s.st.DeviceHSDeletePending(id)
	if err != nil {
		log.Printf("self-delete device #%d: check hs_delete_pending: %v", id, err)
	} else if !pending {
		if err := s.applyPolicy(opCtx); err != nil {
			log.Printf("self-delete device #%d: policy push failed (will retry in sync): %v", id, err)
		}
		return
	}
	d, derr := s.st.DeviceByID(id)
	if derr != nil {
		log.Printf("self-delete device #%d: reload row: %v", id, derr)
		return
	}
	var liveDev *Device
	if ld, lerr := s.st.DeviceByHSNodeID(hsNodeID); lerr == nil {
		liveDev = ld
	}
	if liveDev != nil && liveDev.ID != d.ID {
		log.Printf("self-delete device #%d (%s): ALERT skipping delete: hs_node_id belongs to live device #%d", d.ID, hsNodeID, liveDev.ID)
		s.st.Audit("registrar", "device.delete_skip", fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID), fmt.Sprintf("hs_node_id belongs to live device #%d", liveDev.ID))
		_ = s.st.ClearDeviceHSDeletePending(d.ID)
	} else if n, nerr := s.hs.Node(opCtx, hsNodeID); isHSNotFound(nerr) {
		if err := s.st.ClearDeviceHSDeletePending(id); err != nil {
			log.Printf("self-delete device #%d: clear hs_delete_pending: %v", id, err)
		}
	} else if nerr != nil {
		log.Printf("self-delete device #%d (%s): verify node failed (will retry in sync): %v", id, hsNodeID, nerr)
	} else {
		action, reason := verifyPendingDeleteTarget(d, *n, liveDev)
		switch action {
		case pendingDeleteSkipClear:
			log.Printf("self-delete device #%d (%s): ALERT skipping delete: %s", d.ID, hsNodeID, reason)
			s.st.Audit("registrar", "device.delete_skip", fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID), reason)
			_ = s.st.ClearDeviceHSDeletePending(d.ID)
		case pendingDeleteDefer:
			log.Printf("self-delete device #%d (%s): ALERT deferring delete (will retry in sync): %s", d.ID, hsNodeID, reason)
		case pendingDeleteProceed:
			if err := s.hs.DeleteNode(opCtx, hsNodeID); err != nil {
				log.Printf("self-delete device #%d (%s): headscale delete failed (will retry in sync): %v", id, hsNodeID, err)
			} else if err := s.st.ClearDeviceHSDeletePending(id); err != nil {
				log.Printf("self-delete device #%d: clear hs_delete_pending: %v", id, err)
			}
		}
	}
	if err := s.applyPolicy(opCtx); err != nil {
		log.Printf("self-delete device #%d: policy push failed (will retry in sync): %v", id, err)
	}
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

func isTaggedPseudoUser(u *HSUser) bool {
	return u == nil || u.ID == "" || (u.ID == headscaleTaggedUserID && u.Name == headscaleTaggedUserName)
}

// nodeMatchesBinding verifies that a Headscale node's tag/user ownership still
// matches the device's enrolled role in SQLite. Server devices must carry
// tag:server (never tag:infra) with no real user; personal devices must carry
// no tags and belong to the member's Headscale user ID.
func nodeMatchesBinding(m *Member, d *Device, n *HSNode) bool {
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

func nodeMatchesAddr(n *HSNode, addr netip.Addr) bool {
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

// canTriggerInlineSync bounds sequential inline Sync() calls triggered by
// unknown peers when an open device key exists, including across Headscale errors.
func (s *Service) canTriggerInlineSync() bool {
	s.syncMu.Lock()
	last := s.lastSyncAttemptAt
	s.syncMu.Unlock()
	if last.IsZero() {
		return true
	}
	return s.clock().Sub(last) >= inlineSyncCooldown
}

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
func (s *Service) VerifyDirectPeer(ctx context.Context, peer *PeerIdentity) (*Member, *Device, error) {
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

	d, err := s.st.DeviceByHSNodeID(peer.HSNodeID)
	if errors.Is(err, ErrNotFound) {
		// Only trigger a cooldown-gated, single-flight Sync when an open device
		// key could explain a newly enrolled device racing ahead of the poll.
		if open, kerr := s.st.HasOpenDeviceKeys(); kerr == nil && open && s.canTriggerInlineSync() {
			if serr := s.Sync(ctx); serr != nil {
				log.Printf("auth: inline sync failed for unknown node %s: %v", peer.HSNodeID, serr)
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
		log.Printf("auth: node %s (%s) missing or invalid pinned node_key/machine_key; refusing", d.HSNodeID, d.Name)
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
func (s *Service) verifyAndRotateNodeKey(ctx context.Context, hsNodeID, peerNodeKey string, addr netip.Addr, canon string) (*Member, *Device, error) {
	nowT := s.clock()
	s.rotateMu.Lock()
	call := s.rotateFlight[hsNodeID]
	if call == nil {
		if prev, ok := s.rotateCooldown[hsNodeID]; ok && nowT.Sub(prev) < keyRotateCooldown {
			s.rotateMu.Unlock()
			log.Printf("auth: node %s WhoIs node key mismatch (rate-limited)", hsNodeID)
			return nil, nil, ErrNotFound
		}
		select {
		case s.rotateSem <- struct{}{}:
		default:
			s.rotateMu.Unlock()
			log.Printf("auth: node %s WhoIs node key mismatch (concurrency cap reached)", hsNodeID)
			return nil, nil, ErrNotFound
		}
		if len(s.rotateCooldown) >= 256 {
			for k, ts := range s.rotateCooldown {
				if nowT.Sub(ts) >= keyRotateCooldown {
					delete(s.rotateCooldown, k)
				}
			}
		}
		s.rotateCooldown[hsNodeID] = nowT
		call = &rotateCall{done: make(chan struct{})}
		s.rotateFlight[hsNodeID] = call
		started := s.startBackground(func() {
			workCtx, cancel := context.WithTimeout(s.baseContext(), 15*time.Second)
			n, hsErr := s.hs.Node(workCtx, hsNodeID)
			cancel()
			<-s.rotateSem

			var rerr error
			if hsErr != nil {
				log.Printf("auth: node %s key-rotation verify failed: %v", hsNodeID, hsErr)
				rerr = ErrNotFound
			} else {
				rerr = s.commitNodeKeyRotation(hsNodeID, n, addr, canon)
			}

			s.rotateMu.Lock()
			call.err = rerr
			close(call.done)
			delete(s.rotateFlight, hsNodeID)
			s.rotateMu.Unlock()
		})
		if !started {
			<-s.rotateSem
			delete(s.rotateFlight, hsNodeID)
			s.rotateMu.Unlock()
			return nil, nil, ErrNotFound
		}
	}
	s.rotateMu.Unlock()

	select {
	case <-call.done:
		if call.err != nil {
			return nil, nil, call.err
		}
	case <-ctx.Done():
		return nil, nil, ctx.Err()
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

func (s *Service) commitNodeKeyRotation(hsNodeID string, n *HSNode, addr netip.Addr, canon string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
		log.Printf("auth: ALERT node %s (%s) machine_key mismatch on key rotation (stored=%q headscale=%q)", d.HSNodeID, d.Name, storedMachKey, n.MachineKey)
		return ErrNotFound
	}
	if !nodeMatchesBinding(m, d, n) {
		log.Printf("auth: ALERT node %s (%s) owner/tag binding mismatch on key rotation", d.HSNodeID, d.Name)
		return ErrNotFound
	}
	hsNodeKey, okHSNK := canonicalNodeKey(n.NodeKey)
	if !nodeMatchesAddr(n, addr) || !okHSNK {
		log.Printf("auth: node %s (%s) WhoIs node key/IP mismatch against Headscale", d.HSNodeID, d.Name)
		return ErrNotFound
	}
	if storedNodeKey == hsNodeKey {
		// Already rotated (e.g. by a concurrent syncOnce) or Headscale still holds
		// the old key; caller verifies canonicalNodeKey(d.NodeKey) == peerNodeKey after waking.
		return nil
	}
	rotated, err := s.st.RotateDeviceNodeKey(d.ID, d.NodeKey, d.MachineKey, hsNodeKey)
	if err != nil {
		return err
	}
	if !rotated {
		log.Printf("auth: node %s (%s) conditional key rotation lost race (device removed, member inactive, or changed)", d.HSNodeID, d.Name)
		return ErrNotFound
	}
	s.st.Audit("registrar", "device.key_rotate", fmt.Sprintf("%s/%s#%d", m.Handle, d.Name, d.ID), "")
	return nil
}

// VerifyLiveCaller maps a mesh source IP to an enrolled device and verifies
// against Headscale (single-node GET /api/v1/node/{id}) that the exact
// Headscale node still owns that IP. Used ONLY by the legacy test/migration
// MeshHandler (REGISTRAR_LEGACY_MESH_SOCKET=1); production embedded tsnet uses
// VerifyDirectPeer.
func (s *Service) VerifyLiveCaller(ctx context.Context, src string) (*Member, *Device, error) {
	addr, err := netip.ParseAddr(src)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return nil, nil, ErrNotFound
	}
	canon := addr.String()
	m, d, err := s.WhoIs(canon)
	if err != nil {
		return nil, nil, err
	}
	if m.Status != "active" {
		return nil, nil, forbidden("membership %s", m.Status)
	}
	node, err := s.hs.Node(ctx, d.HSNodeID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, nil, fmt.Errorf("verify caller: %w", err)
	}
	if nodeMatchesAddr(node, addr) {
		return m, d, nil
	}
	if err := s.Sync(ctx); err != nil {
		return nil, nil, err
	}
	m, d, err = s.WhoIs(canon)
	if err != nil {
		return nil, nil, err
	}
	if m.Status != "active" {
		return nil, nil, forbidden("membership %s", m.Status)
	}
	node, err = s.hs.Node(ctx, d.HSNodeID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, nil, fmt.Errorf("verify caller: %w", err)
	}
	if !nodeMatchesAddr(node, addr) {
		return nil, nil, ErrNotFound
	}
	return m, d, nil
}

// PresenceSnapshot returns a display-only map of Headscale nodes indexed by
// node ID for UI online/last-seen badges (GET /api/directory and
// GET /api/admin/devices). No authorization, identity, or ACL policy decision
// may ever read this snapshot.
//
// Refreshes run under the service's shutdown-aware base context with a bounded
// timeout so a disconnecting HTTP client cannot poison the shared flight.
func (s *Service) PresenceSnapshot(ctx context.Context) map[string]HSNode {
	nowT := s.clock()
	s.presenceMu.RLock()
	if s.presenceByID != nil && !s.presenceAt.IsZero() && nowT.Sub(s.presenceAt) < s.cfg.PresenceTTL {
		snap := s.presenceByID
		s.presenceMu.RUnlock()
		return snap
	}
	if !s.presenceAttemptAt.IsZero() && nowT.Sub(s.presenceAttemptAt) < s.cfg.PresenceTTL {
		stale := s.presenceByID
		s.presenceMu.RUnlock()
		return stale
	}
	stale := s.presenceByID
	s.presenceMu.RUnlock()

	s.presenceMu.Lock()
	nowT = s.clock()
	if s.presenceByID != nil && !s.presenceAt.IsZero() && nowT.Sub(s.presenceAt) < s.cfg.PresenceTTL {
		snap := s.presenceByID
		s.presenceMu.Unlock()
		return snap
	}
	if !s.presenceAttemptAt.IsZero() && nowT.Sub(s.presenceAttemptAt) < s.cfg.PresenceTTL {
		stale = s.presenceByID
		s.presenceMu.Unlock()
		return stale
	}
	call := s.presenceFlight
	if call == nil {
		call = &presenceCall{done: make(chan struct{})}
		s.presenceFlight = call
		started := s.startBackground(func() {
			workCtx, cancel := context.WithTimeout(s.baseContext(), presenceTimeout)
			defer cancel()
			nodes, err := s.hs.Nodes(workCtx)
			var snap map[string]HSNode
			if err == nil {
				snap = indexNodesByID(nodes)
			}
			ts := s.clock()
			s.presenceMu.Lock()
			s.presenceAttemptAt = ts
			if err == nil {
				s.presenceByID = snap
				s.presenceAt = ts
				call.nodes = snap
			} else {
				call.nodes = s.presenceByID
			}
			close(call.done)
			s.presenceFlight = nil
			s.presenceMu.Unlock()
		})
		if !started {
			s.presenceFlight = nil
			s.presenceMu.Unlock()
			return stale
		}
	}
	s.presenceMu.Unlock()

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

func (s *Service) setPresence(nodes []HSNode) {
	snap := indexNodesByID(nodes)
	ts := s.clock()
	s.presenceMu.Lock()
	s.presenceByID = snap
	s.presenceAt = ts
	s.presenceAttemptAt = ts
	s.presenceMu.Unlock()
}

// ----------------------------------------------------------------- names --

const maxNameNoteRunes = 140

// cleanNameNote turns a site description into a single plain-text line capped at
// 140 runes, replacing line/tab breaks with spaces and dropping control chars.
func cleanNameNote(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r == '\r' || r == '\n' || r == '\t' || r == '\u2028' || r == '\u2029':
			b.WriteByte(' ')
		case unicode.IsControl(r):
			continue
		default:
			b.WriteRune(r)
		}
	}
	collapsed := strings.Join(strings.Fields(b.String()), " ")
	runes := []rune(collapsed)
	if len(runes) > maxNameNoteRunes {
		return strings.TrimRight(string(runes[:maxNameNoteRunes]), " ")
	}
	return collapsed
}

const (
	privateLabelLen         = 12
	maxPrivateLabelAttempts = 8
	privateLabelFirstChars  = "abcdefghijklmnopqrstuvwxyz"
	privateLabelRestChars   = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// generatePrivateLabel returns a 12-character random DNS label starting with a
// lowercase letter followed by 11 lowercase letters or digits (~61.6 bits).
func generatePrivateLabel() (string, error) {
	var b strings.Builder
	b.Grow(privateLabelLen)
	firstMax := big.NewInt(int64(len(privateLabelFirstChars)))
	restMax := big.NewInt(int64(len(privateLabelRestChars)))
	n, err := rand.Int(rand.Reader, firstMax)
	if err != nil {
		return "", fmt.Errorf("generate private label: %w", err)
	}
	b.WriteByte(privateLabelFirstChars[n.Int64()])
	for i := 1; i < privateLabelLen; i++ {
		n, err := rand.Int(rand.Reader, restMax)
		if err != nil {
			return "", fmt.Errorf("generate private label: %w", err)
		}
		b.WriteByte(privateLabelRestChars[n.Int64()])
	}
	return b.String(), nil
}

// allocatePrivateLabelLocked (s.mu held) picks a random label not present in
// names (active or retired) and not reserved. Fails cleanly after 8 collisions.
func (s *Service) allocatePrivateLabelLocked() (string, error) {
	gen := s.privateLabelFn
	if gen == nil {
		gen = generatePrivateLabel
	}
	all, err := s.st.Names()
	if err != nil {
		return "", err
	}
	used := make(map[string]struct{}, len(all))
	for _, x := range all {
		used[x.Name] = struct{}{}
		used[topLabel(x.Name)] = struct{}{}
	}
	for attempt := 0; attempt < maxPrivateLabelAttempts; attempt++ {
		cand, err := gen()
		if err != nil {
			return "", err
		}
		name, err := s.normaliseName(cand)
		if err != nil || topLabel(name) != name {
			continue
		}
		if _, exists := used[name]; exists {
			continue
		}
		return name, nil
	}
	return "", &Problem{Status: 503, Msg: fmt.Sprintf("could not allocate a unique private name after %d attempts", maxPrivateLabelAttempts)}
}

func (s *Service) Claim(a Actor, handle, rawName string, deviceID int64, note *string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.claimLocked(a, handle, rawName, deviceID, note, nil, false)
}

// ClaimPrivate allocates a random private label for a server device owned by handle.
func (s *Service) ClaimPrivate(a Actor, handle string, deviceID int64, note *string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.claimLocked(a, handle, "", deviceID, note, nil, true)
}

// ServerClaim is a server naming itself (what `hogman share` does). The
// checks run under s.mu together with the claim, so two servers can't race.
func (s *Service) ServerClaim(a Actor, d *Device, rawName string, note *string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.serverMayUse(d, rawName); err != nil {
		return "", err
	}
	return s.claimLocked(a, a.Member.Handle, rawName, d.ID, note, d, false)
}

// ServerClaimPrivate allocates a random private label for the calling server
// device. If this exact server device already owns a single active private name
// (e.g. crash right after claiming before writing share.json), returns that
// existing private name and updates its note if provided. Refuses if the server
// already owns a non-private name or multiple names.
func (s *Service) ServerClaimPrivate(a Actor, d *Device, note *string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return "", err
	}
	if d == nil || d.Kind != "server" {
		return "", forbidden("server devices only")
	}
	all, err := s.st.Names()
	if err != nil {
		return "", err
	}
	var owned []*Name
	for _, n := range all {
		if n.RetiredAt == nil && n.MemberID == d.MemberID && n.DeviceID != nil && *n.DeviceID == d.ID {
			owned = append(owned, n)
		}
	}
	if len(owned) == 1 && owned[0].Private {
		return s.claimLocked(a, a.Member.Handle, owned[0].Name, d.ID, note, d, false)
	}
	if len(owned) > 0 {
		return "", conflict("this server already has a claimed name; pass its existing name")
	}
	return s.claimLocked(a, a.Member.Handle, "", d.ID, note, d, true)
}

// claimLocked: s.mu held. server is the calling server device, or nil.
// When allocatePrivate is true, rawName must be empty and a fresh 12-char
// random label is allocated under s.mu and stored with private=1.
func (s *Service) claimLocked(a Actor, handle, rawName string, deviceID int64, rawNote *string, server *Device, allocatePrivate bool) (string, error) {
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return "", err
	}
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
	if allocatePrivate && strings.TrimSpace(rawName) != "" {
		return "", bad("cannot pass both a name and private: true")
	}

	var name string
	var existing *Name
	var d *Device
	if allocatePrivate {
		// Validate device and cap before allocating a random label.
		d, err = s.st.DeviceByID(deviceID)
		if err != nil || d.RemovedAt != nil || d.MemberID != m.ID {
			return "", bad("device %d is not one of %s's devices", deviceID, handle)
		}
		if d.Kind != "server" {
			return "", bad("device %d is a personal device; names point at servers (personal devices accept no connections)", deviceID)
		}
		if !a.IsOwner() || server != nil {
			count, err := s.st.CountMemberNames(m.ID)
			if err != nil {
				return "", err
			}
			if count >= s.cfg.MaxNamesPerMember {
				return "", conflict("too many names claimed")
			}
		}
		name, err = s.allocatePrivateLabelLocked()
		if err != nil {
			return "", err
		}
	} else {
		name, err = s.normaliseName(rawName)
		if err != nil {
			return "", err
		}
		existing, err = s.st.NameByName(name)
		if err == nil {
			if existing.RetiredAt != nil {
				return "", conflict("%s is retired and cannot be reused", name)
			}
			if existing.MemberID != m.ID && !a.IsOwner() {
				return "", conflict("%s belongs to %s", name, existing.Member)
			}
		} else if !errors.Is(err, ErrNotFound) {
			return "", err
		} else {
			existing = nil
		}
		// If claiming an unclaimed top-level name, refuse if another member (or a
		// retired record) already owns a subdomain under it.
		if existing == nil && topLabel(name) == name {
			all, err := s.st.Names()
			if err != nil {
				return "", err
			}
			for _, x := range all {
				if !strings.HasSuffix(x.Name, "."+name) {
					continue
				}
				if x.RetiredAt != nil {
					return "", conflict("%s has retired subdomains and cannot be reused", name)
				}
				if x.MemberID != m.ID && !a.IsOwner() {
					return "", conflict("%s has subdomains belonging to %s", name, x.Member)
				}
			}
		}
		// A server always counts against the cap, even the owner's: a leaked server
		// link must not be able to claim names without limit.
		if (!a.IsOwner() || server != nil) && (existing == nil || existing.MemberID != m.ID) {
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
			if err == nil && parent.RetiredAt != nil {
				return "", conflict("%s is retired and cannot be reused", top)
			}
			if err != nil || parent.MemberID != m.ID {
				return "", forbidden("claim %s first; names under it belong to whoever owns it", top)
			}
		}
		d, err = s.st.DeviceByID(deviceID)
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
				if strings.HasSuffix(x.Name, "."+name) && x.MemberID != m.ID && x.RetiredAt == nil {
					if err := s.st.DeleteName(x.Name); err != nil {
						return "", err
					}
				}
			}
		}
	}
	note := ""
	if rawNote != nil {
		note = cleanNameNote(*rawNote)
	} else if existing != nil && existing.RetiredAt == nil && existing.MemberID == m.ID {
		note = existing.Note
	}
	isPrivate := allocatePrivate || (existing != nil && existing.Private)
	if err := s.st.UpsertNameWithPrivate(name, m.ID, &d.ID, note, isPrivate); err != nil {
		return "", err
	}
	detail := fmt.Sprintf("member=%s device=%d", handle, d.ID)
	if isPrivate {
		detail += " private=true"
	}
	s.st.Audit(a.String(), "name.claim", name+"."+s.cfg.Zone, detail)
	return name + "." + s.cfg.Zone, nil
}

// serverMayUse (s.mu held): a server naming itself may take a name that is
// free or already points at it, never a retired name or one of its member's
// other names; and a name under another (x.blog) only if the parent points at
// it too, so one server can't squat under another's name.
func (s *Service) serverMayUse(d *Device, rawName string) error {
	name, err := s.normaliseName(rawName)
	if err != nil {
		return err
	}
	pointsHere := func(n *Name) bool {
		return n.MemberID == d.MemberID && n.RetiredAt == nil && n.DeviceID != nil && *n.DeviceID == d.ID
	}
	n, err := s.st.NameByName(name)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return err
	case n.RetiredAt != nil:
		return conflict("%s is retired and cannot be reused", name)
	case !pointsHere(n):
		return conflict("%s is already taken; pick another name", name)
	}
	if top := topLabel(name); top != name {
		p, err := s.st.NameByName(top)
		if err == nil && p.RetiredAt != nil {
			return conflict("%s is retired and cannot be reused", top)
		}
		if err != nil || !pointsHere(p) {
			return forbidden("%s belongs under %s, which doesn't point at this server", name, top)
		}
	}
	return nil
}

// serverOwnsName (s.mu held): a server may release a name only if it, and
// every name under it, points at that server.
func (s *Service) serverOwnsName(d *Device, rawName string) error {
	name, err := s.normaliseName(rawName)
	if err != nil {
		return err
	}
	all, err := s.st.Names()
	if err != nil {
		return err
	}
	found := false
	for _, x := range all {
		if x.Name != name && !strings.HasSuffix(x.Name, "."+name) {
			continue
		}
		if x.MemberID != d.MemberID || x.RetiredAt != nil || x.DeviceID == nil || *x.DeviceID != d.ID {
			return forbidden("%s does not point at this server", x.Name)
		}
		found = found || x.Name == name
	}
	if !found {
		return missing("%s is not claimed", name)
	}
	return nil
}

// serverOwnsACMEName (s.mu held) enforces strict active ownership for ACME
// DNS-01 challenges: the device must be a server and must currently own the
// normalized name (never unclaimed, retired, or reserved labels).
func (s *Service) serverOwnsACMEName(d *Device, rawName string) (string, error) {
	if d == nil || d.Kind != "server" {
		return "", forbidden("server devices only")
	}
	name, err := s.normaliseName(rawName)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(name, ".") {
		if l == "home" || l == "nodes" || reservedNSLabelRE.MatchString(l) || l == "_acme-challenge" {
			return "", forbidden("%q is reserved by the network", l)
		}
	}
	n, err := s.st.NameByName(name)
	if errors.Is(err, ErrNotFound) {
		return "", forbidden("%s must be claimed by this server first", name)
	}
	if err != nil {
		return "", err
	}
	if n.RetiredAt != nil || n.MemberID != d.MemberID || n.DeviceID == nil || *n.DeviceID != d.ID {
		return "", forbidden("%s does not point at this server", name)
	}
	return name, nil
}

// serverHasClaimedName (s.mu held) reports whether d owns at least one active claimed name.
func (s *Service) serverHasClaimedName(d *Device) (bool, error) {
	if d == nil || d.Kind != "server" {
		return false, nil
	}
	all, err := s.st.Names()
	if err != nil {
		return false, err
	}
	for _, n := range all {
		if n.RetiredAt == nil && n.MemberID == d.MemberID && n.DeviceID != nil && *n.DeviceID == d.ID {
			return true, nil
		}
	}
	return false, nil
}

// ServerSetACMETXT writes an ACME DNS-01 challenge TXT record for a name owned by d.
func (s *Service) ServerSetACMETXT(ctx context.Context, d *Device, rawName, value string) (string, error) {
	if s.acme == nil {
		return "", &Problem{Status: 503, Msg: "ACME challenge DNS is not configured"}
	}
	if !acmeTXTValueRE.MatchString(value) {
		return "", bad("invalid ACME TXT value")
	}
	s.mu.Lock()
	name, err := s.serverOwnsACMEName(d, rawName)
	s.mu.Unlock()
	if err != nil {
		return "", err
	}
	s.acmeMu.Lock()
	ok, retry := checkWindow(s.memberTXTHits, d.MemberID, s.cfg.MaxMemberACMETXTPerHour, time.Hour, s.clock())
	s.acmeMu.Unlock()
	if !ok {
		return "", &Problem{Status: 429, Msg: "too many ACME challenge writes for this member in the last hour", RetryAfter: retry}
	}
	fqdn := "_acme-challenge." + name + "." + s.cfg.Zone
	if err := s.acme.SetTXT(ctx, fqdn, value); err != nil {
		return "", err
	}
	s.acmeMu.Lock()
	recordWindow(s.memberTXTHits, d.MemberID, s.clock())
	s.acmeMu.Unlock()
	return fqdn, nil
}

// ServerDeleteACMETXT removes an ACME DNS-01 challenge TXT record for a name owned by d.
func (s *Service) ServerDeleteACMETXT(ctx context.Context, d *Device, rawName, value string) error {
	if s.acme == nil {
		return &Problem{Status: 503, Msg: "ACME challenge DNS is not configured"}
	}
	if !acmeTXTValueRE.MatchString(value) {
		return bad("invalid ACME TXT value")
	}
	s.mu.Lock()
	name, err := s.serverOwnsACMEName(d, rawName)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	fqdn := "_acme-challenge." + name + "." + s.cfg.Zone
	return s.acme.DeleteTXT(ctx, fqdn, value)
}

// ServerMintACMEEAB obtains one single-use fallback CA EAB pair for an enrolled
// server that currently owns at least one claimed name.
func (s *Service) ServerMintACMEEAB(ctx context.Context, d *Device) (*EABPair, error) {
	if d == nil || d.Kind != "server" {
		return nil, forbidden("server devices only")
	}
	if s.acme == nil {
		return nil, &Problem{Status: 503, Msg: "ACME challenge DNS is not configured"}
	}
	s.mu.Lock()
	hasName, err := s.serverHasClaimedName(d)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !hasName {
		return nil, forbidden("claim a name for this server first")
	}
	s.acmeMu.Lock()
	nowTS := s.clock()
	memberOK, memberRetry := checkWindow(s.memberEABHits, d.MemberID, s.cfg.MaxMemberEABPerDay, 24*time.Hour, nowTS)
	if !memberOK {
		s.acmeMu.Unlock()
		return nil, &Problem{Status: 429, Msg: "too many fallback account keys for this member today", RetryAfter: memberRetry}
	}
	serverOK, serverRetry := checkWindow(s.serverEABHits, d.ID, s.cfg.MaxServerEABPerDay, 24*time.Hour, nowTS)
	s.acmeMu.Unlock()
	if !serverOK {
		return nil, &Problem{Status: 429, Msg: "too many fallback account keys for this server today", RetryAfter: serverRetry}
	}
	pair, err := s.acme.MintEAB(ctx)
	if err != nil {
		return nil, err
	}
	s.acmeMu.Lock()
	recTS := s.clock()
	recordWindow(s.memberEABHits, d.MemberID, recTS)
	recordWindow(s.serverEABHits, d.ID, recTS)
	s.acmeMu.Unlock()
	s.st.Audit(d.Member, "acme.eab", fmt.Sprintf("device#%d", d.ID), "")
	return pair, nil
}

// Release frees a name and everything under it.
func (s *Service) Release(a Actor, rawName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.releaseLocked(a, rawName)
}

// ServerRelease is a server giving back a name that points only at it.
func (s *Service) ServerRelease(a Actor, d *Device, rawName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.serverOwnsName(d, rawName); err != nil {
		return err
	}
	return s.releaseLocked(a, rawName)
}

func (s *Service) releaseLocked(a Actor, rawName string) error {
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
	name := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rawName)), "."), "."+s.cfg.Zone)
	n, err := s.st.NameByName(name)
	if errors.Is(err, ErrNotFound) {
		return missing("%s is not claimed", name)
	} else if err != nil {
		return err
	}
	if n.RetiredAt != nil {
		return conflict("%s is retired and cannot be released", name)
	}
	canReleaseRow := func(row *Name) error {
		if a.IsOwner() {
			return nil
		}
		owner, err := s.st.MemberByID(row.MemberID)
		if err != nil {
			return err
		}
		switch {
		case a.Member != nil && a.Member.ID == row.MemberID:
			return nil
		case a.IsAdmin() && owner.Role == "member":
			return nil
		case a.IsAdmin():
			return forbidden("only the owner can release names belonging to an owner or admin")
		default:
			return forbidden("%s is not yours", row.Name)
		}
	}
	if err := canReleaseRow(n); err != nil {
		return err
	}
	all, err := s.st.Names()
	if err != nil {
		return err
	}
	var toRelease []*Name
	for _, x := range all {
		if x.RetiredAt != nil {
			continue
		}
		if x.Name == name || strings.HasSuffix(x.Name, "."+name) {
			if err := canReleaseRow(x); err != nil {
				return err
			}
			toRelease = append(toRelease, x)
		}
	}
	for _, x := range toRelease {
		if x.Private {
			// D-21: private random labels are permanently retired on release, never recycled.
			_ = s.st.RetireName(x.Name)
		} else {
			_ = s.st.DeleteName(x.Name)
		}
	}
	s.st.Audit(a.String(), "name.release", name+"."+s.cfg.Zone, "")
	return nil
}

// ---------------------------------------------------------- sync, policy --

// Sync reconciles Headscale with the ledger and is single-flight: overlapping
// callers share the in-flight pass instead of queuing duplicate Headscale API
// calls. The shared worker runs under the service's shutdown-aware base context
// with a 30s timeout so a disconnecting HTTP caller cannot poison the pass,
// while SIGTERM still cancels cleanly.
//
// Responsibilities and timing:
//   - Enrol newly joined devices (recording HSNodeID, WireGuard NodeKey, and
//     pinned MachineKey), mark their one-time device key used, and push the
//     updated ACL policy: fast interval (SYNC_INTERVAL, default 3s) while an
//     open device key exists, plus cooldown-gated inline Sync on miss.
//   - Retry interrupted Headscale user/node deletions for removed members
//     (including stray tag:server nodes with no Headscale user): fast interval
//     while pending cleanup exists.
//   - Retry any pending policy push after cross-process CLI mutations or
//     transient failures: tracked via SQLite trigger-bumped policy_gen > applied_gen.
//   - Reflect renew_only billing transitions in ACL policy: checked locally on
//     every fast tick and synced immediately on transition.
//   - Backfill missing node_key/machine_key on upgraded rows, update device
//     names/IPs, notice out-of-band headscale CLI deletions, and refresh the
//     display-only presence snapshot: idle interval (SYNC_IDLE_INTERVAL, 30s).
func (s *Service) Sync(ctx context.Context) error {
	s.syncMu.Lock()
	call := s.syncFlight
	if call == nil {
		call = &syncCall{done: make(chan struct{})}
		s.syncFlight = call
		started := s.startBackground(func() {
			workCtx, cancel := context.WithTimeout(s.baseContext(), syncFlightTimeout)
			defer cancel()
			renewOnly, err := s.syncOnce(workCtx)
			ts := s.clock()
			s.syncMu.Lock()
			call.err = err
			s.lastSyncAttemptAt = ts
			if err == nil {
				s.lastSyncAt = ts
				s.lastRenewOnly = renewOnly
				s.syncedOnce = true
			}
			close(call.done)
			s.syncFlight = nil
			s.syncMu.Unlock()
		})
		if !started {
			s.syncFlight = nil
			s.syncMu.Unlock()
			return context.Canceled
		}
	}
	s.syncMu.Unlock()

	select {
	case <-call.done:
		return call.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) LastSyncAt() time.Time {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	return s.lastSyncAt
}

// NeedsFastSync reports (using only local SQLite and billing file state, zero
// Headscale calls) whether background reconciliation should run on the fast
// polling interval rather than backing off to the idle interval.
func (s *Service) NeedsFastSync() bool {
	s.syncMu.Lock()
	synced := s.syncedOnce
	prevRenew := s.lastRenewOnly
	s.syncMu.Unlock()
	if !synced || s.isRenewOnly() != prevRenew {
		return true
	}
	if pGen, aGen, err := s.st.PolicyGenerations(); err != nil || pGen > aGen {
		return true
	}
	if open, err := s.st.HasOpenDeviceKeys(); err != nil || open {
		return true
	}
	if pending, err := s.st.HasPendingMemberCleanup(); err != nil || pending {
		return true
	}
	pendingIDs, err := s.st.PendingDeviceDeleteIDs()
	if err != nil {
		return true
	}
	if len(pendingIDs) > 0 {
		s.deferredDelMu.Lock()
		defer s.deferredDelMu.Unlock()
		for _, id := range pendingIDs {
			if !s.deferredPendingDel[id] {
				return true
			}
		}
	}
	return false
}

func (s *Service) syncOnce(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nodes, err := s.hs.Nodes(ctx)
	if err != nil {
		return false, err
	}
	s.setPresence(nodes)
	keys, err := s.st.PendingDeviceKeys(now() - 86400)
	if err != nil {
		return false, err
	}
	live, err := s.st.LiveDevices()
	if err != nil {
		return false, err
	}
	byNode := map[string]*Device{}
	for _, d := range live {
		byNode[d.HSNodeID] = d
	}
	allMembers, err := s.st.Members()
	if err != nil {
		return false, err
	}
	members := make(map[int64]*Member, len(allMembers))
	for _, m := range allMembers {
		members[m.ID] = m
	}
	memberOf := func(id int64) *Member {
		return members[id]
	}

	// Pre-check drift across all existing live nodes BEFORE making any DB writes.
	// If more than one live device would be retired for machine_key or owner/tag
	// binding drift in a single pass, trip a circuit breaker and retire NONE so a
	// future Headscale serialization change can never wipe out a pen.
	driftReasons := map[string]string{}
	for _, n := range nodes {
		if n.HasTag("tag:infra") {
			continue
		}
		d, ok := byNode[n.ID]
		if !ok {
			continue
		}
		m := memberOf(d.MemberID)
		if m != nil && m.Status == "removed" {
			continue
		}
		dMachKey, dHasMK := canonicalMachineKey(d.MachineKey)
		nMachKey, nHasMK := canonicalMachineKey(n.MachineKey)
		if dHasMK {
			if nHasMK && nMachKey != dMachKey {
				driftReasons[n.ID] = "machine_key changed"
			} else if nHasMK && m != nil && !nodeMatchesBinding(m, d, &n) {
				driftReasons[n.ID] = "owner/tag binding changed"
			}
		} else if d.MachineKey == "" && nHasMK && m != nil && !nodeMatchesBinding(m, d, &n) {
			driftReasons[n.ID] = "owner/tag binding mismatch"
		}
	}
	if len(driftReasons) > 1 {
		log.Printf("sync: ALERT circuit breaker tripped: %d of %d live devices had machine_key or binding drift; retiring none", len(driftReasons), len(live))
		s.st.Audit("registrar", "sync.drift_breaker", fmt.Sprintf("%d/%d", len(driftReasons), len(live)), "refusing mass device retirement")
		return false, fmt.Errorf("sync drift circuit breaker: %d of %d live devices drifted; refusing mass retirement", len(driftReasons), len(live))
	}

	hsByID := make(map[string]HSNode, len(nodes))
	for _, n := range nodes {
		hsByID[n.ID] = n
	}

	pendingDel, err := s.st.PendingDeviceDeletes()
	if err != nil {
		return false, err
	}
	pendingDelByNode := make(map[string]bool, len(pendingDel))
	stillDeferred := make(map[int64]bool)
	for _, d := range pendingDel {
		n, exists := hsByID[d.HSNodeID]
		if !exists {
			if cerr := s.st.ClearDeviceHSDeletePending(d.ID); cerr != nil {
				log.Printf("sync: clear hs_delete_pending for gone device #%d: %v", d.ID, cerr)
			}
			continue
		}
		action, reason := verifyPendingDeleteTarget(d, n, byNode[d.HSNodeID])
		switch action {
		case pendingDeleteSkipClear:
			log.Printf("sync: ALERT skipping pending headscale delete for removed device #%d (%s): %s", d.ID, d.HSNodeID, reason)
			s.st.Audit("registrar", "device.delete_skip", fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID), reason)
			if cerr := s.st.ClearDeviceHSDeletePending(d.ID); cerr != nil {
				log.Printf("sync: clear hs_delete_pending after skip for device #%d: %v", d.ID, cerr)
			}
			continue
		case pendingDeleteDefer:
			stillDeferred[d.ID] = true
			s.deferredDelMu.Lock()
			alreadyAlerted := s.deferredPendingDel[d.ID]
			s.deferredDelMu.Unlock()
			if !alreadyAlerted {
				log.Printf("sync: ALERT deferring pending headscale delete for removed device #%d (%s): %s", d.ID, d.HSNodeID, reason)
			}
			// Only suppress stray enrollment when no live device already owns this node ID.
			if _, isLive := byNode[d.HSNodeID]; !isLive {
				pendingDelByNode[d.HSNodeID] = true
			}
			continue
		case pendingDeleteProceed:
			pendingDelByNode[d.HSNodeID] = true
			if derr := s.hs.DeleteNode(ctx, d.HSNodeID); derr != nil {
				log.Printf("sync: retry headscale delete for removed device #%d (%s): %v", d.ID, d.HSNodeID, derr)
			} else if cerr := s.st.ClearDeviceHSDeletePending(d.ID); cerr != nil {
				log.Printf("sync: clear hs_delete_pending for device #%d: %v", d.ID, cerr)
			}
		}
	}
	s.deferredDelMu.Lock()
	s.deferredPendingDel = stillDeferred
	s.deferredDelMu.Unlock()

	seen := map[string]bool{}
	for _, n := range nodes {
		if n.HasTag("tag:infra") {
			continue
		}
		if pendingDelByNode[n.ID] {
			seen[n.ID] = true
			continue
		}
		seen[n.ID] = true
		v4, v6 := splitIPs(n.IPAddresses)
		name := n.GivenName
		if name == "" {
			name = n.Name
		}
		nNodeKey, nHasNK := canonicalNodeKey(n.NodeKey)
		nMachKey, nHasMK := canonicalMachineKey(n.MachineKey)
		if d, ok := byNode[n.ID]; ok {
			m := memberOf(d.MemberID)
			if m != nil && m.Status == "removed" {
				s.deleteStray(ctx, n, d, "member removed")
				continue
			}
			if reason, drifted := driftReasons[n.ID]; drifted {
				log.Printf("sync: ALERT node %s (%s) %s; retiring old device #%d", n.ID, d.Name, reason, d.ID)
				if err := s.st.MarkDeviceRemoved(d.ID); err != nil {
					return false, err
				}
				s.st.Audit("registrar", "device.gone", fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID), reason)
				delete(byNode, n.ID)
				goto enrollNew
			}
			dMachKey, dHasMK := canonicalMachineKey(d.MachineKey)
			if d.MachineKey != "" && !dHasMK {
				log.Printf("sync: ALERT node %s (%s) has unparseable stored machine_key %q; refusing update", n.ID, d.Name, d.MachineKey)
				continue
			}
			if dHasMK && !nHasMK {
				log.Printf("sync: ALERT node %s (%s) missing or unparseable machine_key in headscale response; refusing update", n.ID, d.Name)
				continue
			}
			if d.MachineKey == "" && !nHasMK {
				if !s.missingMKAlerted[n.ID] {
					log.Printf("sync: ALERT node %s (%s) has no machine_key in headscale or sqlite; direct portal auth will refuse it until headscale provides machineKey", n.ID, d.Name)
					s.missingMKAlerted[n.ID] = true
				}
			}

			nodeKey := d.NodeKey
			if nHasNK {
				dNodeKey, dHasNK := canonicalNodeKey(d.NodeKey)
				if dHasNK && dNodeKey != nNodeKey {
					s.st.Audit("registrar", "device.key_rotate", fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID), "via sync")
				}
				nodeKey = nNodeKey
			}
			machineKey := dMachKey
			if machineKey == "" && nHasMK {
				machineKey = nMachKey
			}
			if d.IPv4 != v4 || d.IPv6 != v6 || d.Name != name || d.NodeKey != nodeKey || d.MachineKey != machineKey {
				if err := s.st.UpdateDevice(d.ID, name, v4, v6, nodeKey, machineKey); err != nil {
					return false, err
				}
			}
			continue
		}
	enrollNew:
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
		if m == nil || m.Status != "active" || k.RevokedAt != nil {
			s.deleteStray(ctx, n, nil, "key revoked or member not active")
			continue
		}
		d := &Device{MemberID: k.MemberID, Kind: k.Kind, HSNodeID: n.ID, NodeKey: nNodeKey, MachineKey: nMachKey, Name: name, IPv4: v4, IPv6: v6}
		maxDevices := s.cfg.MaxDevices
		ownerFloor := 0
		if k.BypassCap {
			maxDevices = 0
		} else if m.Role == "owner" && k.Kind == "personal" {
			maxDevices = addDeviceReserve(s.cfg.MaxDevices)
			ownerFloor = ownerDeviceReserve
		}
		if err := s.st.EnrollDeviceCapped(d, k.ID, maxDevices, ownerFloor); err != nil {
			if errors.Is(err, ErrDeviceAlreadyEnrolled) {
				// Another concurrent sync process already enrolled this live node.
				continue
			}
			if errors.Is(err, ErrDeviceCapReached) {
				s.deleteStray(ctx, n, nil, "device limit reached")
				// Revoke (not MarkUsed) so HasJoined stays false and a transient
				// DeleteNode failure is automatically retried on subsequent syncs.
				_ = s.st.RevokeDeviceKey(k.ID)
				continue
			}
			return false, err
		}
		s.st.Audit("registrar", "device.join", fmt.Sprintf("%s/%s#%d", m.Handle, name, d.ID), k.Kind+" "+v4)
	}
	for _, d := range live {
		if !seen[d.HSNodeID] {
			if err := s.st.MarkDeviceRemoved(d.ID); err != nil {
				return false, err
			}
			s.st.Audit("registrar", "device.gone", fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID), "no longer in headscale")
		}
	}
	// Retry Headscale user deletion for removed members once all their nodes are gone.
	var removedWithHS []*Member
	for _, m := range allMembers {
		if m.Status == "removed" && m.HSUserID != "" {
			removedWithHS = append(removedWithHS, m)
		}
	}
	if len(removedWithHS) > 0 {
		liveByMember := map[int64]bool{}
		if curLive, err := s.st.LiveDevices(); err == nil {
			for _, d := range curLive {
				liveByMember[d.MemberID] = true
			}
			for _, m := range removedWithHS {
				if !liveByMember[m.ID] {
					if err := s.hs.DeleteUser(ctx, m.HSUserID); err == nil || isHSNotFound(err) {
						_ = s.st.ClearMemberHSUserID(m.ID)
					}
				}
			}
		}
	}
	return s.applyPolicyTracked(ctx)
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
		a = a.Unmap()
		if a.Is4() && v4 == "" {
			v4 = a.String()
		} else if a.Is6() && v6 == "" {
			v6 = a.String()
		}
	}
	return
}

func (s *Service) isRenewOnly() bool {
	return isRenewOnlyMode(s.cfg.BillingStatusPath)
}

// buildPolicy is the default-deny policy of DESIGN.md section 8, expressed
// over the IPv4 mesh addresses of devices whose members are active. Suspended
// and removed members' devices appear nowhere, so they can reach nothing.
// Mesh policy is intentionally IPv4-only (100.64.0.0/10 holds 4.19M addresses
// per pen): omitting IPv6 shrinks the policy JSON ~4x, halves every peer's
// WireGuard packet-filter entries, and leaves mesh IPv6 default-denied (D-11).
// During a renew_only wake (I-7 Part 2), only active owner/admin personal
// devices can reach tag:infra (DNS 53 + portal 443); regular members, server
// devices, and all shares are excluded from the Headscale netmap.
func (s *Service) buildPolicy() (string, bool, error) {
	live, err := s.st.LiveDevices()
	if err != nil {
		return "", false, err
	}
	membersByID := map[int64]*Member{}
	ms, err := s.st.Members()
	if err != nil {
		return "", false, err
	}
	for _, m := range ms {
		membersByID[m.ID] = m
	}
	renewOnly := s.isRenewOnly()
	infraSrc := []string{}
	serverSrc := []string{}
	servers := []string{}
	for _, d := range live {
		m := membersByID[d.MemberID]
		if m == nil || m.Status != "active" {
			continue
		}
		if renewOnly {
			if d.Kind != "personal" || (m.Role != "owner" && m.Role != "admin") {
				continue
			}
		}
		if d.IPv4 == "" {
			continue
		}
		infraSrc = append(infraSrc, d.IPv4)
		if !renewOnly {
			if d.Kind == "server" {
				servers = append(servers, d.IPv4)
			} else {
				serverSrc = append(serverSrc, d.IPv4)
			}
		}
	}
	sort.Strings(infraSrc)
	sort.Strings(serverSrc)
	sort.Strings(servers)
	infraSrc = append(infraSrc, "tag:infra")
	serverSrc = append(serverSrc, "tag:infra")

	type grant struct {
		Src []string `json:"src"`
		Dst []string `json:"dst"`
		IP  []string `json:"ip"`
	}
	// The pen's own services: DNS and the home page (HTTPS).
	grants := []grant{{Src: infraSrc, Dst: []string{"tag:infra"}, IP: []string{"53", "443"}}}
	if !renewOnly && len(servers) > 0 {
		// HTTPS only (D-11): active personal devices (and tag:infra) reach servers
		// on 443. Server devices are isolated from each other by default.
		grants = append(grants, grant{Src: serverSrc, Dst: servers, IP: []string{"443"}})
	}
	pol := map[string]any{
		"tagOwners": map[string][]string{"tag:infra": {}, "tag:server": {}},
		"grants":    grants,
	}
	b, err := json.Marshal(pol)
	return string(b), renewOnly, err
}

func (s *Service) applyPolicy(ctx context.Context) error {
	_, err := s.applyPolicyTracked(ctx)
	return err
}

func (s *Service) applyPolicyTracked(ctx context.Context) (bool, error) {
	// Serialize policy builds + Headscale pushes across registrar serve and
	// separate CLI processes so an older in-flight SetPolicy cannot overwrite
	// a newer revocation (e.g. CLI Suspend/Kick).
	if unlock, lockErr := s.st.lockPolicyFile(); lockErr == nil {
		defer unlock()
	} else {
		log.Printf("policy lock: %v (proceeding with generation re-check)", lockErr)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	const maxReconcilePasses = 3
	var renewOnly bool
	for pass := 0; pass < maxReconcilePasses; pass++ {
		// Snapshot policy_gen BEFORE reading members/devices in buildPolicy() so any
		// concurrent mutation leaves policy_gen > gen.
		gen, appliedGen, genErr := s.st.PolicyGenerations()
		pol, curRenewOnly, err := s.buildPolicy()
		if err != nil {
			return false, err
		}
		renewOnly = curRenewOnly
		// Rule: "dirty always pushes" even when pol == s.lastPolicy. lastPolicy
		// is process-local memory and can go stale across CLI SQLite mutations
		// (e.g. serve pushed P2, CLI resumed to P1, then CLI suspended back to P2
		// and its push failed: skipping would leave a suspended member on the
		// mesh). Note: .renew-only is file-driven (not a SQLite trigger), so its
		// transitions rely on pol != s.lastPolicy on the fast-sync loop.
		dirty := genErr != nil || gen > appliedGen
		if pol == s.lastPolicy && !dirty {
			return renewOnly, nil
		}
		t0 := time.Now()
		if err := s.hs.SetPolicy(ctx, pol); err != nil {
			dur := time.Since(t0).Round(time.Millisecond)
			log.Printf("policy: failed gen=%d bytes=%d dur=%s dur_ms=%d err=%v", gen, len(pol), dur, dur.Milliseconds(), err)
			return false, fmt.Errorf("set policy: %w", err)
		}
		dur := time.Since(t0).Round(time.Millisecond)
		log.Printf("policy: applied gen=%d bytes=%d dur=%s dur_ms=%d", gen, len(pol), dur, dur.Milliseconds())
		s.lastPolicy = pol
		if genErr == nil {
			_ = s.st.MarkPolicyApplied(gen)
			// Defense in depth: if another mutation committed while SetPolicy was
			// in flight, clear lastPolicy and immediately reconcile the newer gen.
			if curGen, _, reErr := s.st.PolicyGenerations(); reErr == nil && curGen > gen {
				s.lastPolicy = ""
				continue
			}
		}
		return renewOnly, nil
	}
	return renewOnly, nil
}
