package registrar

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"hogman/registrar/internal/acme"
	"hogman/registrar/internal/headscale"
	"hogman/registrar/internal/ratelimit"
	"hogman/registrar/internal/store"
)

const (
	DefaultMaxMembers              = 500
	DefaultMaxDevices              = 500
	defaultMaxOpenDeviceKeys       = 3
	defaultMaxAdminOpenDeviceKeys  = 10
	defaultMaxNamesPerMember       = 50
	defaultMaxOpenInvites          = 25
	defaultMaxInviteNoteLen        = 256
	defaultMaxServerEABPerDay      = 2
	defaultMaxMemberEABPerDay      = 4
	defaultMaxMemberACMETXTPerHour = 60
	defaultPresenceTTL             = 5 * time.Second
	// OwnerDeviceReserve is the number of extra personal-device slots above
	// MaxDevices reserved strictly for active owners so an owner can replace or
	// add a personal device to manage the pen even when the pen is at MAX_DEVICES.
	OwnerDeviceReserve = 2
)

func defaultPositive[T ~int | ~int64](v *T, def T) {
	if *v <= 0 {
		*v = def
	}
}

func addDeviceReserve(maxDevices int) int {
	if maxDevices <= 0 {
		return 0
	}
	if maxDevices > math.MaxInt-OwnerDeviceReserve {
		return math.MaxInt
	}
	return maxDevices + OwnerDeviceReserve
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
	ACMEBackend             acme.Backend
	Logger                  *slog.Logger
	Now                     func() time.Time
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
	Member *store.Member
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
func (a Actor) Is(m *store.Member) bool {
	return !a.CLI && a.Member != nil && a.Member.ID == m.ID
}

func (a Actor) memberID() *int64 {
	if a.CLI || a.Member == nil {
		return nil
	}
	return &a.Member.ID
}

const (
	InlineSyncCooldown = 3 * time.Second
	KeyRotateCooldown  = 10 * time.Second
	KeyRotateMaxConc   = 4
	syncFlightTimeout  = 30 * time.Second
	presenceTimeout    = 15 * time.Second
)

type syncCall struct {
	done chan struct{}
	err  error
}

type Service struct {
	cfg  Config
	st   *store.Store
	hs   *headscale.Client
	acme acme.Backend

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

	rotator  *keyRotator
	presence *presenceCache

	deferredDelMu      sync.Mutex
	deferredPendingDel map[int64]bool

	serverEABLim   *ratelimit.Window[int64]
	memberEABLim   *ratelimit.Window[int64]
	memberTXTLim   *ratelimit.Window[int64]
	logger         *slog.Logger
	nowFn          func() time.Time
	privateLabelFn func() (string, error)
}

func (s *Service) loggerOrDefault() *slog.Logger {
	if s != nil && s.logger != nil {
		return s.logger
	}
	return slog.Default()
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

func (c Config) withDefaults() Config {
	defaultPositive(&c.MaxMembers, DefaultMaxMembers)
	defaultPositive(&c.MaxDevices, DefaultMaxDevices)
	defaultPositive(&c.MaxOpenDeviceKeys, defaultMaxOpenDeviceKeys)
	defaultPositive(&c.MaxAdminOpenDeviceKeys, defaultMaxAdminOpenDeviceKeys)
	c.MaxAdminOpenDeviceKeys = max(c.MaxAdminOpenDeviceKeys, c.MaxOpenDeviceKeys)
	defaultPositive(&c.MaxNamesPerMember, defaultMaxNamesPerMember)
	defaultPositive(&c.MaxOpenInvites, defaultMaxOpenInvites)
	defaultPositive(&c.MaxInviteNoteLen, defaultMaxInviteNoteLen)
	defaultPositive(&c.MaxServerEABPerDay, defaultMaxServerEABPerDay)
	defaultPositive(&c.MaxMemberEABPerDay, defaultMaxMemberEABPerDay)
	defaultPositive(&c.MaxMemberACMETXTPerHour, defaultMaxMemberACMETXTPerHour)
	defaultPositive(&c.PresenceTTL, defaultPresenceTTL)
	return c
}

func NewService(cfg Config, st *store.Store, hs *headscale.Client) (*Service, error) {
	theme, err := normaliseTheme(cfg.Theme)
	if err != nil {
		return nil, err
	}
	cfg.Theme = theme
	cfg = cfg.withDefaults()
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Service{
		cfg:                cfg,
		st:                 st,
		hs:                 hs,
		acme:               cfg.ACMEBackend,
		orphans:            map[string]bool{},
		missingMKAlerted:   map[string]bool{},
		baseCtx:            context.Background(),
		deferredPendingDel: map[int64]bool{},
		serverEABLim:       ratelimit.NewStrictWindow[int64](cfg.MaxServerEABPerDay, 24*time.Hour, ratelimit.DefaultMaxKeys),
		memberEABLim:       ratelimit.NewStrictWindow[int64](cfg.MaxMemberEABPerDay, 24*time.Hour, ratelimit.DefaultMaxKeys),
		memberTXTLim:       ratelimit.NewStrictWindow[int64](cfg.MaxMemberACMETXTPerHour, time.Hour, ratelimit.DefaultMaxKeys),
		logger:             logger,
		nowFn:              cfg.Now,
	}
	s.rotator = newKeyRotator(s.clock, KeyRotateCooldown, KeyRotateMaxConc, s.startBackground, logger)
	s.presence = newPresenceCache(s.clock, cfg.PresenceTTL, presenceTimeout, s.baseContext, s.startBackground, func(ctx context.Context) ([]headscale.Node, error) {
		return s.hs.Nodes(ctx)
	})
	if st != nil {
		st.SetClock(s.clock)
	}
	return s, nil
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

// NormaliseName turns "Blog.Alice.bobo.hogman." into "blog.alice" and validates labels.
func (s *Service) NormaliseName(raw string) (string, error) { return s.normaliseName(raw) }

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

// requireSelfOrManageable enforces the role hierarchy for actions that a member
// may perform for themselves, an admin may perform for plain members, and only
// an owner may perform for admins or owners.
func requireSelfOrManageable(a Actor, target *store.Member, selfMsg, adminTargetMsg string) error {
	if a.Is(target) {
		return nil
	}
	if !a.IsAdmin() {
		return forbidden("%s", selfMsg)
	}
	if (target.Role == "owner" || target.Role == "admin") && !a.IsOwner() {
		return forbidden("%s", adminTargetMsg)
	}
	return nil
}

func topLabel(name string) string {
	i := strings.LastIndex(name, ".")
	return name[i+1:]
}

func (s *Service) member(handle string) (*store.Member, error) {
	m, err := s.st.MemberByHandle(handle)
	if errors.Is(err, ErrNotFound) {
		return nil, missing("no member %q", handle)
	}
	return m, err
}
