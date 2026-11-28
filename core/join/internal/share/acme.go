package share

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"

	"hogman/join/internal/fsutil"
	"hogman/join/internal/penapi"
)

const defaultFallbackACMECA = "https://dv.acme-v02.api.pki.goog/directory"

// meshTXTProvider writes and cleans up DNS-01 TXT records through the pen
// registrar's /api/acme/txt mesh endpoint using the share's own mesh identity.
type meshTXTProvider struct {
	hc      *http.Client
	penZone string
}

func (p *meshTXTProvider) recordNameForACME(zone, rrName string) (string, error) {
	fqdn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(libdns.AbsoluteName(rrName, zone))), ".")
	rest, ok := strings.CutPrefix(fqdn, "_acme-challenge.")
	if !ok {
		return "", fmt.Errorf("unexpected ACME challenge record %q", fqdn)
	}
	ownerName, ok := strings.CutSuffix(rest, "."+p.penZone)
	if !ok || ownerName == "" {
		return "", fmt.Errorf("challenge record %q is outside pen zone %s", fqdn, p.penZone)
	}
	return ownerName, nil
}

func (p *meshTXTProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	type txtReq struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	var created []txtReq
	out := make([]libdns.Record, 0, len(recs))
	for _, r := range recs {
		rr := r.RR()
		if !strings.EqualFold(rr.Type, "TXT") {
			return nil, fmt.Errorf("mesh ACME TXT provider supports TXT only, got %q", rr.Type)
		}
		name, err := p.recordNameForACME(zone, rr.Name)
		if err != nil {
			return nil, err
		}
		reqBody := txtReq{Name: name, Value: rr.Data}
		if _, err := penapi.HomeAPICtx(ctx, p.hc, p.penZone, http.MethodPost, "/acme/txt", reqBody, nil); err != nil {
			for _, prev := range created {
				_, _ = penapi.HomeAPICtx(context.Background(), p.hc, p.penZone, http.MethodDelete, "/acme/txt", prev, nil)
			}
			return nil, err
		}
		created = append(created, reqBody)
		out = append(out, libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data})
	}
	return out, nil
}

func (p *meshTXTProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	type txtReq struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	out := make([]libdns.Record, 0, len(recs))
	for _, r := range recs {
		rr := r.RR()
		if !strings.EqualFold(rr.Type, "TXT") {
			continue
		}
		name, err := p.recordNameForACME(zone, rr.Name)
		if err != nil {
			return out, err
		}
		reqBody := txtReq{Name: name, Value: rr.Data}
		_, err = penapi.HomeAPICtx(ctx, p.hc, p.penZone, http.MethodDelete, "/acme/txt", reqBody, nil)
		if err != nil {
			var me *penapi.HomeAPIError
			if !errors.As(err, &me) || me.Status != http.StatusNotFound {
				return out, err
			}
		}
		out = append(out, libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data})
	}
	return out, nil
}

// DNSStepError marks errors originating from DNS record setup or local DNS
// propagation checks so failover never switches CAs when DNS is at fault.
type DNSStepError struct{ Err error }

func (e DNSStepError) Error() string { return e.Err.Error() }
func (e DNSStepError) Unwrap() error { return e.Err }

type dns01GateSolver struct {
	inner acmez.Solver
}

func (s dns01GateSolver) Present(ctx context.Context, ch acme.Challenge) error {
	if err := s.inner.Present(ctx, ch); err != nil {
		return DNSStepError{Err: err}
	}
	return nil
}

func (s dns01GateSolver) Wait(ctx context.Context, ch acme.Challenge) error {
	if waiter, ok := s.inner.(acmez.Waiter); ok {
		if err := waiter.Wait(ctx, ch); err != nil {
			return DNSStepError{Err: err}
		}
	}
	return nil
}

func (s dns01GateSolver) CleanUp(ctx context.Context, ch acme.Challenge) error {
	return s.inner.CleanUp(ctx, ch)
}

// ShouldFailoverACME returns true only for CA rate limits, CA 5xx responses,
// or CA transport/outage failures, never for DNS-side failures (including the
// registrar's 429 rate limits) or caller cancellations.
func ShouldFailoverACME(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var dnsErr DNSStepError
	if errors.As(err, &dnsErr) {
		return false
	}
	var prob acme.Problem
	if errors.As(err, &prob) {
		if prob.Status == http.StatusTooManyRequests || prob.Status >= 500 || strings.HasSuffix(prob.Type, ":rateLimited") {
			return true
		}
		for _, sub := range prob.Subproblems {
			if sub.Status == http.StatusTooManyRequests || sub.Status >= 500 || strings.HasSuffix(sub.Type, ":rateLimited") {
				return true
			}
		}
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return !errors.Is(urlErr.Err, context.Canceled)
	}
	return false
}

type ACMEConfig struct {
	Zone               string
	Host               string
	StorageDir         string
	PrimaryCA          string
	FallbackCA         string
	Email              string
	CARootFile         string
	Resolvers          []string
	PropagationDelay   time.Duration
	PropagationTimeout time.Duration
	HTTPClient         *http.Client
	Logger             *slog.Logger
}

func parseCSVEnv(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(part); err != nil {
			part = net.JoinHostPort(part, "53")
		}
		out = append(out, part)
	}
	return out
}

func ACMEConfigFromEnv(zone, host, storageDir string, hc *http.Client) ACMEConfig {
	primaryCA := strings.TrimSpace(os.Getenv("HOGMAN_ACME_CA_URL"))
	fallbackCA := ""
	if raw, ok := os.LookupEnv("HOGMAN_ACME_FALLBACK_CA_URL"); ok {
		raw = strings.TrimSpace(raw)
		if !strings.EqualFold(raw, "off") && !strings.EqualFold(raw, "none") {
			fallbackCA = raw
		}
	} else if primaryCA == "" {
		// Default fallback CA only applies when using the default production CA,
		// so test overrides do not dial external fallback CAs unexpectedly.
		fallbackCA = defaultFallbackACMECA
	}
	if primaryCA == "" {
		primaryCA = certmagic.LetsEncryptProductionCA
	}

	var propDelay, propTimeout time.Duration
	if s := strings.TrimSpace(os.Getenv("HOGMAN_ACME_PROPAGATION_DELAY")); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d >= 0 {
			propDelay = d
		}
	}
	if s := strings.TrimSpace(os.Getenv("HOGMAN_ACME_PROPAGATION_TIMEOUT")); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			propTimeout = d
		}
	}

	return ACMEConfig{
		Zone:               zone,
		Host:               host,
		StorageDir:         storageDir,
		PrimaryCA:          primaryCA,
		FallbackCA:         fallbackCA,
		Email:              strings.TrimSpace(os.Getenv("HOGMAN_ACME_EMAIL")),
		CARootFile:         strings.TrimSpace(os.Getenv("HOGMAN_ACME_CA_ROOT")),
		Resolvers:          parseCSVEnv(os.Getenv("HOGMAN_ACME_RESOLVERS")),
		PropagationDelay:   propDelay,
		PropagationTimeout: propTimeout,
		HTTPClient:         hc,
	}
}

var defaultShareACMEBackoff = []time.Duration{
	5 * time.Second,
	15 * time.Second,
	45 * time.Second,
	2 * time.Minute,
	5 * time.Minute,
	15 * time.Minute,
	30 * time.Minute,
	time.Hour,
}

const (
	defaultShareACMEMaxInProcessWait     = 30 * time.Second
	defaultShareACMEMaxInProcessAttempts = 3
	acmeRetryStateFile                   = "retry.json"
)

type acmeRetryState struct {
	Failures    int       `json:"failures"`
	NextAttempt time.Time `json:"next_attempt"`
}

// nonInteractiveACMEIssuer forces non-interactive PreCheck on synchronous
// CertMagic calls so an empty ACME contact email never prompts stdin (even
// in an interactive foreground terminal). The long-lived cache configs keep
// the unwrapped *certmagic.ACMEIssuer so CertMagic's concrete type assertion
// for ARI "replaces" continues working during background renewals.
type nonInteractiveACMEIssuer struct {
	*certmagic.ACMEIssuer
}

func (n nonInteractiveACMEIssuer) PreCheck(ctx context.Context, names []string, _ bool) error {
	return n.ACMEIssuer.PreCheck(ctx, names, false)
}

func defaultACMEWait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// CertManager obtains, caches, renews, and fails over public ACME certificates
// for a single share hostname using DNS-01 over the pen mesh.
type CertManager struct {
	cfg     ACMEConfig
	host    string
	storage certmagic.Storage
	solver  acmez.Solver
	roots   *x509.CertPool
	logger  *zap.Logger
	slogger *slog.Logger
	cache   *certmagic.Cache

	primaryCfg  *certmagic.Config
	primaryIss  *certmagic.ACMEIssuer
	fallbackCfg *certmagic.Config
	fallbackIss *certmagic.ACMEIssuer

	renewMu              sync.Mutex
	closeOnce            sync.Once
	failoverCh           chan struct{}
	backoff              []time.Duration
	maxInProcessWait     time.Duration
	maxInProcessAttempts int
	now                  func() time.Time
	waitFn               func(context.Context, time.Duration) error
}

func NewCertManager(cfg ACMEConfig) (*CertManager, error) {
	cfg.Zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cfg.Zone)), ".")
	cfg.Host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cfg.Host)), ".")
	if cfg.Zone == "" || cfg.Host == "" {
		return nil, errors.New("acme: zone and host are required")
	}
	if !strings.HasSuffix(cfg.Host, "."+cfg.Zone) {
		return nil, fmt.Errorf("acme: share host %q is outside zone %q", cfg.Host, cfg.Zone)
	}
	if cfg.StorageDir == "" {
		return nil, errors.New("acme: storage directory is required")
	}
	if cfg.HTTPClient == nil {
		return nil, errors.New("acme: HTTP client is required")
	}
	if cfg.PrimaryCA == "" {
		cfg.PrimaryCA = certmagic.LetsEncryptProductionCA
	}
	if len(cfg.Resolvers) == 0 {
		cfg.Resolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	var roots *x509.CertPool
	if cfg.CARootFile != "" {
		raw, err := os.ReadFile(cfg.CARootFile)
		if err != nil {
			return nil, fmt.Errorf("read HOGMAN_ACME_CA_ROOT %s: %w", cfg.CARootFile, err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("HOGMAN_ACME_CA_ROOT %s contains no valid PEM certificate", cfg.CARootFile)
		}
	}
	if err := os.MkdirAll(cfg.StorageDir, 0o700); err != nil {
		return nil, fmt.Errorf("create ACME storage dir: %w", err)
	}

	logger := zap.NewNop()
	slogger := cfg.Logger
	if slogger == nil {
		slogger = fsutil.DaemonLogger()
	}
	m := &CertManager{
		cfg:     cfg,
		host:    cfg.Host,
		storage: &certmagic.FileStorage{Path: cfg.StorageDir},
		solver: dns01GateSolver{
			inner: &certmagic.DNS01Solver{
				DNSManager: certmagic.DNSManager{
					DNSProvider:        &meshTXTProvider{hc: cfg.HTTPClient, penZone: cfg.Zone},
					TTL:                60 * time.Second,
					PropagationDelay:   cfg.PropagationDelay,
					PropagationTimeout: cfg.PropagationTimeout,
					Resolvers:          cfg.Resolvers,
					Logger:             logger,
				},
			},
		},
		roots:                roots,
		logger:               logger,
		slogger:              slogger,
		failoverCh:           make(chan struct{}, 1),
		backoff:              append([]time.Duration(nil), defaultShareACMEBackoff...),
		maxInProcessWait:     defaultShareACMEMaxInProcessWait,
		maxInProcessAttempts: defaultShareACMEMaxInProcessAttempts,
		now:                  time.Now,
		waitFn:               defaultACMEWait,
	}

	m.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: m.getConfigForCert,
		Logger:           logger,
	})
	m.primaryCfg, m.primaryIss = m.newManagedConfig(cfg.PrimaryCA, false)
	if cfg.FallbackCA != "" {
		m.fallbackCfg, m.fallbackIss = m.newManagedConfig(cfg.FallbackCA, true)
	}
	return m, nil
}

func (m *CertManager) Close() {
	m.closeOnce.Do(func() {
		if m.cache != nil {
			m.cache.Stop()
		}
	})
}

func (m *CertManager) TLSConfig() *tls.Config {
	return m.primaryCfg.TLSConfig()
}

func (m *CertManager) newManagedConfig(caURL string, withEAB bool) (*certmagic.Config, *certmagic.ACMEIssuer) {
	var cfg *certmagic.Config
	onEvent := func(_ context.Context, event string, data map[string]any) error {
		if event == "cert_failed" {
			renewal, _ := data["renewal"].(bool)
			errVal, _ := data["error"].(error)
			if renewal && caURL == m.cfg.PrimaryCA && m.fallbackCfg != nil && ShouldFailoverACME(errVal) {
				select {
				case m.failoverCh <- struct{}{}:
				default:
				}
			}
		}
		return nil
	}

	cfg = certmagic.New(m.cache, certmagic.Config{
		Storage: m.storage,
		OnEvent: onEvent,
		Logger:  m.logger,
	})
	tmpl := certmagic.ACMEIssuer{
		CA:                      caURL,
		Email:                   m.cfg.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver:             m.solver,
		TrustedRoots:            m.roots,
		Logger:                  m.logger,
	}
	if withEAB {
		tmpl.NewAccountFunc = func(ctx context.Context, iss *certmagic.ACMEIssuer, acct acme.Account) (acme.Account, error) {
			var pair struct {
				KID        string `json:"kid"`
				HMACB64URL string `json:"hmac_b64url"`
				Contact    string `json:"contact"`
			}
			if _, err := penapi.HomeAPICtx(ctx, m.cfg.HTTPClient, m.cfg.Zone, http.MethodPost, "/acme/eab", nil, &pair); err != nil {
				return acct, err
			}
			if strings.TrimSpace(pair.KID) == "" || strings.TrimSpace(pair.HMACB64URL) == "" {
				return acct, errors.New("registrar returned incomplete EAB credentials")
			}
			iss.ExternalAccount = &acme.EAB{
				KeyID:  pair.KID,
				MACKey: pair.HMACB64URL,
			}
			if len(acct.Contact) == 0 {
				acct.Contact = FallbackContact(pair.Contact)
			}
			return acct, nil
		}
	}
	iss := certmagic.NewACMEIssuer(cfg, tmpl)
	cfg.Issuers = []certmagic.Issuer{iss}
	return cfg, iss
}

func (m *CertManager) syncCert(ctx context.Context, cfg *certmagic.Config, iss *certmagic.ACMEIssuer) error {
	syncCfg := certmagic.New(m.cache, certmagic.Config{
		Storage: m.storage,
		OnEvent: cfg.OnEvent,
		Logger:  m.logger,
		Issuers: []certmagic.Issuer{nonInteractiveACMEIssuer{iss}},
	})
	return syncCfg.ManageSync(ctx, []string{m.host})
}

func (m *CertManager) storageHasPair(ctx context.Context, issuerKey string) bool {
	return m.storage.Exists(ctx, certmagic.StorageKeys.SiteCert(issuerKey, m.host)) &&
		m.storage.Exists(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, m.host))
}

// storageCertFresh inspects the stored leaf certificate without loading it into
// the in-memory TLS cache, returning true only when the cert/key pair exists,
// is currently valid, and has more than one-third of its lifetime remaining.
func (m *CertManager) storageCertFresh(ctx context.Context, issuerKey string) bool {
	if !m.storageHasPair(ctx, issuerKey) {
		return false
	}
	raw, err := m.storage.Load(ctx, certmagic.StorageKeys.SiteCert(issuerKey, m.host))
	if err != nil {
		return false
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return false
	}
	// Match certmagic.Certificate.NeedsRenewal, which evaluates cert validity
	// against wall-clock time (m.now is only for the retry backoff clock).
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	remaining := leaf.NotAfter.Sub(now)
	return lifetime > 0 && remaining > lifetime/3
}

func (m *CertManager) getConfigForCert(_ certmagic.Certificate) (*certmagic.Config, error) {
	ctx := context.Background()
	if m.fallbackCfg != nil && m.fallbackIss != nil &&
		!m.storageCertFresh(ctx, m.primaryIss.IssuerKey()) &&
		m.storageCertFresh(ctx, m.fallbackIss.IssuerKey()) {
		return m.fallbackCfg, nil
	}
	return m.primaryCfg, nil
}

func (m *CertManager) ensureCachedLocked(ctx context.Context) bool {
	if m.storageCertFresh(ctx, m.primaryIss.IssuerKey()) {
		if _, err := m.primaryCfg.CacheManagedCertificate(ctx, m.host); err == nil {
			return true
		}
	}
	if m.fallbackCfg != nil && m.fallbackIss != nil && m.storageCertFresh(ctx, m.fallbackIss.IssuerKey()) {
		if _, err := m.fallbackCfg.CacheManagedCertificate(ctx, m.host); err == nil {
			return true
		}
	}
	return false
}

func (m *CertManager) ensureCached(ctx context.Context) bool {
	m.renewMu.Lock()
	defer m.renewMu.Unlock()
	return m.ensureCachedLocked(ctx)
}

func (m *CertManager) retryStatePath() string {
	return filepath.Join(m.cfg.StorageDir, acmeRetryStateFile)
}

func (m *CertManager) loadRetryState() acmeRetryState {
	raw, err := os.ReadFile(m.retryStatePath())
	if err != nil {
		return acmeRetryState{}
	}
	var st acmeRetryState
	if err := json.Unmarshal(raw, &st); err != nil || st.Failures < 0 {
		return acmeRetryState{}
	}
	return st
}

func (m *CertManager) log() *slog.Logger {
	if m != nil && m.slogger != nil {
		return m.slogger
	}
	return slog.Default()
}

func (m *CertManager) saveRetryState(st acmeRetryState) {
	data, err := json.Marshal(st)
	if err != nil {
		m.log().Warn("acme: could not encode retry state", "host", m.host, "err", err)
		return
	}
	if err := fsutil.WriteFileAtomic(m.retryStatePath(), data, 0o600); err != nil {
		m.log().Warn("acme: could not save retry state", "host", m.host, "err", err)
	}
}

func (m *CertManager) clearRetryState() {
	_ = os.Remove(m.retryStatePath())
}

func (m *CertManager) backoffSchedule() []time.Duration {
	if len(m.backoff) > 0 {
		return m.backoff
	}
	return defaultShareACMEBackoff
}

func (m *CertManager) backoffDelay(failures int) time.Duration {
	sched := m.backoffSchedule()
	idx := failures - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sched) {
		idx = len(sched) - 1
	}
	return sched[idx]
}

func (m *CertManager) maxBackoff() time.Duration {
	sched := m.backoffSchedule()
	return sched[len(sched)-1]
}

func (m *CertManager) currentTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *CertManager) cappedWait(nextAttempt time.Time) time.Duration {
	now := m.currentTime()
	if !now.Before(nextAttempt) {
		return 0
	}
	wait := nextAttempt.Sub(now)
	if maxWait := m.maxBackoff(); wait > maxWait {
		return maxWait
	}
	return wait
}

func (m *CertManager) wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	if m.waitFn != nil {
		return m.waitFn(ctx, d)
	}
	return defaultACMEWait(ctx, d)
}

// Ensure loads a valid cached certificate from storage or obtains one via
// DNS-01 from the primary CA, failing over with lazy EAB only on CA outages or
// rate limits.
func (m *CertManager) Ensure(ctx context.Context) error {
	m.renewMu.Lock()
	defer m.renewMu.Unlock()

	if m.ensureCachedLocked(ctx) {
		m.clearRetryState()
		return nil
	}

	err := m.syncCert(ctx, m.primaryCfg, m.primaryIss)
	if err == nil {
		_, _ = m.primaryCfg.CacheManagedCertificate(ctx, m.host)
		m.clearRetryState()
		return nil
	}
	if m.fallbackCfg == nil || !ShouldFailoverACME(err) {
		return err
	}

	m.log().Warn("acme: primary CA failed; failing over to fallback CA", "host", m.host, "err", err)
	fbErr := m.syncCert(ctx, m.fallbackCfg, m.fallbackIss)
	if fbErr != nil {
		return fmt.Errorf("primary failed (%w); fallback failed: %v", err, fbErr)
	}
	_, _ = m.fallbackCfg.CacheManagedCertificate(ctx, m.host)
	m.clearRetryState()
	return nil
}

func isRegistrarCapErr(err error) bool {
	var me *penapi.HomeAPIError
	return errors.As(err, &me) && me.Status == http.StatusTooManyRequests
}

func IsNonRetryableCertErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	var me *penapi.HomeAPIError
	if errors.As(err, &me) {
		switch me.Status {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusConflict:
			return true
		}
	}
	var prob acme.Problem
	if errors.As(err, &prob) {
		return !ShouldFailoverACME(err) && (prob.Status == http.StatusBadRequest || prob.Status == http.StatusForbidden)
	}
	return false
}

// EnsureWithBackoff obtains or loads a certificate with persistent exponential
// backoff in StorageDir/retry.json so validation failures or service restarts
// do not hammer the CA.
func (m *CertManager) EnsureWithBackoff(ctx context.Context) error {
	if m.ensureCached(ctx) {
		m.clearRetryState()
		return nil
	}

	st := m.loadRetryState()
	if !st.NextAttempt.IsZero() {
		if wait := m.cappedWait(st.NextAttempt); wait > 0 {
			m.log().Info("acme: backing off certificate retry",
				"host", m.host, "wait", wait.Round(time.Second), "until", st.NextAttempt.UTC().Format(time.RFC3339))
			if err := m.wait(ctx, wait); err != nil {
				return err
			}
		}
	}

	maxAttempts := 1
	if st.Failures == 0 && m.maxInProcessAttempts > 1 {
		maxAttempts = m.maxInProcessAttempts
	}

	var last error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := m.Ensure(ctx)
		if err == nil {
			m.clearRetryState()
			return nil
		}
		last = err
		if ctx.Err() != nil {
			return last
		}
		if isRegistrarCapErr(last) {
			delay := m.maxBackoff()
			st.Failures++
			st.NextAttempt = m.currentTime().UTC().Add(delay)
			m.saveRetryState(st)
			m.log().Warn("acme: registrar certificate limit reached",
				"host", m.host, "err", last, "next_retry", delay)
			return last
		}
		if IsNonRetryableCertErr(last) {
			return last
		}

		st.Failures++
		delay := m.backoffDelay(st.Failures)
		st.NextAttempt = m.currentTime().UTC().Add(delay)
		m.saveRetryState(st)

		if attempt+1 >= maxAttempts || (m.maxInProcessWait > 0 && delay > m.maxInProcessWait) {
			m.log().Warn("acme: certificate failed", "host", m.host, "err", last, "next_retry", delay)
			return last
		}
		m.log().Warn("acme: certificate failed; retrying", "host", m.host, "err", last, "retry_in", delay)
		if err := m.wait(ctx, delay); err != nil {
			return err
		}
	}
	return last
}

// RunFailoverLoop watches for background primary renewal failures that qualify
// for failover and obtains a replacement certificate from the fallback CA.
func (m *CertManager) RunFailoverLoop(ctx context.Context) {
	if m.fallbackCfg == nil {
		<-ctx.Done()
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.failoverCh:
			m.renewMu.Lock()
			if err := m.syncCert(ctx, m.fallbackCfg, m.fallbackIss); err != nil {
				m.log().Warn("acme: fallback renewal failed", "host", m.host, "err", err)
			} else {
				_, _ = m.fallbackCfg.CacheManagedCertificate(ctx, m.host)
			}
			m.renewMu.Unlock()

			if err := m.wait(ctx, time.Minute); err != nil {
				return
			}
		}
	}
}

// FallbackContact turns the operator contact handed out with a fallback EAB
// into an ACME contact URI. Google refuses accounts without a contact; the
// primary CA's accounts stay without one. Anything that isn't a plain address
// is dropped rather than sent.
func FallbackContact(addr string) []string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	a, err := mail.ParseAddress(addr)
	if err != nil || a.Name != "" || a.Address != addr {
		return nil
	}
	return []string{"mailto:" + addr}
}
