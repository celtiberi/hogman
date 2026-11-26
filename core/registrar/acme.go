package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

var acmeTXTValueRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// EABPair holds one single-use External Account Binding credential returned by
// the challenge DNS service for registering a fallback ACME account.
type EABPair struct {
	KID        string `json:"kid"`
	HMACB64URL string `json:"hmac_b64url"`
	// Contact is the operator's address for the fallback account (Google
	// requires one). Set by the host, never a member's address.
	Contact string `json:"contact,omitempty"`
}

// fallbackContact turns the operator contact handed out with a fallback EAB
// into an ACME contact URI. Google refuses accounts without a contact; the
// primary CA's accounts stay without one. Anything that isn't a plain address
// is dropped rather than sent.
func fallbackContact(addr string) []string {
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

// ACMEBackend talks to the host's challenge DNS service (or a test stub) to
// write/remove DNS-01 TXT records and lazily mint single-use fallback EAB pairs.
type ACMEBackend interface {
	SetTXT(ctx context.Context, fqdn, value string) error
	DeleteTXT(ctx context.Context, fqdn, value string) error
	MintEAB(ctx context.Context) (*EABPair, error)
}

// ChallengeDNSClient implements ACMEBackend over the challenge DNS HTTP API
// (either Unix domain socket via unix:///path or unix:/path, or http(s)://...).
type ChallengeDNSClient struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewChallengeDNSClient builds a client from CHALLENGE_DNS_URL and token.
func NewChallengeDNSClient(baseURL, token string) (*ChallengeDNSClient, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return nil, errors.New("challenge DNS URL is empty")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("challenge DNS token is empty")
	}

	var normalizedBase string
	var client *http.Client

	switch {
	case strings.HasPrefix(baseURL, "unix://"), strings.HasPrefix(baseURL, "unix:"):
		sockPath := strings.TrimPrefix(strings.TrimPrefix(baseURL, "unix://"), "unix:")
		if sockPath == "" {
			return nil, fmt.Errorf("invalid unix socket URL %q", baseURL)
		}
		normalizedBase = "http://unix"
		client = newUnixHTTPClient(sockPath, 15*time.Second)
	default:
		u, err := url.Parse(baseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("invalid challenge DNS URL %q", baseURL)
		}
		normalizedBase = strings.TrimRight(u.String(), "/")
		client = &http.Client{Timeout: 15 * time.Second}
	}

	return &ChallengeDNSClient{
		baseURL: normalizedBase,
		token:   token,
		http:    client,
	}, nil
}

func newUnixHTTPClient(sockPath string, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", sockPath)
			},
		},
	}
}

func normalizeFQDN(fqdn string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
}

func (c *ChallengeDNSClient) doJSON(ctx context.Context, method, path string, in, out any, okCodes ...int) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return &Problem{Status: http.StatusServiceUnavailable, Msg: fmt.Sprintf("challenge DNS unavailable: %v", err)}
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return &Problem{Status: http.StatusServiceUnavailable, Msg: fmt.Sprintf("reading challenge DNS response: %v", err)}
	}

	for _, code := range okCodes {
		if resp.StatusCode == code {
			if out != nil && len(bytes.TrimSpace(respBytes)) > 0 {
				if err := json.Unmarshal(respBytes, out); err != nil {
					return fmt.Errorf("challenge DNS invalid JSON: %w", err)
				}
			}
			return nil
		}
	}

	msg := strings.TrimSpace(string(respBytes))
	var apiErr struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(respBytes, &apiErr) == nil && apiErr.Error != "" {
		msg = apiErr.Error
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	retryAfter := 0
	if raw := strings.TrimSpace(resp.Header.Get("Retry-After")); raw != "" {
		if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
			retryAfter = secs
		}
	}
	return &Problem{Status: resp.StatusCode, Msg: msg, RetryAfter: retryAfter}
}

func (c *ChallengeDNSClient) SetTXT(ctx context.Context, fqdn, value string) error {
	payload := struct {
		FQDN  string `json:"fqdn"`
		Value string `json:"value"`
	}{FQDN: normalizeFQDN(fqdn), Value: value}
	return c.doJSON(ctx, http.MethodPost, "/v1/txt", payload, nil, http.StatusCreated, http.StatusOK)
}

func (c *ChallengeDNSClient) DeleteTXT(ctx context.Context, fqdn, value string) error {
	payload := struct {
		FQDN  string `json:"fqdn"`
		Value string `json:"value"`
	}{FQDN: normalizeFQDN(fqdn), Value: value}
	return c.doJSON(ctx, http.MethodDelete, "/v1/txt", payload, nil, http.StatusNoContent, http.StatusOK)
}

func (c *ChallengeDNSClient) MintEAB(ctx context.Context) (*EABPair, error) {
	var pair EABPair
	if err := c.doJSON(ctx, http.MethodPost, "/v1/eab", nil, &pair, http.StatusCreated, http.StatusOK); err != nil {
		return nil, err
	}
	if strings.TrimSpace(pair.KID) == "" || strings.TrimSpace(pair.HMACB64URL) == "" {
		return nil, &Problem{Status: http.StatusBadGateway, Msg: "challenge DNS returned incomplete EAB credentials"}
	}
	return &pair, nil
}

// ChallengeDNSProvider adapts ACMEBackend to libdns interfaces for certmagic DNS-01.
type ChallengeDNSProvider struct {
	Backend ACMEBackend
}

func (p *ChallengeDNSProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	out := make([]libdns.Record, 0, len(recs))
	type createdRec struct{ fqdn, value string }
	var created []createdRec

	for _, r := range recs {
		rr := r.RR()
		if !strings.EqualFold(rr.Type, "TXT") {
			return nil, fmt.Errorf("challenge DNS provider supports TXT records only, got %q", rr.Type)
		}
		fqdn := normalizeFQDN(libdns.AbsoluteName(rr.Name, zone))
		if err := p.Backend.SetTXT(ctx, fqdn, rr.Data); err != nil {
			for _, prev := range created {
				_ = p.Backend.DeleteTXT(context.Background(), prev.fqdn, prev.value)
			}
			return nil, err
		}
		created = append(created, createdRec{fqdn: fqdn, value: rr.Data})
		out = append(out, libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data})
	}
	return out, nil
}

func (p *ChallengeDNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	out := make([]libdns.Record, 0, len(recs))
	for _, r := range recs {
		rr := r.RR()
		if !strings.EqualFold(rr.Type, "TXT") {
			continue
		}
		fqdn := normalizeFQDN(libdns.AbsoluteName(rr.Name, zone))
		err := p.Backend.DeleteTXT(ctx, fqdn, rr.Data)
		if err != nil {
			var prob *Problem
			if !errors.As(err, &prob) || prob.Status != http.StatusNotFound {
				return out, err
			}
		}
		out = append(out, libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data})
	}
	return out, nil
}

// dnsStepError marks errors originating from DNS record setup or propagation checks
// so failover logic never switches CAs when our own DNS is broken.
type dnsStepError struct{ err error }

func (e dnsStepError) Error() string { return e.err.Error() }
func (e dnsStepError) Unwrap() error { return e.err }

type dns01GateSolver struct {
	inner acmez.Solver
}

func (s dns01GateSolver) Present(ctx context.Context, ch acme.Challenge) error {
	if err := s.inner.Present(ctx, ch); err != nil {
		return dnsStepError{err: err}
	}
	return nil
}

func (s dns01GateSolver) Wait(ctx context.Context, ch acme.Challenge) error {
	if waiter, ok := s.inner.(acmez.Waiter); ok {
		if err := waiter.Wait(ctx, ch); err != nil {
			return dnsStepError{err: err}
		}
	}
	return nil
}

func (s dns01GateSolver) CleanUp(ctx context.Context, ch acme.Challenge) error {
	return s.inner.CleanUp(ctx, ch)
}

// shouldFailoverACME returns true only when an ACME failure points to rate
// limiting, CA 5xx responses, or CA transport/outage failures — never when our
// DNS challenge setup/validation fails.
func shouldFailoverACME(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var dnsErr dnsStepError
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

// HomeConfig configures certificate issuance and renewal for home.<zone>.
type HomeConfig struct {
	Zone               string
	Host               string // the name to certify; default home.<Zone>. The host's front door uses *.gate.<domain>
	FileBase           string // files written are <FileBase>.crt and <FileBase>.key; default "home"
	HomeTLSDir         string
	CaddyAdminSocket   string
	StorageDir         string
	PrimaryCA          string
	FallbackCA         string
	Email              string
	CARootFile         string
	Resolvers          []string
	PropagationDelay   time.Duration
	PropagationTimeout time.Duration
	Backend            ACMEBackend
	DNSProvider        certmagic.DNSProvider // overrides Backend if set (self-hosted libdns)
	BillingStatusPath  string                // when in renew_only wake, reuse unexpired cert & cap to 1 issuance
}

// HomeCertManager obtains and renews home.<zone> via CertMagic and writes
// home.crt / home.key atomically into HomeTLSDir, reloading portal Caddy on change.
type HomeCertManager struct {
	cfg        HomeConfig
	host       string
	storage    certmagic.Storage
	solver     acmez.Solver
	roots      *x509.CertPool
	logger     *zap.Logger
	cache      *certmagic.Cache
	stopOnce   sync.Once // Run and Close both stop the cache; certmagic panics on a second Stop
	primaryCfg *certmagic.Config
	primaryIss *certmagic.ACMEIssuer

	fallbackCfg *certmagic.Config
	fallbackIss *certmagic.ACMEIssuer

	syncMu          sync.Mutex
	renewMu         sync.Mutex
	certMu          sync.RWMutex
	currentCert     *tls.Certificate
	failoverCh      chan struct{}
	lastCertPEM     []byte
	lastKeyPEM      []byte
	renewWakeIssued bool
}

// NewHomeCertManager builds a certificate manager for home.<cfg.Zone>.
func NewHomeCertManager(cfg HomeConfig) (*HomeCertManager, error) {
	cfg.Zone = normalizeFQDN(cfg.Zone)
	cfg.Host = normalizeFQDN(cfg.Host)
	if cfg.Zone == "" && cfg.Host == "" {
		return nil, errors.New("acme: zone is empty")
	}
	host := cfg.Host
	if host == "" {
		host = "home." + cfg.Zone
	}
	if cfg.FileBase == "" {
		cfg.FileBase = "home"
	}
	if cfg.HomeTLSDir == "" {
		return nil, errors.New("acme: HOME_TLS_DIR is empty")
	}
	if cfg.StorageDir == "" {
		cfg.StorageDir = "/var/lib/registrar/acme"
	}
	if cfg.PrimaryCA == "" {
		cfg.PrimaryCA = certmagic.LetsEncryptProductionCA
	}
	if len(cfg.Resolvers) == 0 {
		cfg.Resolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	provider := cfg.DNSProvider
	if provider == nil {
		if cfg.Backend == nil {
			return nil, errors.New("acme: neither Backend nor DNSProvider is configured")
		}
		provider = &ChallengeDNSProvider{Backend: cfg.Backend}
	}
	if err := os.MkdirAll(cfg.HomeTLSDir, 0o750); err != nil {
		return nil, fmt.Errorf("create HOME_TLS_DIR: %w", err)
	}
	if err := os.MkdirAll(cfg.StorageDir, 0o700); err != nil {
		return nil, fmt.Errorf("create ACME storage dir: %w", err)
	}

	var roots *x509.CertPool
	if cfg.CARootFile != "" {
		raw, err := os.ReadFile(cfg.CARootFile)
		if err != nil {
			return nil, fmt.Errorf("read ACME_CA_ROOT %s: %w", cfg.CARootFile, err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("ACME_CA_ROOT %s contains no valid PEM certificates", cfg.CARootFile)
		}
	}

	logger := zap.NewNop()
	m := &HomeCertManager{
		cfg:     cfg,
		host:    host,
		storage: &certmagic.FileStorage{Path: cfg.StorageDir},
		solver: dns01GateSolver{
			inner: &certmagic.DNS01Solver{
				DNSManager: certmagic.DNSManager{
					DNSProvider:        provider,
					TTL:                60 * time.Second,
					PropagationDelay:   cfg.PropagationDelay,
					PropagationTimeout: cfg.PropagationTimeout,
					Resolvers:          cfg.Resolvers,
					Logger:             logger,
				},
			},
		},
		roots:      roots,
		logger:     logger,
		failoverCh: make(chan struct{}, 1),
	}

	m.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: m.getConfigForCert,
		Logger:           logger,
	})
	m.primaryCfg, m.primaryIss = m.newManagedConfig(cfg.PrimaryCA, false)
	if cfg.FallbackCA != "" {
		m.fallbackCfg, m.fallbackIss = m.newManagedConfig(cfg.FallbackCA, cfg.Backend != nil)
	}
	if pair, err := tls.LoadX509KeyPair(
		filepath.Join(cfg.HomeTLSDir, cfg.FileBase+".crt"),
		filepath.Join(cfg.HomeTLSDir, cfg.FileBase+".key"),
	); err == nil {
		p := pair
		m.currentCert = &p
	}
	return m, nil
}

// GetCertificate returns the currently active TLS certificate for home.<zone>,
// updated in memory whenever HomeCertManager issues or renews a certificate.
func (m *HomeCertManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.certMu.RLock()
	cert := m.currentCert
	m.certMu.RUnlock()
	if cert != nil {
		return cert, nil
	}
	pair, err := tls.LoadX509KeyPair(
		filepath.Join(m.cfg.HomeTLSDir, m.cfg.FileBase+".crt"),
		filepath.Join(m.cfg.HomeTLSDir, m.cfg.FileBase+".key"),
	)
	if err != nil {
		return nil, fmt.Errorf("home TLS certificate not ready yet: %w", err)
	}
	p := pair
	m.certMu.Lock()
	if m.currentCert == nil {
		m.currentCert = &p
	}
	cert = m.currentCert
	m.certMu.Unlock()
	return cert, nil
}

// Close stops the certificate cache. Safe to call more than once, and after Run.
func (m *HomeCertManager) Close() {
	m.stopOnce.Do(func() {
		if m.cache != nil {
			m.cache.Stop()
		}
	})
}

func (m *HomeCertManager) newManagedConfig(caURL string, withEAB bool) (*certmagic.Config, *certmagic.ACMEIssuer) {
	var cfg *certmagic.Config
	onEvent := func(ctx context.Context, event string, data map[string]any) error {
		switch event {
		case "cert_obtained":
			certPath, _ := data["certificate_path"].(string)
			keyPath, _ := data["private_key_path"].(string)
			if certPath != "" && keyPath != "" {
				if err := m.exportFromStorageKeys(ctx, certPath, keyPath); err != nil {
					log.Printf("acme: export home certificate after %s: %v", event, err)
				}
			}
		case "cert_failed":
			renewal, _ := data["renewal"].(bool)
			errVal, _ := data["error"].(error)
			if renewal && caURL == m.cfg.PrimaryCA && m.fallbackCfg != nil && shouldFailoverACME(errVal) {
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
		backend := m.cfg.Backend
		tmpl.NewAccountFunc = func(ctx context.Context, iss *certmagic.ACMEIssuer, acct acme.Account) (acme.Account, error) {
			pair, err := backend.MintEAB(ctx)
			if err != nil {
				return acct, err
			}
			if pair == nil {
				return acct, errors.New("fallback ACME EAB response is empty")
			}
			iss.ExternalAccount = &acme.EAB{
				KeyID:  pair.KID,
				MACKey: pair.HMACB64URL,
			}
			if len(acct.Contact) == 0 {
				acct.Contact = fallbackContact(pair.Contact)
			}
			return acct, nil
		}
	}
	iss := certmagic.NewACMEIssuer(cfg, tmpl)
	cfg.Issuers = []certmagic.Issuer{iss}
	return cfg, iss
}

// nonInteractiveACMEIssuer forces non-interactive PreCheck on synchronous
// CertMagic calls so an empty ACME contact email never prompts stdin. The
// long-lived cache configs keep the unwrapped *certmagic.ACMEIssuer so
// background renewals preserve ARI "replaces" support.
type nonInteractiveACMEIssuer struct {
	*certmagic.ACMEIssuer
}

func (n nonInteractiveACMEIssuer) PreCheck(ctx context.Context, names []string, _ bool) error {
	return n.ACMEIssuer.PreCheck(ctx, names, false)
}

func (m *HomeCertManager) newSyncConfig(cfg *certmagic.Config, iss *certmagic.ACMEIssuer) *certmagic.Config {
	// Synchronous EnsureOnce/ForceRenew/handleFailover calls handle failover
	// inline under renewMu, so suppress cert_failed -> failoverCh enqueues while
	// still exporting newly obtained certificates.
	onEvent := func(ctx context.Context, event string, data map[string]any) error {
		if event != "cert_obtained" {
			return nil
		}
		return cfg.OnEvent(ctx, event, data)
	}
	return certmagic.New(m.cache, certmagic.Config{
		Storage: m.storage,
		OnEvent: onEvent,
		Logger:  m.logger,
		Issuers: []certmagic.Issuer{nonInteractiveACMEIssuer{iss}},
	})
}

func (m *HomeCertManager) obtainOrRenewSync(ctx context.Context, cfg *certmagic.Config, iss *certmagic.ACMEIssuer, force bool) error {
	syncCfg := m.newSyncConfig(cfg, iss)
	if m.storageHasPair(ctx, iss.IssuerKey()) {
		return syncCfg.RenewCertSync(ctx, m.host, force)
	}
	return syncCfg.ObtainCertSync(ctx, m.host)
}

func (m *HomeCertManager) evictCachedCert(issuerKey string) {
	if m.cache == nil || issuerKey == "" {
		return
	}
	m.cache.RemoveManaged([]certmagic.SubjectIssuer{{
		Subject:   m.host,
		IssuerKey: issuerKey,
	}})
}

func (m *HomeCertManager) getConfigForCert(cert certmagic.Certificate) (*certmagic.Config, error) {
	ctx := context.Background()
	if m.fallbackCfg != nil && m.fallbackIss != nil {
		if m.storageHasPair(ctx, m.fallbackIss.IssuerKey()) && !m.storageHasPair(ctx, m.primaryIss.IssuerKey()) {
			return m.fallbackCfg, nil
		}
	}
	return m.primaryCfg, nil
}

func (m *HomeCertManager) storageHasPair(ctx context.Context, issuerKey string) bool {
	return m.storage.Exists(ctx, certmagic.StorageKeys.SiteCert(issuerKey, m.host)) &&
		m.storage.Exists(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, m.host))
}

func (m *HomeCertManager) exportFromStorageKeys(ctx context.Context, certKey, privKey string) error {
	certPEM, err := m.storage.Load(ctx, certKey)
	if err != nil {
		return err
	}
	keyPEM, err := m.storage.Load(ctx, privKey)
	if err != nil {
		return err
	}
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	if bytes.Equal(certPEM, m.lastCertPEM) && bytes.Equal(keyPEM, m.lastKeyPEM) && VerifyTLSFiles(m.cfg.HomeTLSDir, m.cfg.FileBase) == nil {
		return nil
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("parse renewed keypair: %w", err)
	}
	if err := writeTLSFilesAtomic(m.cfg.HomeTLSDir, m.cfg.FileBase, certPEM, keyPEM); err != nil {
		return err
	}
	m.certMu.Lock()
	p := pair
	m.currentCert = &p
	m.certMu.Unlock()
	if m.cfg.CaddyAdminSocket != "" {
		if err := reloadCaddy(ctx, m.cfg.CaddyAdminSocket); err != nil {
			return err
		}
	}
	m.lastCertPEM = certPEM
	m.lastKeyPEM = keyPEM
	return nil
}

func (m *HomeCertManager) syncStoredCert(ctx context.Context, cfg *certmagic.Config, iss *certmagic.ACMEIssuer) (bool, error) {
	if cfg == nil || iss == nil {
		return false, nil
	}
	certKey := certmagic.StorageKeys.SiteCert(iss.IssuerKey(), m.host)
	privKey := certmagic.StorageKeys.SitePrivateKey(iss.IssuerKey(), m.host)
	if !m.storage.Exists(ctx, certKey) || !m.storage.Exists(ctx, privKey) {
		return false, fs.ErrNotExist
	}
	cert, err := cfg.CacheManagedCertificate(ctx, m.host)
	if err != nil {
		return false, err
	}
	if err := m.exportFromStorageKeys(ctx, certKey, privKey); err != nil {
		return false, err
	}
	return cert.NeedsRenewal(cfg), nil
}

func (m *HomeCertManager) isRenewOnlyWake() bool {
	return isRenewOnlyMode(m.cfg.BillingStatusPath)
}

// certValidForAtLeast reports whether <HomeTLSDir>/<FileBase>.crt/.key exists
// and remains valid for at least minRemaining without needing CA issuance.
func certValidForAtLeast(dir, base string, minRemaining time.Duration) bool {
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, base+".crt"), filepath.Join(dir, base+".key"))
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	return leaf.NotAfter.After(time.Now().Add(minRemaining))
}

// EnsureOnce makes sure a valid certificate for home.<zone> is loaded or obtained,
// exported atomically into HomeTLSDir, and handed to portal Caddy.
func (m *HomeCertManager) EnsureOnce(ctx context.Context) error {
	m.renewMu.Lock()
	defer m.renewMu.Unlock()

	renewOnly := m.isRenewOnlyWake()
	if !renewOnly {
		m.renewWakeIssued = false
	} else {
		// I-7 Part 2: during a short renew-only wake, reuse any still-valid
		// certificate on disk (valid >= 1h) without burning a CA issuance.
		if certValidForAtLeast(m.cfg.HomeTLSDir, m.cfg.FileBase, time.Hour) {
			return nil
		}
		if m.renewWakeIssued {
			return errors.New("acme: renewal wake certificate issuance cap (1 per wake) reached")
		}
	}

	// Fast path: if either primary or fallback already holds a non-expiring cert in storage,
	// ensure it is exported and cached before touching the CA.
	primaryNeedsRenew, err := m.syncStoredCert(ctx, m.primaryCfg, m.primaryIss)
	if err == nil && (!primaryNeedsRenew || (renewOnly && certValidForAtLeast(m.cfg.HomeTLSDir, m.cfg.FileBase, time.Hour))) {
		return nil
	}
	if errors.Is(err, fs.ErrNotExist) && m.fallbackCfg != nil {
		fbNeedsRenew, fbErr := m.syncStoredCert(ctx, m.fallbackCfg, m.fallbackIss)
		if fbErr == nil && (!fbNeedsRenew || (renewOnly && certValidForAtLeast(m.cfg.HomeTLSDir, m.cfg.FileBase, time.Hour))) {
			return nil
		}
	}

	if renewOnly {
		m.renewWakeIssued = true
	}

	err = m.obtainOrRenewSync(ctx, m.primaryCfg, m.primaryIss, false)
	if err == nil {
		_, syncErr := m.syncStoredCert(ctx, m.primaryCfg, m.primaryIss)
		return syncErr
	}
	if m.fallbackCfg == nil || !shouldFailoverACME(err) {
		return err
	}

	log.Printf("acme: primary CA failed for %s (%v); failing over to fallback CA", m.host, err)
	fbErr := m.obtainOrRenewSync(ctx, m.fallbackCfg, m.fallbackIss, false)
	if fbErr != nil {
		return fmt.Errorf("primary failed (%w); fallback failed: %v", err, fbErr)
	}
	m.evictCachedCert(m.primaryIss.IssuerKey())
	_, syncErr := m.syncStoredCert(ctx, m.fallbackCfg, m.fallbackIss)
	return syncErr
}

// ForceRenew forces an immediate renewal of home.<zone>, falling back to the
// secondary ACME CA when appropriate, and exports/reloads the new certificate.
func (m *HomeCertManager) ForceRenew(ctx context.Context) error {
	m.renewMu.Lock()
	defer m.renewMu.Unlock()

	if m.fallbackCfg != nil && m.fallbackIss != nil {
		if m.storageHasPair(ctx, m.fallbackIss.IssuerKey()) && !m.storageHasPair(ctx, m.primaryIss.IssuerKey()) {
			if err := m.obtainOrRenewSync(ctx, m.fallbackCfg, m.fallbackIss, true); err != nil {
				return err
			}
			_, syncErr := m.syncStoredCert(ctx, m.fallbackCfg, m.fallbackIss)
			return syncErr
		}
	}

	err := m.obtainOrRenewSync(ctx, m.primaryCfg, m.primaryIss, true)
	if err == nil {
		_, syncErr := m.syncStoredCert(ctx, m.primaryCfg, m.primaryIss)
		return syncErr
	}
	if m.fallbackCfg == nil || !shouldFailoverACME(err) {
		return err
	}

	log.Printf("acme: primary forced renewal failed for %s (%v); failing over to fallback CA", m.host, err)
	if fbErr := m.obtainOrRenewSync(ctx, m.fallbackCfg, m.fallbackIss, true); fbErr != nil {
		return fmt.Errorf("primary failed (%w); fallback failed: %v", err, fbErr)
	}
	m.evictCachedCert(m.primaryIss.IssuerKey())
	_, syncErr := m.syncStoredCert(ctx, m.fallbackCfg, m.fallbackIss)
	return syncErr
}

// Run maintains home.<zone>'s certificate until ctx is canceled.
func (m *HomeCertManager) Run(ctx context.Context) {
	defer m.Close()

	delay := 2 * time.Second
	for {
		if err := m.EnsureOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("acme: managing %s: %v (retrying in %s)", m.host, err, delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			delay *= 2
			if delay > 5*time.Minute {
				delay = 5 * time.Minute
			}
			continue
		}
		break
	}

	log.Printf("acme: %s certificate active in %s", m.host, m.cfg.HomeTLSDir)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.failoverCh:
			m.handleFailover(ctx)
		}
	}
}

func (m *HomeCertManager) handleFailover(ctx context.Context) {
	if m.fallbackCfg == nil {
		return
	}
	m.renewMu.Lock()
	defer m.renewMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	renewOnly := m.isRenewOnlyWake()
	if !renewOnly {
		m.renewWakeIssued = false
	} else {
		if certValidForAtLeast(m.cfg.HomeTLSDir, m.cfg.FileBase, time.Hour) {
			log.Printf("acme: skipping fallback renewal for %s during renew-only wake (on-disk cert still valid)", m.host)
			return
		}
		if m.renewWakeIssued {
			log.Printf("acme: skipping fallback renewal for %s: renewal wake issuance cap (1 per wake) reached", m.host)
			return
		}
	}
	// Fast path: if fallback storage already holds a usable cert, promote it
	// without hitting the CA or consuming the renew-only wake issuance budget.
	if fbNeedsRenew, fbErr := m.syncStoredCert(ctx, m.fallbackCfg, m.fallbackIss); fbErr == nil && (!fbNeedsRenew || (renewOnly && certValidForAtLeast(m.cfg.HomeTLSDir, m.cfg.FileBase, time.Hour))) {
		m.evictCachedCert(m.primaryIss.IssuerKey())
		return
	}
	if renewOnly {
		m.renewWakeIssued = true
	}
	log.Printf("acme: primary renewal failed for %s; failing over to fallback CA", m.host)
	if err := m.obtainOrRenewSync(ctx, m.fallbackCfg, m.fallbackIss, false); err != nil {
		log.Printf("acme: fallback renewal failed for %s: %v", m.host, err)
		return
	}
	m.evictCachedCert(m.primaryIss.IssuerKey())
	if _, err := m.syncStoredCert(ctx, m.fallbackCfg, m.fallbackIss); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("acme: sync fallback certificate for %s: %v", m.host, err)
	}
}

func writeHomeTLSAtomic(dir string, certPEM, keyPEM []byte) error {
	return writeTLSFilesAtomic(dir, "home", certPEM, keyPEM)
}

func writeTLSFilesAtomic(dir, base string, certPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("invalid certificate/key pair: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, base+".key"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, base+".crt"), certPEM, 0o644); err != nil {
		return err
	}
	return nil
}

func writeFileAtomic(dst string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// VerifyHomeTLS checks that home.crt and home.key in dir form a valid, unexpired keypair.
func VerifyHomeTLS(dir string) error { return VerifyTLSFiles(dir, "home") }

// VerifyTLSFiles checks that <base>.crt and <base>.key in dir form a valid, unexpired keypair.
func VerifyTLSFiles(dir, base string) error {
	certPath := filepath.Join(dir, base+".crt")
	keyPath := filepath.Join(dir, base+".key")
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("%s.crt has no certificates", base)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("%s certificate expired at %s", base, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

func reloadCaddy(ctx context.Context, socketPath string) error {
	if socketPath == "" {
		return nil
	}
	if _, err := os.Stat(socketPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Printf("acme: caddy admin socket %s does not exist yet; skipping reload", socketPath)
			return nil
		}
		return err
	}
	client := newUnixHTTPClient(socketPath, 10*time.Second)

	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/config/", nil)
	if err != nil {
		return err
	}
	getResp, err := client.Do(getReq)
	if err != nil {
		if isUnixConnRefused(err) {
			log.Printf("acme: caddy admin socket %s not listening yet; skipping reload", socketPath)
			return nil
		}
		return fmt.Errorf("caddy admin GET /config/: %w", err)
	}
	cfgBytes, readErr := io.ReadAll(io.LimitReader(getResp.Body, 1<<20))
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK || readErr != nil {
		return fmt.Errorf("caddy admin GET /config/: status=%d err=%v", getResp.StatusCode, readErr)
	}

	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/load", bytes.NewReader(cfgBytes))
	if err != nil {
		return err
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Cache-Control", "must-revalidate")

	postResp, err := client.Do(postReq)
	if err != nil {
		return fmt.Errorf("caddy admin POST /load: %w", err)
	}
	postBody, _ := io.ReadAll(io.LimitReader(postResp.Body, 4096))
	_ = postResp.Body.Close()
	if postResp.StatusCode != http.StatusOK {
		return fmt.Errorf("caddy admin POST /load: status=%d body=%s", postResp.StatusCode, strings.TrimSpace(string(postBody)))
	}
	log.Printf("acme: reloaded caddy over %s", socketPath)
	return nil
}

func isUnixConnRefused(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		msg := strings.ToLower(opErr.Err.Error())
		return strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such file")
	}
	return false
}
