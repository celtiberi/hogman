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
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

const defaultFallbackACMECA = "https://dv.acme-v02.api.pki.goog/directory"

type meshAPIError struct {
	Status int
	Msg    string
}

func (e *meshAPIError) Error() string { return e.Msg }

func meshJSON(ctx context.Context, hc *http.Client, zone, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://home."+zone+"/api"+path, body)
	if err != nil {
		return err
	}
	if in != nil || method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &apiErr)
		msg := strings.TrimSpace(apiErr.Error)
		if msg == "" {
			msg = strings.TrimSpace(string(data))
		}
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return &meshAPIError{Status: resp.StatusCode, Msg: msg}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("unreadable answer: %w", err)
		}
	}
	return nil
}

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
		if err := meshJSON(ctx, p.hc, p.penZone, http.MethodPost, "/acme/txt", reqBody, nil); err != nil {
			for _, prev := range created {
				_ = meshJSON(context.Background(), p.hc, p.penZone, http.MethodDelete, "/acme/txt", prev, nil)
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
		err = meshJSON(ctx, p.hc, p.penZone, http.MethodDelete, "/acme/txt", reqBody, nil)
		if err != nil {
			var me *meshAPIError
			if !errors.As(err, &me) || me.Status != http.StatusNotFound {
				return out, err
			}
		}
		out = append(out, libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data})
	}
	return out, nil
}

// dnsStepError marks errors originating from DNS record setup or local DNS
// propagation checks so failover never switches CAs when DNS is at fault.
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

// shouldFailoverACME returns true only for CA rate limits, CA 5xx responses,
// or CA transport/outage failures, never for DNS-side failures (including the
// registrar's 429 weekly cap) or caller cancellations.
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

type shareACMEConfig struct {
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

func shareACMEConfigFromEnv(zone, host, storageDir string, hc *http.Client) shareACMEConfig {
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

	return shareACMEConfig{
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

type shareCertManager struct {
	cfg     shareACMEConfig
	host    string
	storage certmagic.Storage
	solver  acmez.Solver
	roots   *x509.CertPool
	logger  *zap.Logger
	cache   *certmagic.Cache

	primaryCfg  *certmagic.Config
	primaryIss  *certmagic.ACMEIssuer
	fallbackCfg *certmagic.Config
	fallbackIss *certmagic.ACMEIssuer

	renewMu    sync.Mutex
	failoverCh chan struct{}
	backoff    []time.Duration
}

func newShareCertManager(cfg shareACMEConfig) (*shareCertManager, error) {
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
	if cfg.Email == "" {
		cfg.Email = "admin@" + cfg.Zone
	}
	if len(cfg.Resolvers) == 0 {
		cfg.Resolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	if err := os.MkdirAll(cfg.StorageDir, 0o700); err != nil {
		return nil, fmt.Errorf("create ACME storage dir: %w", err)
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

	logger := zap.NewNop()
	m := &shareCertManager{
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
		roots:      roots,
		logger:     logger,
		failoverCh: make(chan struct{}, 1),
		backoff:    []time.Duration{2 * time.Second, 6 * time.Second, 15 * time.Second, 35 * time.Second},
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

func (m *shareCertManager) Close() {
	if m.cache != nil {
		m.cache.Stop()
	}
}

func (m *shareCertManager) TLSConfig() *tls.Config {
	return m.primaryCfg.TLSConfig()
}

func (m *shareCertManager) newManagedConfig(caURL string, withEAB bool) (*certmagic.Config, *certmagic.ACMEIssuer) {
	var cfg *certmagic.Config
	onEvent := func(_ context.Context, event string, data map[string]any) error {
		if event == "cert_failed" {
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
		tmpl.NewAccountFunc = func(ctx context.Context, iss *certmagic.ACMEIssuer, acct acme.Account) (acme.Account, error) {
			var pair struct {
				KID        string `json:"kid"`
				HMACB64URL string `json:"hmac_b64url"`
			}
			if err := meshJSON(ctx, m.cfg.HTTPClient, m.cfg.Zone, http.MethodPost, "/acme/eab", nil, &pair); err != nil {
				return acct, err
			}
			if strings.TrimSpace(pair.KID) == "" || strings.TrimSpace(pair.HMACB64URL) == "" {
				return acct, errors.New("registrar returned incomplete EAB credentials")
			}
			iss.ExternalAccount = &acme.EAB{
				KeyID:  pair.KID,
				MACKey: pair.HMACB64URL,
			}
			return acct, nil
		}
	}
	iss := certmagic.NewACMEIssuer(cfg, tmpl)
	cfg.Issuers = []certmagic.Issuer{iss}
	return cfg, iss
}

func (m *shareCertManager) storageHasPair(ctx context.Context, issuerKey string) bool {
	return m.storage.Exists(ctx, certmagic.StorageKeys.SiteCert(issuerKey, m.host)) &&
		m.storage.Exists(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, m.host))
}

func (m *shareCertManager) getConfigForCert(_ certmagic.Certificate) (*certmagic.Config, error) {
	ctx := context.Background()
	if m.fallbackCfg != nil && m.fallbackIss != nil {
		if m.storageHasPair(ctx, m.fallbackIss.IssuerKey()) && !m.storageHasPair(ctx, m.primaryIss.IssuerKey()) {
			return m.fallbackCfg, nil
		}
	}
	return m.primaryCfg, nil
}

func (m *shareCertManager) cachedNeedsRenewal(ctx context.Context, cfg *certmagic.Config, iss *certmagic.ACMEIssuer) (bool, error) {
	if cfg == nil || iss == nil {
		return false, fs.ErrNotExist
	}
	if !m.storageHasPair(ctx, iss.IssuerKey()) {
		return false, fs.ErrNotExist
	}
	cert, err := cfg.CacheManagedCertificate(ctx, m.host)
	if err != nil {
		return false, err
	}
	return cert.NeedsRenewal(cfg), nil
}

// Ensure loads a valid cached certificate from storage or obtains one via
// DNS-01 from the primary CA, failing over with lazy EAB only on CA outages or
// rate limits.
func (m *shareCertManager) Ensure(ctx context.Context) error {
	m.renewMu.Lock()
	defer m.renewMu.Unlock()

	needsRenew, err := m.cachedNeedsRenewal(ctx, m.primaryCfg, m.primaryIss)
	if err == nil && !needsRenew {
		return nil
	}
	if errors.Is(err, fs.ErrNotExist) && m.fallbackCfg != nil {
		fbRenew, fbErr := m.cachedNeedsRenewal(ctx, m.fallbackCfg, m.fallbackIss)
		if fbErr == nil && !fbRenew {
			return nil
		}
	}

	err = m.primaryCfg.ManageSync(ctx, []string{m.host})
	if err == nil {
		_, _ = m.cachedNeedsRenewal(ctx, m.primaryCfg, m.primaryIss)
		return nil
	}
	if m.fallbackCfg == nil || !shouldFailoverACME(err) {
		return err
	}

	log.Printf("acme: primary CA failed for %s (%v); failing over to fallback CA", m.host, err)
	fbErr := m.fallbackCfg.ManageSync(ctx, []string{m.host})
	if fbErr != nil {
		return fmt.Errorf("primary failed (%w); fallback failed: %v", err, fbErr)
	}
	_, _ = m.cachedNeedsRenewal(ctx, m.fallbackCfg, m.fallbackIss)
	return nil
}

func isNonRetryableShareCertErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	var me *meshAPIError
	if errors.As(err, &me) {
		switch me.Status {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusConflict, http.StatusTooManyRequests:
			return true
		}
	}
	var prob acme.Problem
	if errors.As(err, &prob) {
		return !shouldFailoverACME(err) && (prob.Status == http.StatusBadRequest || prob.Status == http.StatusForbidden)
	}
	return false
}

// EnsureWithBackoff obtains or loads a certificate with exponential backoff so
// validation failures do not hammer Let's Encrypt's 5-per-hour limit.
func (m *shareCertManager) EnsureWithBackoff(ctx context.Context) error {
	var last error
	for attempt := 0; ; attempt++ {
		if err := m.Ensure(ctx); err == nil {
			return nil
		} else {
			last = err
		}
		if ctx.Err() != nil || isNonRetryableShareCertErr(last) || attempt >= len(m.backoff) {
			return last
		}
		wait := m.backoff[attempt]
		log.Printf("acme: certificate for %s failed (%v); retrying in %s", m.host, last, wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// RunFailoverLoop watches for background primary renewal failures that qualify
// for failover and obtains a replacement certificate from the fallback CA.
func (m *shareCertManager) RunFailoverLoop(ctx context.Context) {
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
			if err := m.fallbackCfg.ManageSync(ctx, []string{m.host}); err != nil {
				log.Printf("acme: fallback renewal failed for %s: %v", m.host, err)
			} else {
				_, _ = m.cachedNeedsRenewal(ctx, m.fallbackCfg, m.fallbackIss)
			}
			m.renewMu.Unlock()

			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Minute):
			}
		}
	}
}
