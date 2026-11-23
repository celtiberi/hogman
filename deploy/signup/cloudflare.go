package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultTurnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// Official Cloudflare edge IP ranges (https://www.cloudflare.com/ips-v4, /ips-v6).
// Used only when TRUST_CLOUDFLARE=1 (or overridden via TRUSTED_PROXY_CIDRS).
var defaultCloudflareCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

func parseCIDRs(items []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(items))
	for _, raw := range items {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func trustedProxiesFromEnv() ([]netip.Prefix, error) {
	if custom := strings.TrimSpace(os.Getenv("TRUSTED_PROXY_CIDRS")); custom != "" {
		fields := strings.FieldsFunc(custom, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
		return parseCIDRs(fields)
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("TRUST_CLOUDFLARE")))
	if v == "1" || v == "true" || v == "yes" {
		return parseCIDRs(defaultCloudflareCIDRs)
	}
	return nil, nil
}

func ipInPrefixes(addr netip.Addr, prefixes []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

var (
	errTurnstileInvalid = errors.New("please complete the verification check and try again")
	errTurnstileDown    = errors.New("could not verify the human check right now; try again")
)

type turnstileVerifier struct {
	siteKey       string
	secret        string
	verifyURL     string
	expectedHosts []string
	client        *http.Client
}

func parseHostList(items ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range items {
		fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
		for _, f := range fields {
			h := stripHostPort(f)
			if h != "" && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

func newTurnstileVerifier(siteKey, secret, verifyURL string, expectedHosts ...string) *turnstileVerifier {
	if verifyURL == "" {
		verifyURL = defaultTurnstileVerifyURL
	}
	return &turnstileVerifier{
		siteKey:       strings.TrimSpace(siteKey),
		secret:        strings.TrimSpace(secret),
		verifyURL:     strings.TrimSpace(verifyURL),
		expectedHosts: parseHostList(expectedHosts...),
		client:        &http.Client{Timeout: 5 * time.Second},
	}
}

func turnstileFromEnv() (*turnstileVerifier, error) {
	siteKey := strings.TrimSpace(os.Getenv("TURNSTILE_SITE_KEY"))
	secretFile := strings.TrimSpace(os.Getenv("TURNSTILE_SECRET_FILE"))
	if siteKey == "" && secretFile == "" {
		return nil, nil
	}
	if siteKey == "" || secretFile == "" {
		return nil, errors.New("set both TURNSTILE_SITE_KEY and TURNSTILE_SECRET_FILE (or neither)")
	}
	raw, err := os.ReadFile(secretFile)
	if err != nil {
		return nil, fmt.Errorf("read TURNSTILE_SECRET_FILE: %w", err)
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return nil, errors.New("TURNSTILE_SECRET_FILE is empty")
	}
	expected := strings.TrimSpace(os.Getenv("TURNSTILE_EXPECTED_HOSTS"))
	if expected == "" {
		expected = strings.TrimSpace(os.Getenv("TURNSTILE_EXPECTED_HOST"))
	}
	return newTurnstileVerifier(
		siteKey,
		secret,
		env("TURNSTILE_VERIFY_URL", defaultTurnstileVerifyURL),
		expected,
	), nil
}

func (tv *turnstileVerifier) hostAllowed(hostname string) bool {
	if len(tv.expectedHosts) == 0 {
		return true
	}
	got := stripHostPort(hostname)
	for _, want := range tv.expectedHosts {
		if got == want {
			return true
		}
	}
	return false
}

func (tv *turnstileVerifier) verify(ctx context.Context, token, remoteIP string) error {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 2048 {
		return errTurnstileInvalid
	}
	form := url.Values{}
	form.Set("secret", tv.secret)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tv.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return errTurnstileDown
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := tv.client.Do(req)
	if err != nil {
		return errTurnstileDown
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errTurnstileDown
	}
	var out struct {
		Success  bool   `json:"success"`
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&out); err != nil {
		return errTurnstileDown
	}
	if !out.Success {
		return errTurnstileInvalid
	}
	if !tv.hostAllowed(out.Hostname) {
		return errTurnstileInvalid
	}
	return nil
}
