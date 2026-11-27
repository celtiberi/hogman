package link

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// UserError marks an actionable user-facing error (exits 1 without stack/prefix noise).
type UserError struct{ Msg string }

func (e *UserError) Error() string { return e.Msg }

// Errorf constructs a UserError.
func Errorf(f string, a ...any) error { return &UserError{Msg: fmt.Sprintf(f, a...)} }

// UsageError marks CLI syntax / flag / argument errors that should exit with code 2.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// UsageErrorf constructs a UsageError.
func UsageErrorf(f string, a ...any) error { return &UsageError{Msg: fmt.Sprintf(f, a...)} }

// Link is what a person is handed:
//
//	invite: https://<host>/join#t=<invite token>
//	device: https://<host>/join#k=<device key>
//
// The fragment never leaves this machine except as the redeem request.
type Link struct {
	Host        string // the network's public control host
	InviteToken string
	DeviceKey   string
	ForShare    bool // a server link: only for `hogman share`, never a whole-computer join
}

// TrimMatchingQuotes removes a single pair of matching surrounding single or double quotes.
func TrimMatchingQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return strings.TrimSpace(s[1 : len(s)-1])
		}
	}
	return s
}

// Parse parses and validates a Hogman invite or device join link.
func Parse(raw string) (*Link, error) {
	u, err := url.Parse(TrimMatchingQuotes(raw))
	if err != nil {
		return nil, fmt.Errorf("not a link: %w", err)
	}
	if u.User != nil {
		return nil, errors.New("the link must not contain credentials")
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("the link must start with https://")
	}
	if strings.TrimSuffix(u.Path, "/") != "/join" {
		return nil, errors.New("this is not a join link (expected https://<host>/join#...)")
	}
	q, err := url.ParseQuery(u.Fragment)
	if err != nil {
		return nil, fmt.Errorf("the part after # is damaged: %w", err)
	}
	if q.Get("fp") != "" {
		return nil, errors.New("this link is from an older release (carries fp=) and is no longer supported; ask whoever sent it for a fresh one")
	}
	l := &Link{
		Host:        strings.ToLower(u.Host),
		InviteToken: q.Get("t"),
		DeviceKey:   q.Get("k"),
		ForShare:    q.Get("for") == "share",
	}
	switch {
	case l.InviteToken == "" && l.DeviceKey == "":
		return nil, errors.New("the link has no invite or device key in it; was it copied whole?")
	case l.InviteToken != "" && l.DeviceKey != "":
		return nil, errors.New("the link has both an invite and a device key")
	}
	return l, nil
}

var (
	HandleRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	dnsLabelRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	nonHostnameRE = regexp.MustCompile(`[^a-z0-9-]+`)
	penQueryRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	meshRanges    = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
)

// InMeshRanges reports whether ip falls within the Tailscale/Headscale CGNAT mesh range.
func InMeshRanges(ip netip.Addr) bool {
	for _, r := range meshRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidPublicDNSName validates a canonical lowercase public DNS name with at least two labels.
func ValidPublicDNSName(name string) bool {
	if name == "" || len(name) > 253 || name != strings.ToLower(name) ||
		strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lbl := range labels {
		if !dnsLabelRE.MatchString(lbl) {
			return false
		}
	}
	return true
}

// ValidatePublicZone enforces the binding between a control gate host and its claimed pen zone.
func ValidatePublicZone(inviteHost, zone string) error {
	h := strings.TrimSpace(inviteHost)
	if hostPart, _, err := net.SplitHostPort(h); err == nil {
		h = hostPart
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if net.ParseIP(h) != nil || !ValidPublicDNSName(h) {
		return Errorf("%s is not a valid domain name for public certificates", inviteHost)
	}
	if !ValidPublicDNSName(zone) || strings.HasSuffix(zone, ".hogman") {
		return Errorf("%s sent an unexpected network name %q", inviteHost, zone)
	}
	eTLD1, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return Errorf("%s is not under a registrable public domain: %v", inviteHost, err)
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(zone); err != nil {
		return Errorf("%s sent an invalid public network name %q", inviteHost, zone)
	}
	// Hosted gates (<pen>.gate.<base>) must bind exclusively to <pen>.pens.<base>.
	if parts := strings.SplitN(h, ".", 3); len(parts) == 3 && parts[1] == "gate" && parts[0] != "" && parts[2] != "" &&
		(parts[2] == eTLD1 || strings.HasSuffix(parts[2], "."+eTLD1)) {
		want := parts[0] + ".pens." + parts[2]
		if zone != want {
			return Errorf("refusing: %s claimed zone %q instead of %q", inviteHost, zone, want)
		}
		return nil
	}
	// Self-hosted gates must choose a strict subdomain of the gate's registrable domain.
	if !strings.HasSuffix(zone, "."+eTLD1) || len(zone) <= len("."+eTLD1) {
		return Errorf("refusing: %s claimed zone %q outside %s", inviteHost, zone, eTLD1)
	}
	return nil
}

const MaxHostnameLen = 63

// SanitizeHostname normalizes a computer hostname into a single safe DNS label.
// Rejects hostnames longer than 63 characters rather than truncating them.
func SanitizeHostname(raw string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(raw))
	h = strings.Split(h, ".")[0]
	h = nonHostnameRE.ReplaceAllString(h, "-")
	h = strings.Trim(h, "-")
	if len(h) > MaxHostnameLen {
		return "", Errorf("device name %q is %d characters (max %d) — pick a shorter name with --hostname", h, len(h), MaxHostnameLen)
	}
	return h, nil
}

// DefaultHostname returns the sanitized local OS hostname or "device".
func DefaultHostname() (string, error) {
	raw, _ := os.Hostname()
	h, err := SanitizeHostname(raw)
	if err != nil {
		return "", Errorf("this computer's hostname %q is over %d characters — pick a shorter device name with --hostname", raw, MaxHostnameLen)
	}
	if h != "" {
		return h, nil
	}
	return "device", nil
}

// ValidatePenQuery ensures a --pen / HOGMAN_PEN value is a valid DNS label or zone name.
func ValidatePenQuery(raw string) (string, error) {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if q == "" || len(q) > 253 || !penQueryRE.MatchString(q) {
		return "", Errorf("invalid pen name %q: must be a DNS name or short pen label (letters, digits, dashes, dots)", raw)
	}
	return q, nil
}

// HostOf returns the bare lowercase hostname of a URL ("" if invalid or empty).
func HostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// PenMatchesQuery reports whether a pen (zone + optional control host) matches
// a user query: exact full zone, exact control host, or exact first DNS label.
func PenMatchesQuery(zone, loginServer, query string) bool {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(query)), ".")
	if q == "" {
		return false
	}
	z := strings.ToLower(zone)
	if q == z {
		return true
	}
	if h := HostOf(loginServer); h != "" && q == h {
		return true
	}
	if !strings.Contains(q, ".") {
		if first, _, ok := strings.Cut(z, "."); ok && first == q {
			return true
		}
	}
	return false
}

// ShortPenLabel returns the leading DNS label of a pen zone.
func ShortPenLabel(zone string) string {
	z := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if first, _, ok := strings.Cut(z, "."); ok && first != "" {
		return first
	}
	return z
}

// FirstLine returns the first non-empty trimmed line of s.
func FirstLine(s string) string { return strings.SplitN(strings.TrimSpace(s), "\n", 2)[0] }
