package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Link is what a person is handed:
//
//	invite: https://<host>/join#t=<invite token>&fp=<root fingerprint>
//	device: https://<host>/join#k=<device key>&fp=<root fingerprint>
//
// The fragment never leaves this machine except as the redeem request.
type Link struct {
	Host        string // the network's public control host
	InviteToken string
	DeviceKey   string
	ForShare    bool   // a server link: only for `hogman-join share`, never a whole-computer join
	Fingerprint string // SHA-256 of the root certificate, uppercase hex, no colons
}

var fpRE = regexp.MustCompile(`^[0-9A-F]{64}$`)

func normaliseFP(s string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
}

func ParseLink(raw string) (*Link, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
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
	l := &Link{Host: u.Host, InviteToken: q.Get("t"), DeviceKey: q.Get("k"), Fingerprint: normaliseFP(q.Get("fp")),
		ForShare: q.Get("for") == "share"}
	switch {
	case l.InviteToken == "" && l.DeviceKey == "":
		return nil, errors.New("the link has no invite or device key in it; was it copied whole?")
	case l.InviteToken != "" && l.DeviceKey != "":
		return nil, errors.New("the link has both an invite and a device key")
	case l.Fingerprint != "" && !fpRE.MatchString(l.Fingerprint):
		return nil, errors.New("the link has no valid certificate fingerprint (fp=...); was it copied whole?")
	}
	return l, nil
}

// RootInfo is a network root certificate that has been checked.
type RootInfo struct {
	PEM         string
	Cert        *x509.Certificate
	Fingerprint string
	SHA1        string // macOS and Windows tools identify certificates this way
	Zone        string
}

// CheckRoot verifies that pemText is the root the link promised, and that it
// can only vouch for names inside the network. A root without that limit
// could be used to impersonate any website, so it is refused outright.
func CheckRoot(pemText, wantFP, zone string) (*RootInfo, error) {
	blk, _ := pem.Decode([]byte(pemText))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("the network sent something that is not a certificate")
	}
	sum := sha256.Sum256(blk.Bytes)
	fp := strings.ToUpper(hex.EncodeToString(sum[:]))
	if fp != normaliseFP(wantFP) {
		return nil, fmt.Errorf("certificate fingerprint mismatch: the link says %s, the server sent %s. "+
			"Do not continue: either the link is wrong or someone is in the middle", short(wantFP), short(fp))
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unreadable certificate: %w", err)
	}
	if !c.IsCA {
		return nil, errors.New("the network's certificate is not a certificate authority")
	}
	now := time.Now()
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return nil, errors.New("the network's certificate is expired or not yet valid")
	}
	if !c.PermittedDNSDomainsCritical || len(c.PermittedDNSDomains) != 1 || c.PermittedDNSDomains[0] != zone {
		return nil, fmt.Errorf("refusing: the network's certificate is not limited to .%s (it permits %v). "+
			"Installing it would let it vouch for any website", zone, c.PermittedDNSDomains)
	}
	if len(c.PermittedIPRanges) > 0 {
		return nil, errors.New("refusing: the network's certificate permits IP address ranges")
	}
	if !hasExcludedAllIPs(c) {
		return nil, errors.New("refusing: the network's certificate is not barred from vouching for IP addresses")
	}
	s1 := sha1Hex(blk.Bytes)
	return &RootInfo{PEM: pemText, Cert: c, Fingerprint: fp, SHA1: s1, Zone: zone}, nil
}

func hasExcludedAllIPs(c *x509.Certificate) bool {
	var excl4, excl6 bool
	for _, n := range c.ExcludedIPRanges {
		if n == nil {
			continue
		}
		ones, bits := n.Mask.Size()
		if ones == 0 && bits == 32 && n.IP.To4() != nil {
			excl4 = true
		} else if ones == 0 && bits == 128 && n.IP.To16() != nil && n.IP.To4() == nil {
			excl6 = true
		}
	}
	return excl4 && excl6
}

type legacyRootMatch struct {
	Zone        string
	Fingerprint string
	SHA1        string
	CommonName  string
	PEM         string
}

func certSHA256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func isLegacyHogmanRoot(c *x509.Certificate, wantZone, wantFP string) (string, bool) {
	if c == nil || !c.IsCA {
		return "", false
	}
	wantZone = strings.TrimSpace(wantZone)
	wantFP = normaliseFP(wantFP)

	shapeZone := ""
	shapeMatch := false
	if c.PermittedDNSDomainsCritical && len(c.PermittedDNSDomains) == 1 && len(c.PermittedIPRanges) == 0 && hasExcludedAllIPs(c) {
		z := c.PermittedDNSDomains[0]
		if zoneRE.MatchString(z) && c.Subject.CommonName == z+" Root CA" {
			shapeZone = z
			shapeMatch = true
		}
	}

	if wantFP != "" && certSHA256Hex(c.Raw) == wantFP {
		if shapeZone != "" {
			return shapeZone, true
		}
		return wantZone, true
	}
	if shapeMatch && ((wantZone == "" && wantFP == "") || (wantZone != "" && shapeZone == wantZone)) {
		return shapeZone, true
	}
	return "", false
}

func matchingLegacyRootsFromPEM(pemData []byte, wantZone, wantFP string) []legacyRootMatch {
	var out []legacyRootMatch
	seen := map[string]bool{}
	rest := pemData
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		zone, ok := isLegacyHogmanRoot(c, wantZone, wantFP)
		if !ok {
			continue
		}
		s1 := sha1Hex(blk.Bytes)
		if seen[s1] {
			continue
		}
		seen[s1] = true
		out = append(out, legacyRootMatch{
			Zone:        zone,
			Fingerprint: certSHA256Hex(blk.Bytes),
			SHA1:        s1,
			CommonName:  c.Subject.CommonName,
			PEM:         string(pem.EncodeToMemory(blk)),
		})
	}
	return out
}

func filterLinuxLegacyAnchorFiles(dir string, names []string, wantZone, wantFP string, readFile func(string) ([]byte, error)) []string {
	var out []string
	wantName := ""
	if z := strings.TrimSpace(wantZone); z != "" {
		wantName = "hogman-" + z + ".crt"
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "hogman-") || !strings.HasSuffix(name, ".crt") {
			continue
		}
		if wantName != "" && name != wantName && normaliseFP(wantFP) == "" {
			continue
		}
		p := filepath.Join(dir, name)
		b, err := readFile(p)
		if err != nil {
			continue
		}
		if len(matchingLegacyRootsFromPEM(b, wantZone, wantFP)) > 0 {
			out = append(out, p)
		}
	}
	return out
}

func parseWindowsBase64CertsLegacyRoots(lines, wantZone, wantFP string) []legacyRootMatch {
	var out []legacyRootMatch
	seen := map[string]bool{}
	for _, rawLine := range strings.Split(lines, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			continue
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		zone, ok := isLegacyHogmanRoot(c, wantZone, wantFP)
		if !ok {
			continue
		}
		s1 := sha1Hex(der)
		if seen[s1] {
			continue
		}
		seen[s1] = true
		out = append(out, legacyRootMatch{
			Zone:        zone,
			Fingerprint: certSHA256Hex(der),
			SHA1:        s1,
			CommonName:  c.Subject.CommonName,
		})
	}
	return out
}

var sha1HexRE = regexp.MustCompile(`^[0-9A-F]{40}$`)

func parseWindowsLegacyRootSHA1s(certutilOutput, wantZone string) []string {
	var out []string
	seen := map[string]bool{}
	wantZone = strings.TrimSpace(wantZone)

	var issuer, subject, sha1 string
	flush := func() {
		if sha1HexRE.MatchString(sha1) && issuer != "" && issuer == subject {
			if cn, ok := strings.CutPrefix(subject, "CN="); ok {
				if zone, ok := strings.CutSuffix(strings.TrimSpace(cn), " Root CA"); ok && zoneRE.MatchString(zone) {
					if (wantZone == "" || zone == wantZone) && !seen[sha1] {
						seen[sha1] = true
						out = append(out, sha1)
					}
				}
			}
		}
		issuer, subject, sha1 = "", "", ""
	}
	for _, rawLine := range strings.Split(certutilOutput, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "====") {
			flush()
			continue
		}
		if v, ok := strings.CutPrefix(line, "Issuer:"); ok {
			issuer = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(line, "Subject:"); ok {
			subject = strings.TrimSpace(v)
		} else if strings.HasPrefix(strings.ToLower(line), "cert hash(sha1):") {
			if _, rest, ok := strings.Cut(line, ":"); ok {
				sha1 = normaliseFP(rest)
			}
		}
	}
	flush()
	return out
}

func short(fp string) string {
	fp = normaliseFP(fp)
	if len(fp) > 16 {
		return fp[:8] + "…" + fp[len(fp)-8:]
	}
	return fp
}
