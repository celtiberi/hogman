package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
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
	l := &Link{Host: u.Host, InviteToken: q.Get("t"), DeviceKey: q.Get("k"), Fingerprint: normaliseFP(q.Get("fp"))}
	switch {
	case l.InviteToken == "" && l.DeviceKey == "":
		return nil, errors.New("the link has no invite or device key in it; was it copied whole?")
	case l.InviteToken != "" && l.DeviceKey != "":
		return nil, errors.New("the link has both an invite and a device key")
	case !fpRE.MatchString(l.Fingerprint):
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
	if !excl4 || !excl6 {
		return nil, errors.New("refusing: the network's certificate is not barred from vouching for IP addresses")
	}
	s1 := sha1Hex(blk.Bytes)
	return &RootInfo{PEM: pemText, Cert: c, Fingerprint: fp, SHA1: s1, Zone: zone}, nil
}

func short(fp string) string {
	fp = normaliseFP(fp)
	if len(fp) > 16 {
		return fp[:8] + "…" + fp[len(fp)-8:]
	}
	return fp
}
