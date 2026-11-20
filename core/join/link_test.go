package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

const fp64 = "485E37903CBA30B0D8FA0050C1D83486497247EE5B5A53C5943E39629FCC9F82"

func TestParseLink(t *testing.T) {
	cases := []struct {
		in      string
		wantErr string
		check   func(*Link) bool
	}{
		{in: "https://hs.example.com/join#t=hmi_abc&fp=" + fp64,
			check: func(l *Link) bool {
				return l.Host == "hs.example.com" && l.InviteToken == "hmi_abc" && l.DeviceKey == ""
			}},
		{in: "https://hs.example.com/join#k=hskey-auth-xyz&fp=" + strings.ToLower(fp64),
			check: func(l *Link) bool { return l.DeviceKey == "hskey-auth-xyz" && l.Fingerprint == fp64 }},
		{in: "  https://hs.example.com/join/#t=x&fp=48:5E:37:90:3C:BA:30:B0:D8:FA:00:50:C1:D8:34:86:49:72:47:EE:5B:5A:53:C5:94:3E:39:62:9F:CC:9F:82  ",
			check: func(l *Link) bool { return l.Fingerprint == fp64 }},
		{in: "http://hs.example.com/join#t=x&fp=" + fp64, wantErr: "https://"},
		{in: "https://hs.example.com/other#t=x&fp=" + fp64, wantErr: "not a join link"},
		{in: "https://hs.example.com/join#fp=" + fp64, wantErr: "no invite or device key"},
		{in: "https://hs.example.com/join#t=x", wantErr: "fingerprint"},
		{in: "https://hs.example.com/join#t=x&fp=ABC", wantErr: "fingerprint"},
		{in: "https://hs.example.com/join#t=x&k=y&fp=" + fp64, wantErr: "both"},
		{in: "https://user:pass@hs.example.com/join#t=x&fp=" + fp64, wantErr: "credentials"},
	}
	for _, c := range cases {
		l, err := ParseLink(c.in)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%q: want error containing %q, got %v", c.in, c.wantErr, err)
			}
			continue
		}
		if err != nil || !c.check(l) {
			t.Errorf("%q: got %+v, %v", c.in, l, err)
		}
	}
}

func makeCustomRoot(t *testing.T, permitted []string, permIPs, exclIPs []string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	parseCIDRs := func(cidrs []string) []*net.IPNet {
		var out []*net.IPNet
		for _, c := range cidrs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, n)
		}
		return out
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		PermittedDNSDomains: permitted, PermittedDNSDomainsCritical: len(permitted) > 0,
		PermittedIPRanges: parseCIDRs(permIPs),
		ExcludedIPRanges:  parseCIDRs(exclIPs),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), strings.ToUpper(hex.EncodeToString(sum[:]))
}

func makeRoot(t *testing.T, permitted []string, excludeIPs bool) (string, string) {
	t.Helper()
	var excl []string
	if excludeIPs {
		excl = []string{"0.0.0.0/0", "::/0"}
	}
	return makeCustomRoot(t, permitted, nil, excl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
}

func TestCheckRoot(t *testing.T) {
	good, goodFP := makeRoot(t, []string{"bobo.hogman"}, true)
	if _, err := CheckRoot(good, goodFP, "bobo.hogman"); err != nil {
		t.Fatalf("good root rejected: %v", err)
	}
	if _, err := CheckRoot(good, fp64, "bobo.hogman"); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("wrong fingerprint accepted: %v", err)
	}
	if _, err := CheckRoot(good, goodFP, "other.hogman"); err == nil {
		t.Errorf("root for another zone accepted")
	}
	open, openFP := makeRoot(t, nil, true)
	if _, err := CheckRoot(open, openFP, "bobo.hogman"); err == nil || !strings.Contains(err.Error(), "not limited") {
		t.Errorf("unconstrained root accepted: %v", err)
	}
	noIP, noIPFP := makeRoot(t, []string{"bobo.hogman"}, false)
	if _, err := CheckRoot(noIP, noIPFP, "bobo.hogman"); err == nil || !strings.Contains(err.Error(), "IP") {
		t.Errorf("root allowing IPs accepted: %v", err)
	}

	now := time.Now()
	badCases := []struct {
		name      string
		permIPs   []string
		exclIPs   []string
		notBefore time.Time
		notAfter  time.Time
	}{
		{"permitted IPv4 range", []string{"0.0.0.0/0"}, []string{"0.0.0.0/0", "::/0"}, now.Add(-time.Minute), now.Add(time.Hour)},
		{"narrow IP exclusion", nil, []string{"127.0.0.1/32"}, now.Add(-time.Minute), now.Add(time.Hour)},
		{"IPv4 exclusion without IPv6", nil, []string{"0.0.0.0/0"}, now.Add(-time.Minute), now.Add(time.Hour)},
		{"expired root", nil, []string{"0.0.0.0/0", "::/0"}, now.Add(-2 * time.Hour), now.Add(-time.Minute)},
	}
	for _, tc := range badCases {
		pemText, fp := makeCustomRoot(t, []string{"bobo.hogman"}, tc.permIPs, tc.exclIPs, tc.notBefore, tc.notAfter)
		if _, err := CheckRoot(pemText, fp, "bobo.hogman"); err == nil {
			t.Errorf("%s: expected CheckRoot to reject certificate", tc.name)
		}
	}
}

// A server (share) link is marked for=share; a plain device link isn't.
func TestParseLinkForShare(t *testing.T) {
	fp := strings.Repeat("AB", 32)
	l, err := ParseLink("https://hs.example.com/join#k=hskey-auth-x&fp=" + fp + "&for=share")
	if err != nil || !l.ForShare || l.DeviceKey != "hskey-auth-x" {
		t.Fatalf("share link: %+v, %v", l, err)
	}
	l, err = ParseLink("https://hs.example.com/join#k=hskey-auth-x&fp=" + fp)
	if err != nil || l.ForShare {
		t.Fatalf("device link: %+v, %v", l, err)
	}
}
