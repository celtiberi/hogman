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

func makeRoot(t *testing.T, permitted []string, excludeIPs bool) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		PermittedDNSDomains: permitted, PermittedDNSDomainsCritical: len(permitted) > 0,
	}
	if excludeIPs {
		_, all4, _ := net.ParseCIDR("0.0.0.0/0")
		_, all6, _ := net.ParseCIDR("::/0")
		tpl.ExcludedIPRanges = []*net.IPNet{all4, all6}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), strings.ToUpper(hex.EncodeToString(sum[:]))
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
}
