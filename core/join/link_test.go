package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"path/filepath"
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
		{in: "https://hs.example.com/join#t=x",
			check: func(l *Link) bool { return l.InviteToken == "x" && l.Fingerprint == "" }},
		{in: "https://hs.example.com/join#k=hskey-auth-xyz&for=share",
			check: func(l *Link) bool { return l.DeviceKey == "hskey-auth-xyz" && l.ForShare && l.Fingerprint == "" }},
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

func makeHogmanNamedRoot(t *testing.T, cn string, permitted []string, exclIPs []string) (pemStr, rawB64, fp, s1 string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var excl []*net.IPNet
	for _, c := range exclIPs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		excl = append(excl, n)
	}
	tpl := &x509.Certificate{
		SerialNumber:                big.NewInt(1),
		Subject:                     pkix.Name{CommonName: cn},
		NotBefore:                   time.Now().Add(-time.Hour),
		NotAfter:                    time.Now().Add(time.Hour),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		KeyUsage:                    x509.KeyUsageCertSign,
		PermittedDNSDomains:         permitted,
		PermittedDNSDomainsCritical: len(permitted) > 0,
		ExcludedIPRanges:            excl,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBytes), base64.StdEncoding.EncodeToString(der), certSHA256Hex(der), sha1Hex(der)
}

func TestIsLegacyHogmanRootAndPEMMatching(t *testing.T) {
	hogPEM, _, hogFP, hogS1 := makeHogmanNamedRoot(t, "bobo.hogman Root CA", []string{"bobo.hogman"}, []string{"0.0.0.0/0", "::/0"})
	otherPEM, _, otherFP, _ := makeHogmanNamedRoot(t, "other.hogman Root CA", []string{"other.hogman"}, []string{"0.0.0.0/0", "::/0"})
	foreignPEM, _, _, _ := makeHogmanNamedRoot(t, "Corporate Root CA", nil, nil)
	partialPEM, _, _, _ := makeHogmanNamedRoot(t, "evil.hogman Root CA", []string{"evil.hogman"}, []string{"0.0.0.0/0"})

	bundle := []byte(foreignPEM + hogPEM + otherPEM + partialPEM)

	// Empty zone + empty FP matches both pre-RootFP Hogman CAs, skipping foreign/incomplete CAs.
	all := matchingLegacyRootsFromPEM(bundle, "", "")
	if len(all) != 2 || all[0].Zone != "bobo.hogman" || all[1].Zone != "other.hogman" {
		t.Fatalf("wildcard match = %+v, want bobo.hogman + other.hogman", all)
	}

	// Specific zone matches only that zone.
	onlyBobo := matchingLegacyRootsFromPEM(bundle, "bobo.hogman", "")
	if len(onlyBobo) != 1 || onlyBobo[0].Fingerprint != hogFP || onlyBobo[0].SHA1 != hogS1 {
		t.Fatalf("zone match = %+v, want bobo.hogman fp=%s", onlyBobo, hogFP)
	}

	// Fingerprint match works even when zone differs or CommonName differs from shape.
	fpOnly := matchingLegacyRootsFromPEM([]byte(foreignPEM+otherPEM), "different.zone", otherFP)
	if len(fpOnly) != 1 || fpOnly[0].Fingerprint != otherFP {
		t.Fatalf("fp match = %+v, want %s", fpOnly, otherFP)
	}
}

func TestFilterLinuxLegacyAnchorFiles(t *testing.T) {
	hogPEM, _, hogFP, _ := makeHogmanNamedRoot(t, "bobo.hogman Root CA", []string{"bobo.hogman"}, []string{"0.0.0.0/0", "::/0"})
	otherPEM, _, _, _ := makeHogmanNamedRoot(t, "other.hogman Root CA", []string{"other.hogman"}, []string{"0.0.0.0/0", "::/0"})
	foreignPEM, _, _, _ := makeHogmanNamedRoot(t, "Unrelated Corp CA", nil, nil)

	const dir = "/usr/local/share/ca-certificates"
	files := map[string][]byte{
		filepath.Join(dir, "hogman-bobo.hogman.crt"): []byte(hogPEM),
		filepath.Join(dir, "hogman-other.hogman.crt"): []byte(otherPEM),
		filepath.Join(dir, "hogman-fake.crt"):          []byte(foreignPEM),
		filepath.Join(dir, "corp-root.crt"):            []byte(hogPEM),
	}
	names := []string{"hogman-bobo.hogman.crt", "hogman-other.hogman.crt", "hogman-fake.crt", "corp-root.crt"}
	read := func(p string) ([]byte, error) { return files[p], nil }

	gotBobo := filterLinuxLegacyAnchorFiles(dir, names, "bobo.hogman", "", read)
	wantBobo := []string{filepath.Join(dir, "hogman-bobo.hogman.crt")}
	if strings.Join(gotBobo, ",") != strings.Join(wantBobo, ",") {
		t.Fatalf("gotBobo = %v, want %v", gotBobo, wantBobo)
	}

	gotAll := filterLinuxLegacyAnchorFiles(dir, names, "", "", read)
	if len(gotAll) != 2 || gotAll[0] != wantBobo[0] || gotAll[1] != filepath.Join(dir, "hogman-other.hogman.crt") {
		t.Fatalf("gotAll = %v, want bobo + other hogman-*.crt", gotAll)
	}

	gotFP := filterLinuxLegacyAnchorFiles(dir, names, "", hogFP, read)
	if len(gotFP) != 1 || gotFP[0] != wantBobo[0] {
		t.Fatalf("gotFP = %v, want %v", gotFP, wantBobo)
	}
}

func TestParseWindowsLegacyRootMatchers(t *testing.T) {
	_, hogB64, hogFP, hogS1 := makeHogmanNamedRoot(t, "bobo.hogman Root CA", []string{"bobo.hogman"}, []string{"0.0.0.0/0", "::/0"})
	_, foreignB64, _, _ := makeHogmanNamedRoot(t, "Corp Root CA", nil, nil)

	lines := foreignB64 + "\n\n  " + hogB64 + "  \nnot-base64\n"
	got := parseWindowsBase64CertsLegacyRoots(lines, "", hogFP)
	if len(got) != 1 || got[0].SHA1 != hogS1 || got[0].Zone != "bobo.hogman" {
		t.Fatalf("base64 match = %+v, want SHA1=%s", got, hogS1)
	}

	certutilOut := `Root "Trusted Root Certification Authorities"
================ Certificate 0 ================
Serial Number: 01
Issuer: CN=DigiCert Global Root CA
Subject: CN=DigiCert Global Root CA
Cert Hash(sha1): aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd

================ Certificate 1 ================
Serial Number: 02
Issuer: CN=bobo.hogman Root CA
Subject: CN=bobo.hogman Root CA
Cert Hash(sha1): ` + hogS1 + `
`
	sha1s := parseWindowsLegacyRootSHA1s(certutilOut, "")
	if len(sha1s) != 1 || sha1s[0] != hogS1 {
		t.Fatalf("certutil SHA1s = %v, want [%s]", sha1s, hogS1)
	}
	if none := parseWindowsLegacyRootSHA1s(certutilOut, "other.hogman"); len(none) != 0 {
		t.Fatalf("wrong zone matched: %v", none)
	}
}
