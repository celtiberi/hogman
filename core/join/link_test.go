package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseLink(t *testing.T) {
	legacyFP := strings.Repeat("AB", 32)
	cases := []struct {
		in      string
		wantErr string
		check   func(*Link) bool
	}{
		{in: "https://hs.example.com/join#t=hmi_abc",
			check: func(l *Link) bool {
				return l.Host == "hs.example.com" && l.InviteToken == "hmi_abc" && l.DeviceKey == ""
			}},
		{in: "  https://hs.example.com/join/#k=hskey-auth-xyz  ",
			check: func(l *Link) bool { return l.Host == "hs.example.com" && l.DeviceKey == "hskey-auth-xyz" }},
		{in: "https://hs.example.com/join#k=hskey-auth-xyz&for=share",
			check: func(l *Link) bool { return l.DeviceKey == "hskey-auth-xyz" && l.ForShare }},
		{in: "http://hs.example.com/join#t=x", wantErr: "https://"},
		{in: "https://hs.example.com/other#t=x", wantErr: "not a join link"},
		{in: "https://hs.example.com/join#for=share", wantErr: "no invite or device key"},
		{in: "https://hs.example.com/join#t=x&fp=" + legacyFP, wantErr: "older release"},
		{in: "https://hs.example.com/join#t=x&k=y", wantErr: "both"},
		{in: "https://user:pass@hs.example.com/join#t=x", wantErr: "credentials"},
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

// A server (share) link is marked for=share; a plain device link isn't.
func TestParseLinkForShare(t *testing.T) {
	l, err := ParseLink("https://hs.example.com/join#k=hskey-auth-x&for=share")
	if err != nil || !l.ForShare || l.DeviceKey != "hskey-auth-x" {
		t.Fatalf("share link: %+v, %v", l, err)
	}
	l, err = ParseLink("https://hs.example.com/join#k=hskey-auth-x")
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
		filepath.Join(dir, "hogman-bobo.hogman.crt"):  []byte(hogPEM),
		filepath.Join(dir, "hogman-other.hogman.crt"): []byte(otherPEM),
		filepath.Join(dir, "hogman-fake.crt"):         []byte(foreignPEM),
		filepath.Join(dir, "corp-root.crt"):           []byte(hogPEM),
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
