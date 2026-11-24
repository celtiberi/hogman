package main

import (
	"strings"
	"testing"
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
