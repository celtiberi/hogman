package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

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

func trimMatchingQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return strings.TrimSpace(s[1 : len(s)-1])
		}
	}
	return s
}

func ParseLink(raw string) (*Link, error) {
	u, err := url.Parse(trimMatchingQuotes(raw))
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
	l := &Link{Host: strings.ToLower(u.Host), InviteToken: q.Get("t"), DeviceKey: q.Get("k"),
		ForShare: q.Get("for") == "share"}
	switch {
	case l.InviteToken == "" && l.DeviceKey == "":
		return nil, errors.New("the link has no invite or device key in it; was it copied whole?")
	case l.InviteToken != "" && l.DeviceKey != "":
		return nil, errors.New("the link has both an invite and a device key")
	}
	return l, nil
}
