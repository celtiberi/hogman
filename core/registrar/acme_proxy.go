package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// serverOwnsACMEName (s.mu held) enforces strict active ownership for ACME
// DNS-01 challenges: the device must be a server and must currently own the
// normalized name (never unclaimed, retired, or reserved labels).
func (s *Service) serverOwnsACMEName(d *Device, rawName string) (string, error) {
	if d == nil || d.Kind != "server" {
		return "", forbidden("server devices only")
	}
	name, err := s.normaliseName(rawName)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(name, ".") {
		if l == "home" || l == "nodes" || reservedNSLabelRE.MatchString(l) || l == "_acme-challenge" {
			return "", forbidden("%q is reserved by the network", l)
		}
	}
	n, err := s.st.NameByName(name)
	if errors.Is(err, ErrNotFound) {
		return "", forbidden("%s must be claimed by this server first", name)
	}
	if err != nil {
		return "", err
	}
	if n.RetiredAt != nil || n.MemberID != d.MemberID || n.DeviceID == nil || *n.DeviceID != d.ID {
		return "", forbidden("%s does not point at this server", name)
	}
	return name, nil
}

// serverHasClaimedName (s.mu held) reports whether d owns at least one active claimed name.
func (s *Service) serverHasClaimedName(d *Device) (bool, error) {
	if d == nil || d.Kind != "server" {
		return false, nil
	}
	all, err := s.st.Names()
	if err != nil {
		return false, err
	}
	for _, n := range all {
		if n.RetiredAt == nil && n.MemberID == d.MemberID && n.DeviceID != nil && *n.DeviceID == d.ID {
			return true, nil
		}
	}
	return false, nil
}

// ServerSetACMETXT writes an ACME DNS-01 challenge TXT record for a name owned by d.
func (s *Service) ServerSetACMETXT(ctx context.Context, d *Device, rawName, value string) (string, error) {
	if s.acme == nil {
		return "", &Problem{Status: 503, Msg: "ACME challenge DNS is not configured"}
	}
	if !acmeTXTValueRE.MatchString(value) {
		return "", bad("invalid ACME TXT value")
	}
	s.mu.Lock()
	name, err := s.serverOwnsACMEName(d, rawName)
	s.mu.Unlock()
	if err != nil {
		return "", err
	}
	if ok, retry := s.memberTXTLim.CheckLimit(d.MemberID, s.cfg.MaxMemberACMETXTPerHour, s.clock()); !ok {
		return "", &Problem{Status: 429, Msg: "too many ACME challenge writes for this member in the last hour", RetryAfter: retry}
	}
	fqdn := "_acme-challenge." + name + "." + s.cfg.Zone
	if err := s.acme.SetTXT(ctx, fqdn, value); err != nil {
		return "", err
	}
	s.memberTXTLim.Record(d.MemberID, s.clock())
	return fqdn, nil
}

// ServerDeleteACMETXT removes an ACME DNS-01 challenge TXT record for a name owned by d.
func (s *Service) ServerDeleteACMETXT(ctx context.Context, d *Device, rawName, value string) error {
	if s.acme == nil {
		return &Problem{Status: 503, Msg: "ACME challenge DNS is not configured"}
	}
	if !acmeTXTValueRE.MatchString(value) {
		return bad("invalid ACME TXT value")
	}
	s.mu.Lock()
	name, err := s.serverOwnsACMEName(d, rawName)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	fqdn := "_acme-challenge." + name + "." + s.cfg.Zone
	return s.acme.DeleteTXT(ctx, fqdn, value)
}

// ServerMintACMEEAB obtains one single-use fallback CA EAB pair for an enrolled
// server that currently owns at least one claimed name.
func (s *Service) ServerMintACMEEAB(ctx context.Context, d *Device) (*EABPair, error) {
	if d == nil || d.Kind != "server" {
		return nil, forbidden("server devices only")
	}
	if s.acme == nil {
		return nil, &Problem{Status: 503, Msg: "ACME challenge DNS is not configured"}
	}
	s.mu.Lock()
	hasName, err := s.serverHasClaimedName(d)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !hasName {
		return nil, forbidden("claim a name for this server first")
	}
	nowTS := s.clock()
	if memberOK, memberRetry := s.memberEABLim.CheckLimit(d.MemberID, s.cfg.MaxMemberEABPerDay, nowTS); !memberOK {
		return nil, &Problem{Status: 429, Msg: "too many fallback account keys for this member today", RetryAfter: memberRetry}
	}
	if serverOK, serverRetry := s.serverEABLim.CheckLimit(d.ID, s.cfg.MaxServerEABPerDay, nowTS); !serverOK {
		return nil, &Problem{Status: 429, Msg: "too many fallback account keys for this server today", RetryAfter: serverRetry}
	}
	pair, err := s.acme.MintEAB(ctx)
	if err != nil {
		return nil, err
	}
	recTS := s.clock()
	s.memberEABLim.Record(d.MemberID, recTS)
	s.serverEABLim.Record(d.ID, recTS)
	s.st.Audit(d.Member, "acme.eab", fmt.Sprintf("device#%d", d.ID), "")
	return pair, nil
}
