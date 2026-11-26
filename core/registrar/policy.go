package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

func (s *Service) isRenewOnly() bool {
	return s.billingPolicy().IsRenewOnly()
}

// buildPolicy renders the default-deny Headscale ACL policy over the IPv4 mesh
// addresses of devices whose members are active. Suspended and removed members'
// devices appear nowhere, so they can reach nothing.
//
// Mesh policy is intentionally IPv4-only (100.64.0.0/10 holds 4.19M addresses
// per pen): omitting IPv6 shrinks the policy JSON ~4x, halves every peer's
// WireGuard packet-filter entries, and leaves mesh IPv6 default-denied (D-11).
// During a renew_only wake (I-7 Part 2), only active owner/admin personal
// devices can reach tag:infra (DNS 53 + portal 443); regular members, server
// devices, and all shares are excluded from the Headscale netmap.
func (s *Service) buildPolicy() (string, bool, error) {
	live, err := s.st.LiveDevices()
	if err != nil {
		return "", false, err
	}
	membersByID := map[int64]*Member{}
	ms, err := s.st.Members()
	if err != nil {
		return "", false, err
	}
	for _, m := range ms {
		membersByID[m.ID] = m
	}
	renewOnly := s.isRenewOnly()
	infraSrc := []string{}
	serverSrc := []string{}
	servers := []string{}
	for _, d := range live {
		m := membersByID[d.MemberID]
		if m == nil || m.Status != "active" {
			continue
		}
		if renewOnly {
			if d.Kind != "personal" || (m.Role != "owner" && m.Role != "admin") {
				continue
			}
		}
		if d.IPv4 == "" {
			continue
		}
		infraSrc = append(infraSrc, d.IPv4)
		if !renewOnly {
			if d.Kind == "server" {
				servers = append(servers, d.IPv4)
			} else {
				serverSrc = append(serverSrc, d.IPv4)
			}
		}
	}
	sort.Strings(infraSrc)
	sort.Strings(serverSrc)
	sort.Strings(servers)
	infraSrc = append(infraSrc, "tag:infra")
	serverSrc = append(serverSrc, "tag:infra")

	type grant struct {
		Src []string `json:"src"`
		Dst []string `json:"dst"`
		IP  []string `json:"ip"`
	}
	// The pen's own services: DNS and the home page (HTTPS).
	grants := []grant{{Src: infraSrc, Dst: []string{"tag:infra"}, IP: []string{"53", "443"}}}
	if !renewOnly && len(servers) > 0 {
		// HTTPS only (D-11): active personal devices (and tag:infra) reach servers
		// on 443. Server devices are isolated from each other by default.
		grants = append(grants, grant{Src: serverSrc, Dst: servers, IP: []string{"443"}})
	}
	pol := map[string]any{
		"tagOwners": map[string][]string{"tag:infra": {}, "tag:server": {}},
		"grants":    grants,
	}
	b, err := json.Marshal(pol)
	return string(b), renewOnly, err
}

func (s *Service) applyPolicy(ctx context.Context) error {
	_, err := s.applyPolicyTracked(ctx)
	return err
}

func (s *Service) applyPolicyTracked(ctx context.Context) (bool, error) {
	logger := s.loggerOrDefault()
	// Serialize policy builds + Headscale pushes across registrar serve and
	// separate CLI processes so an older in-flight SetPolicy cannot overwrite
	// a newer revocation (e.g. CLI Suspend/Kick).
	if unlock, lockErr := s.st.lockPolicyFile(); lockErr == nil {
		defer unlock()
	} else {
		logger.Warn("policy advisory lock failed (proceeding with generation re-check)", "err", lockErr)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	const maxReconcilePasses = 3
	var renewOnly bool
	for pass := 0; pass < maxReconcilePasses; pass++ {
		// Snapshot policy_gen BEFORE reading members/devices in buildPolicy() so any
		// concurrent mutation leaves policy_gen > gen.
		gen, appliedGen, genErr := s.st.PolicyGenerations()
		pol, curRenewOnly, err := s.buildPolicy()
		if err != nil {
			return false, err
		}
		renewOnly = curRenewOnly
		// Rule: "dirty always pushes" even when pol == s.lastPolicy. lastPolicy
		// is process-local memory and can go stale across CLI SQLite mutations
		// (e.g. serve pushed P2, CLI resumed to P1, then CLI suspended back to P2
		// and its push failed: skipping would leave a suspended member on the
		// mesh). Note: .renew-only is file-driven (not a SQLite trigger), so its
		// transitions rely on pol != s.lastPolicy on the fast-sync loop.
		dirty := genErr != nil || gen > appliedGen
		if pol == s.lastPolicy && !dirty {
			return renewOnly, nil
		}
		t0 := time.Now()
		if err := s.hs.SetPolicy(ctx, pol); err != nil {
			dur := time.Since(t0).Round(time.Millisecond)
			logger.Error("policy: failed", "gen", gen, "bytes", len(pol), "dur", dur, "dur_ms", dur.Milliseconds(), "err", err)
			return false, fmt.Errorf("set policy: %w", err)
		}
		dur := time.Since(t0).Round(time.Millisecond)
		logger.Info("policy: applied", "gen", gen, "bytes", len(pol), "dur", dur, "dur_ms", dur.Milliseconds())
		s.lastPolicy = pol
		if genErr == nil {
			_ = s.st.MarkPolicyApplied(gen)
			// Defense in depth: if another mutation committed while SetPolicy was
			// in flight, clear lastPolicy and immediately reconcile the newer gen.
			if curGen, _, reErr := s.st.PolicyGenerations(); reErr == nil && curGen > gen {
				s.lastPolicy = ""
				continue
			}
		}
		return renewOnly, nil
	}
	return renewOnly, nil
}
