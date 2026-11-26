package registrar

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"hogman/registrar/internal/headscale"
	"hogman/registrar/internal/store"
)

// canTriggerInlineSync bounds sequential inline Sync() calls triggered by
// unknown peers when an open device key exists, including across Headscale errors.
func (s *Service) canTriggerInlineSync() bool {
	s.syncMu.Lock()
	last := s.lastSyncAttemptAt
	s.syncMu.Unlock()
	if last.IsZero() {
		return true
	}
	return s.clock().Sub(last) >= InlineSyncCooldown
}

// Sync reconciles Headscale with the ledger and is single-flight: overlapping
// callers share the in-flight pass instead of queuing duplicate Headscale API
// calls. The shared worker runs under the service's shutdown-aware base context
// with a 30s timeout so a disconnecting HTTP caller cannot poison the pass,
// while SIGTERM still cancels cleanly.
//
// Responsibilities and timing:
//   - Enrol newly joined devices (recording HSNodeID, WireGuard NodeKey, and
//     pinned MachineKey), mark their one-time device key used, and push the
//     updated ACL policy: fast interval (SYNC_INTERVAL, default 3s) while an
//     open device key exists, plus cooldown-gated inline Sync on miss.
//   - Retry interrupted Headscale user/node deletions for removed members
//     (including stray tag:server nodes with no Headscale user): fast interval
//     while pending cleanup exists.
//   - Retry any pending policy push after cross-process CLI mutations or
//     transient failures: tracked via SQLite trigger-bumped policy_gen > applied_gen.
//   - Reflect renew_only billing transitions in ACL policy: checked locally on
//     every fast tick and synced immediately on transition.
//   - Backfill missing node_key/machine_key on upgraded rows, update device
//     names/IPs, notice out-of-band headscale CLI deletions, and refresh the
//     display-only presence snapshot: idle interval (SYNC_IDLE_INTERVAL, 30s).
func (s *Service) Sync(ctx context.Context) error {
	s.syncMu.Lock()
	call := s.syncFlight
	if call == nil {
		call = &syncCall{done: make(chan struct{})}
		s.syncFlight = call
		started := s.startBackground(func() {
			workCtx, cancel := context.WithTimeout(s.baseContext(), syncFlightTimeout)
			defer cancel()
			renewOnly, err := s.syncOnce(workCtx)
			ts := s.clock()
			s.syncMu.Lock()
			call.err = err
			s.lastSyncAttemptAt = ts
			if err == nil {
				s.lastSyncAt = ts
				s.lastRenewOnly = renewOnly
				s.syncedOnce = true
			}
			close(call.done)
			s.syncFlight = nil
			s.syncMu.Unlock()
		})
		if !started {
			s.syncFlight = nil
			s.syncMu.Unlock()
			return context.Canceled
		}
	}
	s.syncMu.Unlock()

	select {
	case <-call.done:
		return call.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) LastSyncAt() time.Time {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	return s.lastSyncAt
}

// NeedsFastSync reports (using only local SQLite and billing file state, zero
// Headscale calls) whether background reconciliation should run on the fast
// polling interval rather than backing off to the idle interval.
func (s *Service) NeedsFastSync() bool {
	s.syncMu.Lock()
	synced := s.syncedOnce
	prevRenew := s.lastRenewOnly
	s.syncMu.Unlock()
	if !synced || s.IsRenewOnly() != prevRenew {
		return true
	}
	if pGen, aGen, err := s.st.PolicyGenerations(); err != nil || pGen > aGen {
		return true
	}
	if open, err := s.st.HasOpenDeviceKeys(); err != nil || open {
		return true
	}
	if pending, err := s.st.HasPendingMemberCleanup(); err != nil || pending {
		return true
	}
	pendingIDs, err := s.st.PendingDeviceDeleteIDs()
	if err != nil {
		return true
	}
	if len(pendingIDs) > 0 {
		s.deferredDelMu.Lock()
		defer s.deferredDelMu.Unlock()
		for _, id := range pendingIDs {
			if !s.deferredPendingDel[id] {
				return true
			}
		}
	}
	return false
}

// detectSyncDrift checks all live devices for machine_key or owner/tag binding
// drift before any database writes happen, powering the mass-retirement circuit
// breaker in syncOnce.
func detectSyncDrift(nodes []headscale.Node, byNode map[string]*store.Device, members map[int64]*store.Member) map[string]string {
	driftReasons := map[string]string{}
	for _, n := range nodes {
		if n.HasTag("tag:infra") {
			continue
		}
		d, ok := byNode[n.ID]
		if !ok {
			continue
		}
		m := members[d.MemberID]
		if m != nil && m.Status == "removed" {
			continue
		}
		dMachKey, dHasMK := canonicalMachineKey(d.MachineKey)
		nMachKey, nHasMK := canonicalMachineKey(n.MachineKey)
		if dHasMK {
			if nHasMK && nMachKey != dMachKey {
				driftReasons[n.ID] = "machine_key changed"
			} else if nHasMK && m != nil && !nodeMatchesBinding(m, d, &n) {
				driftReasons[n.ID] = "owner/tag binding changed"
			}
		} else if d.MachineKey == "" && nHasMK && m != nil && !nodeMatchesBinding(m, d, &n) {
			driftReasons[n.ID] = "owner/tag binding mismatch"
		}
	}
	return driftReasons
}

func (s *Service) syncOnce(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	logger := s.loggerOrDefault()

	nodes, err := s.hs.Nodes(ctx)
	if err != nil {
		return false, err
	}
	s.setPresence(nodes)
	keys, err := s.st.PendingDeviceKeys(s.clock().Unix() - 86400)
	if err != nil {
		return false, err
	}
	live, err := s.st.LiveDevices()
	if err != nil {
		return false, err
	}
	byNode := make(map[string]*store.Device, len(live))
	for _, d := range live {
		byNode[d.HSNodeID] = d
	}
	allMembers, err := s.st.Members()
	if err != nil {
		return false, err
	}
	members := make(map[int64]*store.Member, len(allMembers))
	for _, m := range allMembers {
		members[m.ID] = m
	}

	// Phase 1: pre-check drift across all live nodes BEFORE making any DB writes.
	// If more than one live device would be retired in a single pass, trip a
	// circuit breaker and retire NONE so a future Headscale serialization change
	// can never wipe out a pen.
	driftReasons := detectSyncDrift(nodes, byNode, members)
	if len(driftReasons) > 1 {
		logger.Error("sync: ALERT circuit breaker tripped; retiring none",
			"drifted", len(driftReasons), "live", len(live))
		s.st.Audit("registrar", "sync.drift_breaker", fmt.Sprintf("%d/%d", len(driftReasons), len(live)), "refusing mass device retirement")
		return false, fmt.Errorf("sync drift circuit breaker: %d of %d live devices drifted; refusing mass retirement", len(driftReasons), len(live))
	}

	hsByID := make(map[string]headscale.Node, len(nodes))
	for _, n := range nodes {
		hsByID[n.ID] = n
	}

	// Phase 2: drain durable pending self-deletes.
	pendingDelByNode, err := s.reconcilePendingDeletes(ctx, hsByID, byNode)
	if err != nil {
		return false, err
	}

	// Phase 3: reconcile live Headscale nodes (update existing, retire drifted, enroll new).
	seen := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		if n.HasTag("tag:infra") {
			continue
		}
		seen[n.ID] = true
		if pendingDelByNode[n.ID] {
			continue
		}
		v4, v6 := splitIPs(n.IPAddresses)
		name := n.GivenName
		if name == "" {
			name = n.Name
		}
		nNodeKey, nHasNK := canonicalNodeKey(n.NodeKey)
		nMachKey, nHasMK := canonicalMachineKey(n.MachineKey)

		if d, ok := byNode[n.ID]; ok {
			shouldEnroll, err := s.reconcileExistingNode(ctx, n, d, members[d.MemberID], v4, v6, name, nNodeKey, nHasNK, nMachKey, nHasMK, driftReasons, byNode)
			if err != nil {
				return false, err
			}
			if !shouldEnroll {
				continue
			}
		}
		if err := s.enrollNewNode(ctx, n, keys, members, v4, v6, name, nNodeKey, nMachKey); err != nil {
			return false, err
		}
	}

	// Phase 4: retire devices that disappeared from Headscale and retry removed-member user cleanup.
	if err := s.retireMissingDevices(live, seen); err != nil {
		return false, err
	}
	s.cleanupRemovedMembers(ctx, allMembers)

	// Phase 5: reconcile Headscale ACL policy.
	return s.applyPolicyTracked(ctx)
}

func (s *Service) reconcilePendingDeletes(ctx context.Context, hsByID map[string]headscale.Node, byNode map[string]*store.Device) (map[string]bool, error) {
	logger := s.loggerOrDefault()
	pendingDel, err := s.st.PendingDeviceDeletes()
	if err != nil {
		return nil, err
	}
	pendingDelByNode := make(map[string]bool, len(pendingDel))
	stillDeferred := make(map[int64]bool)
	for _, d := range pendingDel {
		n, exists := hsByID[d.HSNodeID]
		if !exists {
			if cerr := s.st.ClearDeviceHSDeletePending(d.ID); cerr != nil {
				logger.Warn("sync: clear hs_delete_pending for gone device failed", "device_id", d.ID, "err", cerr)
			}
			continue
		}
		action, reason := verifyPendingDeleteTarget(d, n, byNode[d.HSNodeID])
		switch action {
		case pendingDeleteSkipClear:
			logger.Warn("sync: ALERT skipping pending headscale delete",
				"device_id", d.ID, "hs_node_id", d.HSNodeID, "reason", reason)
			s.st.Audit("registrar", "device.delete_skip", fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID), reason)
			if cerr := s.st.ClearDeviceHSDeletePending(d.ID); cerr != nil {
				logger.Warn("sync: clear hs_delete_pending after skip failed", "device_id", d.ID, "err", cerr)
			}
		case pendingDeleteDefer:
			stillDeferred[d.ID] = true
			s.deferredDelMu.Lock()
			alreadyAlerted := s.deferredPendingDel[d.ID]
			s.deferredDelMu.Unlock()
			if !alreadyAlerted {
				logger.Warn("sync: ALERT deferring pending headscale delete",
					"device_id", d.ID, "hs_node_id", d.HSNodeID, "reason", reason)
			}
			// Only suppress stray enrollment when no live device already owns this node ID.
			if _, isLive := byNode[d.HSNodeID]; !isLive {
				pendingDelByNode[d.HSNodeID] = true
			}
		case pendingDeleteProceed:
			pendingDelByNode[d.HSNodeID] = true
			if derr := s.hs.DeleteNode(ctx, d.HSNodeID); derr != nil {
				logger.Warn("sync: retry headscale delete failed",
					"device_id", d.ID, "hs_node_id", d.HSNodeID, "err", derr)
			} else if cerr := s.st.ClearDeviceHSDeletePending(d.ID); cerr != nil {
				logger.Warn("sync: clear hs_delete_pending failed", "device_id", d.ID, "err", cerr)
			}
		}
	}
	s.deferredDelMu.Lock()
	s.deferredPendingDel = stillDeferred
	s.deferredDelMu.Unlock()
	return pendingDelByNode, nil
}

// reconcileExistingNode updates or retires a known live device row. It returns
// shouldEnroll=true when a drifted device was retired and the same Headscale
// node should immediately be evaluated for fresh enrollment.
func (s *Service) reconcileExistingNode(
	ctx context.Context,
	n headscale.Node,
	d *store.Device,
	m *store.Member,
	v4, v6, name, nNodeKey string,
	nHasNK bool,
	nMachKey string,
	nHasMK bool,
	driftReasons map[string]string,
	byNode map[string]*store.Device,
) (shouldEnroll bool, err error) {
	logger := s.loggerOrDefault()
	if m != nil && m.Status == "removed" {
		s.deleteStray(ctx, n, d, "member removed")
		return false, nil
	}
	if reason, drifted := driftReasons[n.ID]; drifted {
		logger.Warn("sync: ALERT retiring drifted device",
			"hs_node_id", n.ID, "name", d.Name, "device_id", d.ID, "reason", reason)
		if err := s.st.MarkDeviceRemovedAudited(d.ID, &store.AuditRecord{
			Actor:  "registrar",
			Action: "device.gone",
			Target: fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID),
			Detail: reason,
		}); err != nil {
			return false, err
		}
		delete(byNode, n.ID)
		return true, nil
	}
	dMachKey, dHasMK := canonicalMachineKey(d.MachineKey)
	if d.MachineKey != "" && !dHasMK {
		logger.Warn("sync: ALERT unparseable stored machine_key; refusing update",
			"hs_node_id", n.ID, "name", d.Name, "machine_key", d.MachineKey)
		return false, nil
	}
	if dHasMK && !nHasMK {
		logger.Warn("sync: ALERT missing or unparseable machine_key in headscale response; refusing update",
			"hs_node_id", n.ID, "name", d.Name)
		return false, nil
	}
	if d.MachineKey == "" && !nHasMK {
		if !s.missingMKAlerted[n.ID] {
			logger.Warn("sync: ALERT node has no machine_key in headscale or sqlite; direct portal auth will refuse it until headscale provides machineKey",
				"hs_node_id", n.ID, "name", d.Name)
			s.missingMKAlerted[n.ID] = true
		}
	}

	nodeKey := d.NodeKey
	rotatedViaSync := false
	if nHasNK {
		dNodeKey, dHasNK := canonicalNodeKey(d.NodeKey)
		if dHasNK && dNodeKey != nNodeKey {
			rotatedViaSync = true
		}
		nodeKey = nNodeKey
	}
	machineKey := dMachKey
	if machineKey == "" && nHasMK {
		machineKey = nMachKey
	}
	if d.IPv4 != v4 || d.IPv6 != v6 || d.Name != name || d.NodeKey != nodeKey || d.MachineKey != machineKey {
		if err := s.st.UpdateDevice(d.ID, name, v4, v6, nodeKey, machineKey); err != nil {
			return false, err
		}
		if rotatedViaSync {
			s.st.Audit("registrar", "device.key_rotate", fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID), "via sync")
		}
	}
	return false, nil
}

func (s *Service) enrollNewNode(
	ctx context.Context,
	n headscale.Node,
	keys map[string]*store.DeviceKey,
	members map[int64]*store.Member,
	v4, v6, name, nNodeKey, nMachKey string,
) error {
	var k *store.DeviceKey
	if n.PreAuthKey != nil {
		k = keys[n.PreAuthKey.ID]
	}
	if k == nil {
		if !s.orphans[n.ID] {
			s.loggerOrDefault().Warn("node was not enrolled through the registrar; it gets no access",
				"hs_node_id", n.ID, "name", name)
			s.orphans[n.ID] = true
		}
		return nil
	}
	m := members[k.MemberID]
	if m == nil || m.Status != "active" || k.RevokedAt != nil {
		s.deleteStray(ctx, n, nil, "key revoked or member not active")
		return nil
	}
	d := &store.Device{
		MemberID:   k.MemberID,
		Kind:       k.Kind,
		HSNodeID:   n.ID,
		NodeKey:    nNodeKey,
		MachineKey: nMachKey,
		Name:       name,
		IPv4:       v4,
		IPv6:       v6,
	}
	maxDevices := s.cfg.MaxDevices
	ownerFloor := 0
	if k.BypassCap {
		maxDevices = 0
	} else if m.Role == "owner" && k.Kind == "personal" {
		maxDevices = addDeviceReserve(s.cfg.MaxDevices)
		ownerFloor = OwnerDeviceReserve
	}
	err := s.st.EnrollDeviceCappedAudited(d, k.ID, maxDevices, ownerFloor, func(id int64) store.AuditRecord {
		return store.AuditRecord{
			Actor:  "registrar",
			Action: "device.join",
			Target: fmt.Sprintf("%s/%s#%d", m.Handle, name, id),
			Detail: k.Kind + " " + v4,
		}
	})
	if err != nil {
		if errors.Is(err, store.ErrDeviceAlreadyEnrolled) {
			// Another concurrent sync process already enrolled this live node.
			return nil
		}
		if errors.Is(err, store.ErrDeviceCapReached) {
			s.deleteStray(ctx, n, nil, "device limit reached")
			// Revoke (not MarkUsed) so HasJoined stays false and a transient
			// DeleteNode failure is automatically retried on subsequent syncs.
			_ = s.st.RevokeDeviceKey(k.ID)
			return nil
		}
		return err
	}
	return nil
}

func (s *Service) retireMissingDevices(live []*store.Device, seen map[string]bool) error {
	for _, d := range live {
		if !seen[d.HSNodeID] {
			if err := s.st.MarkDeviceRemovedAudited(d.ID, &store.AuditRecord{
				Actor:  "registrar",
				Action: "device.gone",
				Target: fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID),
				Detail: "no longer in headscale",
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) cleanupRemovedMembers(ctx context.Context, allMembers []*store.Member) {
	var removedWithHS []*store.Member
	for _, m := range allMembers {
		if m.Status == "removed" && m.HSUserID != "" {
			removedWithHS = append(removedWithHS, m)
		}
	}
	if len(removedWithHS) == 0 {
		return
	}
	curLive, err := s.st.LiveDevices()
	if err != nil {
		return
	}
	liveByMember := make(map[int64]bool, len(curLive))
	for _, d := range curLive {
		liveByMember[d.MemberID] = true
	}
	for _, m := range removedWithHS {
		if !liveByMember[m.ID] {
			if err := s.hs.DeleteUser(ctx, m.HSUserID); err == nil || headscale.IsNotFound(err) {
				_ = s.st.ClearMemberHSUserID(m.ID)
			}
		}
	}
}

func (s *Service) deleteStray(ctx context.Context, n headscale.Node, d *store.Device, why string) {
	if err := s.hs.DeleteNode(ctx, n.ID); err != nil {
		s.loggerOrDefault().Warn("delete stray headscale node failed", "hs_node_id", n.ID, "reason", why, "err", err)
		return
	}
	if d != nil {
		_ = s.st.MarkDeviceRemoved(d.ID)
	}
	s.st.Audit("registrar", "device.reject", n.ID+" "+n.GivenName, why)
}

func splitIPs(ips []string) (v4, v6 string) {
	for _, raw := range ips {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if a.Is4() && v4 == "" {
			v4 = a.String()
		} else if a.Is6() && v6 == "" {
			v6 = a.String()
		}
	}
	return
}
