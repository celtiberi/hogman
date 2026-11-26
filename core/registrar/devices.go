package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

func (s *Service) IssueDeviceKey(ctx context.Context, a Actor, handle, kind string) (string, int64, error) {
	if kind != "personal" && kind != "server" {
		return "", 0, bad("kind must be personal or server")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return "", 0, err
	}
	m, err := s.member(handle)
	if err != nil {
		return "", 0, err
	}
	if err := requireSelfOrManageable(a, m,
		"you can only add your own devices",
		"only the owner can add devices for an owner or admin",
	); err != nil {
		return "", 0, err
	}
	if !a.Is(m) && kind == "personal" {
		// No account recovery (D-16): a personal key joins a device as that
		// member, so nobody makes one for someone else. The one exception is
		// the server's own tool giving a member their very first device, which
		// is how a new pen's owner gets in. Anyone who has ever joined and
		// loses every device starts again with a new invite.
		if !a.CLI {
			return "", 0, forbidden("you can only add your own devices")
		}
		joined, err := s.st.HasJoined(m.ID)
		if err != nil {
			return "", 0, err
		}
		if joined {
			return "", 0, forbidden("%s has already joined a device, and there is no account recovery: invite them again as a new member", handle)
		}
	}
	if m.Status != "active" {
		return "", 0, conflict("%s is %s", handle, m.Status)
	}
	maxOpen := 0
	maxDevices := 0
	ownerFloor := 0
	bypassCap := a.CLI
	if !a.CLI {
		maxOpen = s.cfg.MaxOpenDeviceKeys
		if a.IsAdmin() {
			maxOpen = s.cfg.MaxAdminOpenDeviceKeys
			if maxOpen < s.cfg.MaxOpenDeviceKeys {
				maxOpen = s.cfg.MaxOpenDeviceKeys
			}
		}
		maxDevices = s.cfg.MaxDevices
		if m.Role == "owner" && kind == "personal" {
			maxDevices = addDeviceReserve(s.cfg.MaxDevices)
			ownerFloor = ownerDeviceReserve
		}
		// Fast pre-checks before creating a Headscale pre-auth key; atomic
		// enforcement runs inside InsertDeviceKeyCapped (BEGIN IMMEDIATE).
		open, err := s.st.CountOpenDeviceKeys(m.ID)
		if err != nil {
			return "", 0, err
		}
		if open >= maxOpen {
			return "", 0, conflict("too many unused device keys; wait for existing keys to be used or expire")
		}
		live, totalOpen, err := s.st.CountDeviceSlots()
		if err != nil {
			return "", 0, err
		}
		if live+totalOpen >= maxDevices {
			allowedByFloor := false
			if ownerFloor > 0 {
				if ownerSlots, oerr := s.st.CountMemberPersonalSlots(m.ID); oerr == nil && ownerSlots < ownerFloor {
					allowedByFloor = true
				}
			}
			if !allowedByFloor {
				return "", 0, conflict("this network has reached its device limit (%d)", s.cfg.MaxDevices)
			}
		}
	}
	key, exp, err := s.issueKeyCapped(ctx, m, kind, maxDevices, maxOpen, ownerFloor, bypassCap, &AuditRecord{
		Actor:  a.String(),
		Action: "device.key",
		Target: handle,
		Detail: kind,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrOpenKeyCapReached):
			return "", 0, conflict("too many unused device keys; wait for existing keys to be used or expire")
		case errors.Is(err, ErrDeviceCapReached):
			return "", 0, conflict("this network has reached its device limit (%d)", s.cfg.MaxDevices)
		default:
			return "", 0, err
		}
	}
	return key, exp, nil
}

func (s *Service) issueKeyCapped(ctx context.Context, m *Member, kind string, maxDevices, maxOpenForMember, ownerPersonalFloor int, bypassCap bool, audit *AuditRecord) (string, int64, error) {
	var k *HSPreAuthKey
	var err error
	if kind == "server" {
		k, err = s.hs.CreateKey(ctx, "", []string{"tag:server"}, s.cfg.DeviceKeyTTL)
	} else {
		k, err = s.hs.CreateKey(ctx, m.HSUserID, nil, s.cfg.DeviceKeyTTL)
	}
	if err != nil {
		return "", 0, err
	}
	dk := &DeviceKey{
		MemberID:  m.ID,
		Kind:      kind,
		HSKeyID:   k.ID,
		ExpiresAt: s.clock().Add(s.cfg.DeviceKeyTTL).Unix(),
		BypassCap: bypassCap,
	}
	if err := s.st.InsertDeviceKeyCappedAudited(dk, maxDevices, maxOpenForMember, ownerPersonalFloor, audit); err != nil {
		rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = s.hs.ExpireKey(rbCtx, k.ID)
		rbCancel()
		return "", 0, err
	}
	return k.Key, dk.ExpiresAt, nil
}

const (
	removeDeviceTimeout        = 30 * time.Second
	removeDeviceCleanupTimeout = 15 * time.Second
)

func (s *Service) RemoveDevice(ctx context.Context, a Actor, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Bail immediately if the caller already disconnected or timed out while
	// waiting on s.mu (prevents cancelled non-self delete bursts from piling up
	// Headscale calls under s.mu).
	if err := ctx.Err(); err != nil {
		return err
	}
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
	d, err := s.st.DeviceByID(id)
	if errors.Is(err, ErrNotFound) || (err == nil && d.RemovedAt != nil) {
		return missing("no device %d", id)
	} else if err != nil {
		return err
	}
	owner, err := s.st.MemberByID(d.MemberID)
	if err != nil {
		return err
	}
	if err := requireSelfOrManageable(a, owner,
		"not your device",
		"only the owner can remove devices of an owner or admin",
	); err != nil {
		return err
	}
	// Derive the Headscale DeleteNode timeout AFTER acquiring s.mu so waiting
	// behind a long Sync() does not starve Headscale, while still honoring caller
	// ctx cancellation for synchronous non-self deletes.
	opCtx, cancel := context.WithTimeout(ctx, removeDeviceTimeout)
	defer cancel()
	if err := s.hs.DeleteNode(opCtx, d.HSNodeID); err != nil {
		return err
	}
	// Once Headscale deleted the node, finish SQLite cleanup and policy push on
	// a detached lifecycle context so a late caller disconnect cannot split-brain
	// SQLite/Headscale state or leak leaf DNS names.
	cleanupCtx, cleanupCancel := context.WithTimeout(s.baseContext(), removeDeviceCleanupTimeout)
	defer cleanupCancel()
	// Removing a device on purpose atomically releases the leaf names it served
	// (preserving parent names that still have subdomains elsewhere), marks the
	// device removed, and records the audit entry. A kick retires names instead.
	if err := s.st.CommitDeviceRemoval(d.ID, AuditRecord{
		Actor:  a.String(),
		Action: "device.remove",
		Target: fmt.Sprintf("%s/%s#%d", owner.Handle, d.Name, d.ID),
	}); err != nil {
		return err
	}
	return s.applyPolicy(cleanupCtx)
}

// SelfRemoveDevice commits an authenticated device's own removal durably in
// SQLite BEFORE the HTTP handler answers 202 Accepted (no Headscale call and
// no s.mu wait), then kicks off best-effort background Headscale DeleteNode +
// SetPolicy cleanup. Because removed_at, leaf-name release, policy_gen bump,
// and hs_delete_pending = 1 are committed first, portal auth and /api/me deny
// immediately and syncOnce() durably converges both Headscale node deletion
// and ACL policy across mutex contention, Headscale outages, or restarts (I-34).
func (s *Service) SelfRemoveDevice(a Actor, id int64) error {
	if a.CLI || a.Member == nil {
		return forbidden("not a member device")
	}
	d, err := s.st.CommitSelfDelete(a.Member.ID, id, a.String())
	if err != nil {
		return err
	}
	// Best-effort fast path: delete from Headscale and push policy promptly.
	// If shutting down (startBackground returns false) or Headscale is briefly
	// unavailable, durable hs_delete_pending + dirty policy_gen guarantee
	// syncOnce() finishes cleanup automatically.
	s.startBackground(func() {
		s.finishSelfDelete(d.ID, d.HSNodeID)
	})
	return nil
}

type pendingDeleteAction int

const (
	pendingDeleteProceed pendingDeleteAction = iota
	pendingDeleteSkipClear
	pendingDeleteDefer
)

// verifyPendingDeleteTarget checks whether a Headscale node still matches a
// removed device row before deleting it, preventing node-ID reuse from ever
// deleting a different machine, a live re-enrolled device, or tag:infra.
func verifyPendingDeleteTarget(d *Device, n HSNode, liveDev *Device) (pendingDeleteAction, string) {
	if n.HasTag("tag:infra") {
		return pendingDeleteSkipClear, "headscale node is tag:infra"
	}
	if liveDev != nil && liveDev.ID != d.ID {
		return pendingDeleteSkipClear, fmt.Sprintf("hs_node_id belongs to live device #%d", liveDev.ID)
	}
	dMachKey, dHasMK := canonicalMachineKey(d.MachineKey)
	if d.MachineKey != "" && !dHasMK {
		return pendingDeleteDefer, "unparseable stored machine_key"
	}
	nMachKey, nHasMK := canonicalMachineKey(n.MachineKey)
	if dHasMK && nHasMK && dMachKey != nMachKey {
		return pendingDeleteSkipClear, "headscale node machine_key mismatch"
	}
	if dHasMK && !nHasMK {
		return pendingDeleteDefer, "headscale missing machine_key"
	}
	return pendingDeleteProceed, ""
}

func (s *Service) finishSelfDelete(id int64, hsNodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	opCtx, cancel := context.WithTimeout(s.baseContext(), removeDeviceTimeout)
	defer cancel()
	if opCtx.Err() != nil {
		return
	}
	logger := s.loggerOrDefault()
	// Re-check durable hs_delete_pending after acquiring s.mu: syncOnce may
	// already have deleted the node or cleared pending after a machineKey mismatch.
	pending, err := s.st.DeviceHSDeletePending(id)
	if err != nil {
		logger.Warn("self-delete check hs_delete_pending failed", "device_id", id, "err", err)
	} else if !pending {
		if err := s.applyPolicy(opCtx); err != nil {
			logger.Warn("self-delete policy push failed (will retry in sync)", "device_id", id, "err", err)
		}
		return
	}
	d, derr := s.st.DeviceByID(id)
	if derr != nil {
		logger.Warn("self-delete reload device failed", "device_id", id, "err", derr)
		return
	}
	var liveDev *Device
	if ld, lerr := s.st.DeviceByHSNodeID(hsNodeID); lerr == nil {
		liveDev = ld
	}
	if liveDev != nil && liveDev.ID != d.ID {
		logger.Warn("self-delete ALERT skipping delete: hs_node_id belongs to live device",
			"device_id", d.ID, "hs_node_id", hsNodeID, "live_device_id", liveDev.ID)
		s.st.Audit("registrar", "device.delete_skip", fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID), fmt.Sprintf("hs_node_id belongs to live device #%d", liveDev.ID))
		_ = s.st.ClearDeviceHSDeletePending(d.ID)
	} else if n, nerr := s.hs.Node(opCtx, hsNodeID); isHSNotFound(nerr) {
		if err := s.st.ClearDeviceHSDeletePending(id); err != nil {
			logger.Warn("self-delete clear hs_delete_pending failed", "device_id", id, "err", err)
		}
	} else if nerr != nil {
		logger.Warn("self-delete verify node failed (will retry in sync)", "device_id", id, "hs_node_id", hsNodeID, "err", nerr)
	} else {
		action, reason := verifyPendingDeleteTarget(d, *n, liveDev)
		switch action {
		case pendingDeleteSkipClear:
			logger.Warn("self-delete ALERT skipping delete", "device_id", d.ID, "hs_node_id", hsNodeID, "reason", reason)
			s.st.Audit("registrar", "device.delete_skip", fmt.Sprintf("%s/%s#%d", d.Member, d.Name, d.ID), reason)
			_ = s.st.ClearDeviceHSDeletePending(d.ID)
		case pendingDeleteDefer:
			logger.Warn("self-delete ALERT deferring delete (will retry in sync)", "device_id", d.ID, "hs_node_id", hsNodeID, "reason", reason)
		case pendingDeleteProceed:
			if err := s.hs.DeleteNode(opCtx, hsNodeID); err != nil {
				logger.Warn("self-delete headscale delete failed (will retry in sync)", "device_id", id, "hs_node_id", hsNodeID, "err", err)
			} else if err := s.st.ClearDeviceHSDeletePending(id); err != nil {
				logger.Warn("self-delete clear hs_delete_pending failed", "device_id", id, "err", err)
			}
		}
	}
	if err := s.applyPolicy(opCtx); err != nil {
		logger.Warn("self-delete policy push failed (will retry in sync)", "device_id", id, "err", err)
	}
}

// WhoIs maps a mesh source address to the device and member behind it.
func (s *Service) WhoIs(ip string) (*Member, *Device, error) {
	d, err := s.st.DeviceByIP(ip)
	if err != nil {
		return nil, nil, err
	}
	m, err := s.st.MemberByID(d.MemberID)
	return m, d, err
}
