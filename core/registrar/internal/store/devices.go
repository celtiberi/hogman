package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ------------------------------------------------------------ device keys --

type DeviceKey struct {
	ID        int64
	MemberID  int64
	Kind      string
	HSKeyID   string
	ExpiresAt int64
	UsedAt    *int64
	RevokedAt *int64
	BypassCap bool
}

func (s *Store) InsertDeviceKey(k *DeviceKey) error {
	return s.InsertDeviceKeyCapped(k, 0, 0, 0)
}

// CountDeviceSlots returns the current count of live devices and open
// (unused, unrevoked, unexpired) device keys across the pen.
func (s *Store) CountDeviceSlots() (live int, openKeys int, err error) {
	err = s.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM devices WHERE removed_at IS NULL),
		(SELECT COUNT(*) FROM device_keys WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?)`,
		s.unixNow()).Scan(&live, &openKeys)
	return live, openKeys, err
}

// CountMemberPersonalSlots returns a member's live personal devices plus open
// personal device keys (used for D-16 per-owner personal lockout headroom).
func (s *Store) CountMemberPersonalSlots(memberID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM devices WHERE removed_at IS NULL AND member_id = ? AND kind = 'personal') +
		(SELECT COUNT(*) FROM device_keys WHERE member_id = ? AND kind = 'personal' AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?)`,
		memberID, memberID, s.unixNow()).Scan(&n)
	return n, err
}

// InsertDeviceKeyCapped inserts a device key inside BEGIN IMMEDIATE, atomically
// enforcing per-member open-key limits (maxOpenForMember > 0) and pen-wide
// live_devices + open_device_keys limits (maxDevices > 0). When ownerPersonalFloor
// > 0, an active owner's personal key is also allowed whenever that owner holds
// fewer than ownerPersonalFloor live+open personal slots (D-16 lockout protection
// on grandfathered over-cap pens).
func (s *Store) InsertDeviceKeyCapped(k *DeviceKey, maxDevices, maxOpenForMember, ownerPersonalFloor int) error {
	return s.InsertDeviceKeyCappedAudited(k, maxDevices, maxOpenForMember, ownerPersonalFloor, nil)
}

func (s *Store) InsertDeviceKeyCappedAudited(k *DeviceKey, maxDevices, maxOpenForMember, ownerPersonalFloor int, audit *AuditRecord) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		ts := s.unixNow()
		if maxOpenForMember > 0 {
			var open int
			if err := c.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_keys
				WHERE member_id = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`,
				k.MemberID, ts).Scan(&open); err != nil {
				return err
			}
			if open >= maxOpenForMember {
				return ErrOpenKeyCapReached
			}
		}
		if maxDevices > 0 {
			var usedSlots int
			if err := c.QueryRowContext(ctx, `SELECT
				(SELECT COUNT(*) FROM devices WHERE removed_at IS NULL) +
				(SELECT COUNT(*) FROM device_keys WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?)`,
				ts).Scan(&usedSlots); err != nil {
				return err
			}
			if usedSlots >= maxDevices {
				allowedByFloor := false
				if ownerPersonalFloor > 0 && k.Kind == "personal" {
					var ownerSlots int
					if err := c.QueryRowContext(ctx, `SELECT
						(SELECT COUNT(*) FROM devices WHERE removed_at IS NULL AND member_id = ? AND kind = 'personal') +
						(SELECT COUNT(*) FROM device_keys WHERE member_id = ? AND kind = 'personal' AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?)`,
						k.MemberID, k.MemberID, ts).Scan(&ownerSlots); err != nil {
						return err
					}
					allowedByFloor = ownerSlots < ownerPersonalFloor
				}
				if !allowedByFloor {
					return ErrDeviceCapReached
				}
			}
		}
		bypass := 0
		if k.BypassCap {
			bypass = 1
		}
		res, err := c.ExecContext(ctx, `INSERT INTO device_keys (member_id, kind, hs_key_id, created_at, expires_at, bypass_cap) VALUES (?,?,?,?,?,?)`,
			k.MemberID, k.Kind, k.HSKeyID, ts, k.ExpiresAt, bypass)
		if err != nil {
			return err
		}
		k.ID, _ = res.LastInsertId()
		if audit != nil {
			if err := insertAuditTx(ctx, c, ts, *audit); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) PendingDeviceKeys(cutoff int64) (map[string]*DeviceKey, error) {
	rows, err := s.db.Query(`SELECT id, member_id, kind, hs_key_id, expires_at, used_at, revoked_at, bypass_cap FROM device_keys
		WHERE used_at IS NULL AND expires_at > ?`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*DeviceKey{}
	for rows.Next() {
		var k DeviceKey
		var bypass int
		if err := rows.Scan(&k.ID, &k.MemberID, &k.Kind, &k.HSKeyID, &k.ExpiresAt, &k.UsedAt, &k.RevokedAt, &bypass); err != nil {
			return nil, err
		}
		k.BypassCap = bypass != 0
		out[k.HSKeyID] = &k
	}
	return out, rows.Err()
}

func (s *Store) CountOpenDeviceKeys(memberID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM device_keys
		WHERE member_id = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, memberID, s.unixNow()).Scan(&n)
	return n, err
}

// HasOpenDeviceKeys reports whether any member has an unused, unrevoked,
// unexpired device key awaiting enrolment.
func (s *Store) HasOpenDeviceKeys() (bool, error) {
	var exists int
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM device_keys
		WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?)`, s.unixNow()).Scan(&exists)
	return exists != 0, err
}

// HasJoined reports whether a member has ever had a personal device on the
// pen: a used personal key (kept after the device is removed) or a device.
func (s *Store) HasJoined(memberID int64) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT
		(SELECT count(*) FROM device_keys WHERE member_id = ? AND kind = 'personal' AND used_at IS NOT NULL) +
		(SELECT count(*) FROM devices WHERE member_id = ? AND kind = 'personal')`, memberID, memberID).Scan(&n)
	return n > 0, err
}

func (s *Store) MarkDeviceKeyUsed(id int64) error {
	_, err := s.db.Exec(`UPDATE device_keys SET used_at = ? WHERE id = ? AND used_at IS NULL`, s.unixNow(), id)
	return err
}

// OpenDeviceKeys returns keys of a member that are unused, unrevoked and unexpired.
func (s *Store) OpenDeviceKeys(memberID int64) ([]*DeviceKey, error) {
	rows, err := s.db.Query(`SELECT id, member_id, kind, hs_key_id, expires_at FROM device_keys
		WHERE member_id = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, memberID, s.unixNow())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DeviceKey
	for rows.Next() {
		var k DeviceKey
		if err := rows.Scan(&k.ID, &k.MemberID, &k.Kind, &k.HSKeyID, &k.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, &k)
	}
	return out, rows.Err()
}

func (s *Store) RevokeDeviceKey(id int64) error {
	_, err := s.db.Exec(`UPDATE device_keys SET revoked_at = ? WHERE id = ?`, s.unixNow(), id)
	return err
}

// ---------------------------------------------------------------- devices --

type Device struct {
	ID         int64  `json:"id"`
	MemberID   int64  `json:"member_id"`
	Member     string `json:"member"`
	Kind       string `json:"kind"`
	HSNodeID   string `json:"-"`
	NodeKey    string `json:"-"`
	MachineKey string `json:"-"`
	Name       string `json:"name"`
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6,omitempty"`
	CreatedAt  int64  `json:"created_at"`
	RemovedAt  *int64 `json:"removed_at,omitempty"`
}

const deviceCols = `d.id, d.member_id, m.handle, d.kind, d.hs_node_id, d.node_key, d.machine_key, d.name, d.ipv4, d.ipv6, d.created_at, d.removed_at`
const deviceFrom = ` FROM devices d JOIN members m ON m.id = d.member_id `

func scanDevice(r interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	err := r.Scan(&d.ID, &d.MemberID, &d.Member, &d.Kind, &d.HSNodeID, &d.NodeKey, &d.MachineKey, &d.Name, &d.IPv4, &d.IPv6, &d.CreatedAt, &d.RemovedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &d, err
}

func (s *Store) queryDevices(where string, args ...any) ([]*Device, error) {
	rows, err := s.db.Query(`SELECT `+deviceCols+deviceFrom+where+` ORDER BY d.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// LiveDevices are devices still registered with Headscale, whatever their member's status.
func (s *Store) LiveDevices() ([]*Device, error) {
	return s.queryDevices(`WHERE d.removed_at IS NULL`)
}

func (s *Store) MemberDevices(memberID int64) ([]*Device, error) {
	return s.queryDevices(`WHERE d.removed_at IS NULL AND d.member_id = ?`, memberID)
}

func (s *Store) DeviceByID(id int64) (*Device, error) {
	return scanDevice(s.db.QueryRow(`SELECT `+deviceCols+deviceFrom+`WHERE d.id = ?`, id))
}

func (s *Store) DeviceByIP(ip string) (*Device, error) {
	if ip == "" {
		return nil, ErrNotFound
	}
	return scanDevice(s.db.QueryRow(`SELECT `+deviceCols+deviceFrom+
		`WHERE d.removed_at IS NULL AND ((d.ipv4 != '' AND d.ipv4 = ?) OR (d.ipv6 != '' AND d.ipv6 = ?))`, ip, ip))
}

func (s *Store) DeviceByHSNodeID(nodeID string) (*Device, error) {
	if nodeID == "" {
		return nil, ErrNotFound
	}
	return scanDevice(s.db.QueryRow(`SELECT `+deviceCols+deviceFrom+
		`WHERE d.removed_at IS NULL AND d.hs_node_id = ?`, nodeID))
}

func (s *Store) InsertDevice(d *Device) error {
	return s.EnrollDeviceCapped(d, 0, 0, 0)
}

// EnrollDeviceCapped atomically enrolls a newly synced live device and marks
// its device key used (when keyID > 0) inside BEGIN IMMEDIATE. It checks
// whether hs_node_id is already live FIRST (returning ErrDeviceAlreadyEnrolled
// so overlapping serve + CLI syncs never mistake an already-enrolled device
// for an over-cap stray), then enforces maxDevices (when > 0) with optional
// per-owner personal-device floor (D-16).
func (s *Store) EnrollDeviceCapped(d *Device, keyID int64, maxDevices, ownerPersonalFloor int) error {
	return s.EnrollDeviceCappedAudited(d, keyID, maxDevices, ownerPersonalFloor, nil)
}

func (s *Store) EnrollDeviceCappedAudited(d *Device, keyID int64, maxDevices, ownerPersonalFloor int, auditFn func(id int64) AuditRecord) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		if d.HSNodeID != "" {
			var exists int
			if err := c.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE removed_at IS NULL AND hs_node_id = ?)`, d.HSNodeID).Scan(&exists); err != nil {
				return err
			}
			if exists != 0 {
				return ErrDeviceAlreadyEnrolled
			}
		}
		if maxDevices > 0 {
			var live int
			if err := c.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE removed_at IS NULL`).Scan(&live); err != nil {
				return err
			}
			if live >= maxDevices {
				allowedByFloor := false
				if ownerPersonalFloor > 0 && d.Kind == "personal" {
					var ownerLive int
					if err := c.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE removed_at IS NULL AND member_id = ? AND kind = 'personal'`, d.MemberID).Scan(&ownerLive); err != nil {
						return err
					}
					allowedByFloor = ownerLive < ownerPersonalFloor
				}
				if !allowedByFloor {
					return ErrDeviceCapReached
				}
			}
		}
		ts := s.unixNow()
		res, err := c.ExecContext(ctx, `INSERT INTO devices (member_id, kind, hs_node_id, node_key, machine_key, name, ipv4, ipv6, created_at) VALUES (?,?,?,?,?,?,?,?,?)`,
			d.MemberID, d.Kind, d.HSNodeID, d.NodeKey, d.MachineKey, d.Name, d.IPv4, d.IPv6, ts)
		if err != nil {
			return err
		}
		d.ID, _ = res.LastInsertId()
		if keyID > 0 {
			if _, err := c.ExecContext(ctx, `UPDATE device_keys SET used_at = ? WHERE id = ? AND used_at IS NULL`, ts, keyID); err != nil {
				return err
			}
		}
		if auditFn != nil {
			if err := insertAuditTx(ctx, c, ts, auditFn(d.ID)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) UpdateDevice(id int64, name, v4, v6, nodeKey, machineKey string) error {
	_, err := s.db.Exec(`UPDATE devices SET name = ?, ipv4 = ?, ipv6 = ?, node_key = ?, machine_key = ? WHERE id = ?`,
		name, v4, v6, nodeKey, machineKey, id)
	return err
}

// RotateDeviceNodeKey conditionally updates a live device's WireGuard node key
// only if its previous node_key and pinned machine_key still match, the row
// has not been removed concurrently, and the owning member is still active.
func (s *Store) RotateDeviceNodeKey(id int64, oldNodeKey, machineKey, newNodeKey string) (bool, error) {
	return s.RotateDeviceNodeKeyAudited(id, oldNodeKey, machineKey, newNodeKey, nil)
}

func (s *Store) RotateDeviceNodeKeyAudited(id int64, oldNodeKey, machineKey, newNodeKey string, audit *AuditRecord) (bool, error) {
	var rotated bool
	err := withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		res, err := c.ExecContext(ctx, `UPDATE devices SET node_key = ?
			WHERE id = ? AND node_key = ? AND machine_key = ? AND removed_at IS NULL
			  AND EXISTS (SELECT 1 FROM members WHERE id = devices.member_id AND status = 'active')`,
			newNodeKey, id, oldNodeKey, machineKey)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return nil
		}
		rotated = true
		if audit != nil {
			if err := insertAuditTx(ctx, c, s.unixNow(), *audit); err != nil {
				return err
			}
		}
		return nil
	})
	return rotated, err
}

// releaseLeafNamesOfDevice frees active leaf names pointing at a device while
// unpointing (instead of deleting) any parent name that still has child
// subdomains elsewhere, and permanently retiring private random labels (D-21).
// Shared by DeleteNamesOfDevice, CommitDeviceRemoval, and CommitSelfDelete.
func releaseLeafNamesOfDevice(ctx context.Context, ex sqlExecContexter, deviceID, ts int64) error {
	if _, err := ex.ExecContext(ctx, `UPDATE names SET device_id = NULL
		WHERE device_id = ? AND held_until IS NULL
		AND EXISTS (
			SELECT 1 FROM names c
			WHERE length(c.name) > length(names.name) + 1
			AND substr(c.name, length(c.name) - length(names.name)) = '.' || names.name
			AND (c.held_until IS NOT NULL OR c.device_id IS NULL OR c.device_id != ?)
		)`, deviceID, deviceID); err != nil {
		return err
	}
	// Private random site names are permanently retired on release (D-21), never deleted for reuse.
	if _, err := ex.ExecContext(ctx, `UPDATE names SET device_id = NULL, held_until = ?, note = ''
		WHERE device_id = ? AND held_until IS NULL AND private != 0`, ts, deviceID); err != nil {
		return err
	}
	_, err := ex.ExecContext(ctx, `DELETE FROM names WHERE device_id = ? AND held_until IS NULL AND private = 0`, deviceID)
	return err
}

// DeleteNamesOfDevice frees active leaf names pointing at a device. If a name
// on the removed device still has child subdomains (active on other devices,
// unpointed, or retired), it is unpointed (device_id = NULL) rather than
// deleted so another member cannot hijack the orphaned parent and release or
// take over the child subdomains.
func (s *Store) DeleteNamesOfDevice(deviceID int64) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		return releaseLeafNamesOfDevice(context.Background(), c, deviceID, s.unixNow())
	})
}

// MarkDeviceRemoved retires a device and unpoints any names aimed at it.
func (s *Store) MarkDeviceRemoved(id int64) error {
	return s.MarkDeviceRemovedAudited(id, nil)
}

func (s *Store) MarkDeviceRemovedAudited(id int64, audit *AuditRecord) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		ts := s.unixNow()
		if _, err := c.ExecContext(ctx, `UPDATE devices SET removed_at = ? WHERE id = ? AND removed_at IS NULL`, ts, id); err != nil {
			return err
		}
		if _, err := c.ExecContext(ctx, `UPDATE names SET device_id = NULL WHERE device_id = ?`, id); err != nil {
			return err
		}
		if audit != nil {
			if err := insertAuditTx(ctx, c, ts, *audit); err != nil {
				return err
			}
		}
		return nil
	})
}

// CommitDeviceRemoval atomically releases leaf names owned by deviceID, marks
// the device removed, unpoints any remaining names, and records the audit line
// in a single BEGIN IMMEDIATE transaction.
func (s *Store) CommitDeviceRemoval(deviceID int64, audit AuditRecord) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		ts := s.unixNow()
		if err := releaseLeafNamesOfDevice(ctx, c, deviceID, ts); err != nil {
			return err
		}
		if _, err := c.ExecContext(ctx, `UPDATE devices SET removed_at = ? WHERE id = ? AND removed_at IS NULL`, ts, deviceID); err != nil {
			return err
		}
		if _, err := c.ExecContext(ctx, `UPDATE names SET device_id = NULL WHERE device_id = ?`, deviceID); err != nil {
			return err
		}
		return insertAuditTx(ctx, c, ts, audit)
	})
}

// CommitSelfDelete atomically commits a device's own removal in SQLite (before
// answering 202 Accepted) so portal auth, /api/me, leaf-name release, audit,
// policy_gen bump, and Headscale delete intent (hs_delete_pending = 1) are all
// durable immediately — surviving Headscale outages, mutex contention, and
// process restarts (I-34).
func (s *Store) CommitSelfDelete(memberID, deviceID int64, actor string) (*Device, error) {
	var out *Device
	err := withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		var status, handle string
		if err := c.QueryRowContext(ctx, `SELECT status, handle FROM members WHERE id = ?`, memberID).Scan(&status, &handle); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrMemberRemoved
			}
			return err
		}
		if status != "active" {
			return &MemberStatusError{Status: status}
		}
		d, err := scanDevice(c.QueryRowContext(ctx, `SELECT `+deviceCols+deviceFrom+`WHERE d.id = ?`, deviceID))
		if errors.Is(err, ErrNotFound) || (err == nil && d.RemovedAt != nil) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if d.MemberID != memberID {
			return ErrNotYourDevice
		}
		// Release leaf names served by this device (preserving parent names that
		// still have child subdomains elsewhere), shared with DeleteNamesOfDevice.
		ts := s.unixNow()
		if err := releaseLeafNamesOfDevice(ctx, c, d.ID, ts); err != nil {
			return err
		}
		res, err := c.ExecContext(ctx, `UPDATE devices SET removed_at = ?, hs_delete_pending = 1 WHERE id = ? AND removed_at IS NULL`, ts, d.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		if _, err := c.ExecContext(ctx, `UPDATE names SET device_id = NULL WHERE device_id = ?`, d.ID); err != nil {
			return err
		}
		if err := insertAuditTx(ctx, c, ts, AuditRecord{
			Actor:  actor,
			Action: "device.remove",
			Target: fmt.Sprintf("%s/%s#%d", handle, d.Name, d.ID),
		}); err != nil {
			return err
		}
		d.RemovedAt = &ts
		out = d
		return nil
	})
	return out, err
}

// PendingDeviceDeletes returns removed devices whose Headscale node still needs
// to be deleted asynchronously by finishSelfDelete or syncOnce.
func (s *Store) PendingDeviceDeletes() ([]*Device, error) {
	return s.queryDevices(`WHERE d.hs_delete_pending != 0`)
}

// PendingDeviceDeleteIDs returns the IDs of removed devices whose Headscale
// node deletion is still pending.
func (s *Store) PendingDeviceDeleteIDs() ([]int64, error) {
	rows, err := s.db.Query(`SELECT id FROM devices WHERE hs_delete_pending != 0 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// DeviceHSDeletePending reports whether the given device row still has
// hs_delete_pending set.
func (s *Store) DeviceHSDeletePending(id int64) (bool, error) {
	var pending int
	err := s.db.QueryRow(`SELECT hs_delete_pending FROM devices WHERE id = ?`, id).Scan(&pending)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return pending != 0, err
}

// HasPendingDeviceDeletes reports whether any removed device still has a
// pending Headscale node deletion.
func (s *Store) HasPendingDeviceDeletes() (bool, error) {
	var exists int
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM devices WHERE hs_delete_pending != 0)`).Scan(&exists)
	return exists == 1, err
}

// ClearDeviceHSDeletePending clears hs_delete_pending once Headscale confirmed
// the node is gone. Does not touch columns watched by devices_policy_gen_au.
func (s *Store) ClearDeviceHSDeletePending(id int64) error {
	_, err := s.db.Exec(`UPDATE devices SET hs_delete_pending = 0 WHERE id = ?`, id)
	return err
}
