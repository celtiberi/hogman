package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type Member struct {
	ID        int64  `json:"id"`
	Handle    string `json:"handle"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	InvitedBy *int64 `json:"invited_by,omitempty"`
	HSUserID  string `json:"-"`
	CreatedAt int64  `json:"created_at"`
	RemovedAt *int64 `json:"removed_at,omitempty"`
}

const memberCols = `id, handle, role, status, invited_by, hs_user_id, created_at, removed_at`

func scanMember(r interface{ Scan(...any) error }) (*Member, error) {
	var m Member
	err := r.Scan(&m.ID, &m.Handle, &m.Role, &m.Status, &m.InvitedBy, &m.HSUserID, &m.CreatedAt, &m.RemovedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &m, err
}

func (s *Store) MemberByHandle(h string) (*Member, error) {
	return scanMember(s.db.QueryRow(`SELECT `+memberCols+` FROM members WHERE handle = ?`, h))
}

func (s *Store) MemberByID(id int64) (*Member, error) {
	return scanMember(s.db.QueryRow(`SELECT `+memberCols+` FROM members WHERE id = ?`, id))
}

func (s *Store) Members() ([]*Member, error) {
	rows, err := s.db.Query(`SELECT ` + memberCols + ` FROM members ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Member
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// HerdMember is a member as the keeper's page lists them: with how many
// devices they have on the network.
type HerdMember struct {
	*Member
	Devices int `json:"devices"`
}

// scanPlus scans a row whose last columns come after the ones scanMember reads.
type scanPlus struct {
	r     interface{ Scan(...any) error }
	extra []any
}

func (p scanPlus) Scan(dest ...any) error { return p.r.Scan(append(dest, p.extra...)...) }

// Herd lists members who haven't been removed, a page at a time: owners and
// admins first, then by handle. q, if set, matches anywhere in the handle and
// may only hold handle characters. Returns the page and how many match in all.
func (s *Store) Herd(q string, limit, offset int) ([]*HerdMember, int, error) {
	where, args := `WHERE status != 'removed'`, []any{}
	if q != "" {
		where += ` AND handle LIKE ?`
		args = append(args, "%"+q+"%")
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM members `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT `+memberCols+`,
		(SELECT COUNT(*) FROM devices d WHERE d.member_id = members.id AND d.removed_at IS NULL)
		FROM members `+where+`
		ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, handle
		LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*HerdMember{}
	for rows.Next() {
		var n int
		m, err := scanMember(scanPlus{rows, []any{&n}})
		if err != nil {
			return nil, 0, err
		}
		out = append(out, &HerdMember{m, n})
	}
	return out, total, rows.Err()
}

func (s *Store) CountActiveMembers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM members WHERE status != 'removed'`).Scan(&n)
	return n, err
}

func (s *Store) InsertMember(m *Member) error {
	return s.InsertMemberCapped(m, 0)
}

// InsertMemberCapped inserts a member, atomically checking handle uniqueness
// first and then enforcing maxMembers (when > 0) against non-removed members
// (active + suspended) inside a BEGIN IMMEDIATE transaction.
func (s *Store) InsertMemberCapped(m *Member, maxMembers int) error {
	return s.InsertMemberCappedAudited(m, maxMembers, nil)
}

// InsertMemberCappedAudited inserts a member (with optional cap enforcement)
// and, if audit is non-nil, writes its audit entry in the same transaction.
func (s *Store) InsertMemberCappedAudited(m *Member, maxMembers int, audit *AuditRecord) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		var exists int
		if err := c.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM members WHERE handle = ?)`, m.Handle).Scan(&exists); err != nil {
			return err
		}
		if exists != 0 {
			return conflict("handle %q is taken", m.Handle)
		}
		if maxMembers > 0 {
			var count int
			if err := c.QueryRowContext(ctx, `SELECT COUNT(*) FROM members WHERE status != 'removed'`).Scan(&count); err != nil {
				return err
			}
			if count >= maxMembers {
				return ErrMemberCapReached
			}
		}
		ts := s.unixNow()
		res, err := c.ExecContext(ctx, `INSERT INTO members (handle, role, status, invited_by, hs_user_id, created_at) VALUES (?,?,?,?,?,?)`,
			m.Handle, m.Role, m.Status, m.InvitedBy, m.HSUserID, ts)
		if err != nil {
			return err
		}
		m.ID, _ = res.LastInsertId()
		if audit != nil {
			if err := insertAuditTx(ctx, c, ts, *audit); err != nil {
				return err
			}
		}
		return nil
	})
}

// RollbackRedeem atomically unclaims an invite and deletes the newly created
// member row in a single BEGIN IMMEDIATE transaction after a failed redeem.
func (s *Store) RollbackRedeem(inviteID, memberID int64) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		if _, err := c.ExecContext(ctx, `UPDATE invites SET redeemed_by = NULL, redeemed_at = NULL WHERE id = ? AND redeemed_by = ?`, inviteID, memberID); err != nil {
			return err
		}
		_, err := c.ExecContext(ctx, `DELETE FROM members WHERE id = ?`, memberID)
		return err
	})
}

func (s *Store) ClearMemberHSUserID(id int64) error {
	_, err := s.db.Exec(`UPDATE members SET hs_user_id = '' WHERE id = ?`, id)
	return err
}

func (s *Store) SetMemberStatus(id int64, status string) error {
	return s.SetMemberStatusAudited(id, status, nil)
}

func (s *Store) SetMemberStatusAudited(id int64, status string, audit *AuditRecord) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		ts := s.unixNow()
		var removed any
		if status == "removed" {
			removed = ts
		}
		res, err := c.ExecContext(ctx, `UPDATE members SET status = ?, removed_at = ? WHERE id = ? AND status != 'removed'`, status, removed, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return conflict("member has already been removed")
		}
		if audit != nil {
			if err := insertAuditTx(ctx, c, ts, *audit); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) SetMemberRole(id int64, role string) error {
	_, err := s.db.Exec(`UPDATE members SET role = ? WHERE id = ?`, role, id)
	return err
}

// SetMemberRoleAudited atomically updates a non-owner member's role, writes
// the role-change audit entry, and optionally revokes open invites minted by
// the member (recording the invite revocation audit entry when any are revoked).
func (s *Store) SetMemberRoleAudited(id int64, role string, revokeOpenInvites bool, audit AuditRecord) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		ts := s.unixNow()
		if _, err := c.ExecContext(ctx, `UPDATE members SET role = ? WHERE id = ?`, role, id); err != nil {
			return err
		}
		if err := insertAuditTx(ctx, c, ts, audit); err != nil {
			return err
		}
		if revokeOpenInvites {
			res, err := c.ExecContext(ctx, `UPDATE invites SET revoked_at = ? WHERE minted_by = ? AND redeemed_at IS NULL AND revoked_at IS NULL`, ts, id)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				if err := insertAuditTx(ctx, c, ts, AuditRecord{
					Actor:  audit.Actor,
					Action: "invite.revoke",
					Target: audit.Target,
					Detail: fmt.Sprintf("%d open, after role change", n),
				}); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// DemoteOwner gives an owner another role only while some other owner
// remains, in one statement, so two owners demoting each other at the same
// moment can never leave the pen with none (there is no recovery: D-16).
func (s *Store) DemoteOwner(id int64, role string) (bool, error) {
	res, err := s.db.Exec(`UPDATE members SET role = ? WHERE id = ? AND role = 'owner'
		AND (SELECT count(*) FROM members WHERE role = 'owner' AND status != 'removed' AND id != ?) > 0`,
		role, id, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// DemoteOwnerAudited atomically demotes an owner (only while another active or
// suspended owner remains), revokes open invites minted by the demoted owner,
// and commits both audit lines in a single BEGIN IMMEDIATE transaction.
func (s *Store) DemoteOwnerAudited(id int64, role string, revokeOpenInvites bool, audit AuditRecord) (bool, error) {
	var demoted bool
	err := withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		ts := s.unixNow()
		res, err := c.ExecContext(ctx, `UPDATE members SET role = ? WHERE id = ? AND role = 'owner'
			AND (SELECT count(*) FROM members WHERE role = 'owner' AND status != 'removed' AND id != ?) > 0`,
			role, id, id)
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
		demoted = true
		if err := insertAuditTx(ctx, c, ts, audit); err != nil {
			return err
		}
		if revokeOpenInvites {
			invRes, err := c.ExecContext(ctx, `UPDATE invites SET revoked_at = ? WHERE minted_by = ? AND redeemed_at IS NULL AND revoked_at IS NULL`, ts, id)
			if err != nil {
				return err
			}
			if invN, _ := invRes.RowsAffected(); invN > 0 {
				if err := insertAuditTx(ctx, c, ts, AuditRecord{
					Actor:  audit.Actor,
					Action: "invite.revoke",
					Target: audit.Target,
					Detail: fmt.Sprintf("%d open, after role change", invN),
				}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return demoted, err
}

func (s *Store) CountOwners() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM members WHERE role = 'owner' AND status != 'removed'`).Scan(&n)
	return n, err
}

func (s *Store) DeleteMember(id int64) error {
	_, err := s.db.Exec(`DELETE FROM members WHERE id = ?`, id)
	return err
}

// HasPendingMemberCleanup reports whether any removed member still has a
// Headscale user ID pending deletion OR any live device row (including
// tag:server nodes, which carry no Headscale user).
func (s *Store) HasPendingMemberCleanup() (bool, error) {
	var exists int
	err := s.db.QueryRow(`SELECT EXISTS(
		SELECT 1 FROM members WHERE status = 'removed' AND hs_user_id != ''
		UNION ALL
		SELECT 1 FROM devices d JOIN members m ON m.id = d.member_id
		WHERE d.removed_at IS NULL AND m.status = 'removed'
	)`).Scan(&exists)
	return exists != 0, err
}
