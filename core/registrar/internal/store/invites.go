package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type Invite struct {
	ID         int64  `json:"id"`
	MintedBy   *int64 `json:"minted_by,omitempty"`
	Role       string `json:"role"`
	Note       string `json:"note,omitempty"`
	CreatedAt  int64  `json:"created_at"`
	ExpiresAt  int64  `json:"expires_at"`
	RedeemedBy *int64 `json:"redeemed_by,omitempty"`
	RedeemedAt *int64 `json:"redeemed_at,omitempty"`
	RevokedAt  *int64 `json:"revoked_at,omitempty"`
}

func (i *Invite) State() string {
	return i.StateAt(time.Now().Unix())
}

func (i *Invite) StateAt(nowUnix int64) string {
	switch {
	case i.RedeemedAt != nil:
		return "redeemed"
	case i.RevokedAt != nil:
		return "revoked"
	case i.ExpiresAt <= nowUnix:
		return "expired"
	}
	return "open"
}

const inviteCols = `id, minted_by, role, note, created_at, expires_at, redeemed_by, redeemed_at, revoked_at`

func scanInvite(r interface{ Scan(...any) error }) (*Invite, error) {
	var i Invite
	err := r.Scan(&i.ID, &i.MintedBy, &i.Role, &i.Note, &i.CreatedAt, &i.ExpiresAt, &i.RedeemedBy, &i.RedeemedAt, &i.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &i, err
}

func (s *Store) InsertInvite(tokenHash string, i *Invite) error {
	return s.InsertInviteAudited(tokenHash, i, nil)
}

func (s *Store) InsertInviteAudited(tokenHash string, i *Invite, auditFn func(id int64) AuditRecord) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		res, err := c.ExecContext(ctx, `INSERT INTO invites (token_hash, minted_by, role, note, created_at, expires_at) VALUES (?,?,?,?,?,?)`,
			tokenHash, i.MintedBy, i.Role, i.Note, i.CreatedAt, i.ExpiresAt)
		if err != nil {
			return err
		}
		i.ID, _ = res.LastInsertId()
		if auditFn != nil {
			if err := insertAuditTx(ctx, c, i.CreatedAt, auditFn(i.ID)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) InviteByHash(h string) (*Invite, error) {
	return scanInvite(s.db.QueryRow(`SELECT `+inviteCols+` FROM invites WHERE token_hash = ?`, h))
}

func (s *Store) InviteByID(id int64) (*Invite, error) {
	return scanInvite(s.db.QueryRow(`SELECT `+inviteCols+` FROM invites WHERE id = ?`, id))
}

// OpenInvites lists unused, unrevoked, unexpired invites, newest first.
func (s *Store) OpenInvites(limit int) ([]*Invite, error) {
	rows, err := s.db.Query(`SELECT `+inviteCols+` FROM invites
		WHERE redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > ?
		ORDER BY id DESC LIMIT ?`, s.unixNow(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Invite{}
	for rows.Next() {
		i, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *Store) Invites(mintedBy *int64) ([]*Invite, error) {
	q, args := `SELECT `+inviteCols+` FROM invites ORDER BY id`, []any{}
	if mintedBy != nil {
		q, args = `SELECT `+inviteCols+` FROM invites WHERE minted_by = ? ORDER BY id`, []any{*mintedBy}
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Invite
	for rows.Next() {
		i, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// ClaimInvite marks an open invite redeemed. Returns false if someone else got there first.
func (s *Store) ClaimInvite(id, memberID int64) (bool, error) {
	ts := s.unixNow()
	res, err := s.db.Exec(`UPDATE invites SET redeemed_by = ?, redeemed_at = ?
		WHERE id = ? AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, memberID, ts, id, ts)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *Store) UnclaimInvite(id, memberID int64) error {
	_, err := s.db.Exec(`UPDATE invites SET redeemed_by = NULL, redeemed_at = NULL WHERE id = ? AND redeemed_by = ?`, id, memberID)
	return err
}

func (s *Store) RevokeInvite(id int64) error {
	return s.RevokeInviteAudited(id, nil)
}

func (s *Store) RevokeInviteAudited(id int64, audit *AuditRecord) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		ts := s.unixNow()
		res, err := c.ExecContext(ctx, `UPDATE invites SET revoked_at = ? WHERE id = ? AND redeemed_at IS NULL AND revoked_at IS NULL`, ts, id)
		if err != nil {
			return err
		}
		if audit != nil {
			if n, _ := res.RowsAffected(); n > 0 {
				if err := insertAuditTx(ctx, c, ts, *audit); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *Store) RevokeOpenInvitesBy(memberID int64) (int64, error) {
	res, err := s.db.Exec(`UPDATE invites SET revoked_at = ? WHERE minted_by = ? AND redeemed_at IS NULL AND revoked_at IS NULL`, s.unixNow(), memberID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) CountOpenInvites(memberID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM invites
		WHERE minted_by = ? AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, memberID, s.unixNow()).Scan(&n)
	return n, err
}
