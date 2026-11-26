package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type Name struct {
	Name       string `json:"name"`
	MemberID   int64  `json:"member_id"`
	Member     string `json:"member"`
	DeviceID   *int64 `json:"device_id,omitempty"`
	DeviceKind string `json:"-"`
	HSNodeID   string `json:"-"`
	Note       string `json:"note,omitempty"`
	Private    bool   `json:"private,omitempty"`
	IPv4       string `json:"ipv4,omitempty"`
	IPv6       string `json:"ipv6,omitempty"`
	// RetiredAt is stored in names.held_until for backward compatibility with existing DBs;
	// any non-NULL value means the name is permanently retired and may never be reused.
	RetiredAt *int64 `json:"retired_at,omitempty"`
}

func (s *Store) queryNames(where string, args ...any) ([]*Name, error) {
	rows, err := s.db.Query(`SELECT n.name, n.member_id, m.handle, n.device_id, COALESCE(d.kind, ''), COALESCE(d.hs_node_id, ''), n.note, n.private, COALESCE(d.ipv4, ''), COALESCE(d.ipv6, ''), n.held_until
		FROM names n JOIN members m ON m.id = n.member_id
		LEFT JOIN devices d ON d.id = n.device_id AND d.removed_at IS NULL `+where+` ORDER BY n.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Name
	for rows.Next() {
		var n Name
		var priv int
		if err := rows.Scan(&n.Name, &n.MemberID, &n.Member, &n.DeviceID, &n.DeviceKind, &n.HSNodeID, &n.Note, &priv, &n.IPv4, &n.IPv6, &n.RetiredAt); err != nil {
			return nil, err
		}
		n.Private = priv != 0
		out = append(out, &n)
	}
	return out, rows.Err()
}

func (s *Store) Names() ([]*Name, error) { return s.queryNames(``) }

func (s *Store) NameByName(name string) (*Name, error) {
	ns, err := s.queryNames(`WHERE n.name = ?`, name)
	if err != nil {
		return nil, err
	}
	if len(ns) == 0 {
		return nil, ErrNotFound
	}
	return ns[0], nil
}

func (s *Store) CountMemberNames(memberID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM names WHERE member_id = ? AND held_until IS NULL`, memberID).Scan(&n)
	return n, err
}

func (s *Store) UpsertName(name string, memberID int64, deviceID *int64, note string) error {
	return s.UpsertNameWithPrivate(name, memberID, deviceID, note, false)
}

func (s *Store) UpsertNameWithPrivate(name string, memberID int64, deviceID *int64, note string, private bool) error {
	return s.UpsertNameWithPrivateAudited(name, memberID, deviceID, note, private, nil)
}

func (s *Store) UpsertNameWithPrivateAudited(name string, memberID int64, deviceID *int64, note string, private bool, audit *AuditRecord) error {
	priv := 0
	if private {
		priv = 1
	}
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		ts := s.unixNow()
		res, err := c.ExecContext(ctx, `INSERT INTO names (name, member_id, device_id, note, private, created_at) VALUES (?,?,?,?,?,?)
			ON CONFLICT(name) DO UPDATE SET
				member_id = excluded.member_id,
				device_id = excluded.device_id,
				note = excluded.note,
				private = CASE WHEN names.private = 1 THEN 1 ELSE excluded.private END
			WHERE names.held_until IS NULL`,
			name, memberID, deviceID, note, priv, ts)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			return fmt.Errorf("name %s is retired", name)
		}
		if audit != nil {
			if err := insertAuditTx(ctx, c, ts, *audit); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) DeleteName(name string) error {
	_, err := s.db.Exec(`DELETE FROM names WHERE name = ? AND held_until IS NULL`, name)
	return err
}

// RetireName unpoints a single name and permanently retires it (random private
// labels are never recycled once released).
func (s *Store) RetireName(name string) error {
	_, err := s.db.Exec(`UPDATE names SET device_id = NULL, held_until = ?, note = '' WHERE name = ? AND held_until IS NULL`, s.unixNow(), name)
	return err
}

// ReleaseNames atomically releases a set of active names, permanently retiring
// private random labels and deleting non-private names.
func (s *Store) ReleaseNames(rows []*Name) error {
	return s.ReleaseNamesAudited(rows, nil)
}

func (s *Store) ReleaseNamesAudited(rows []*Name, audit *AuditRecord) error {
	if len(rows) == 0 {
		return nil
	}
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		ts := s.unixNow()
		for _, x := range rows {
			if x.Private {
				if _, err := c.ExecContext(ctx, `UPDATE names SET device_id = NULL, held_until = ?, note = '' WHERE name = ? AND member_id = ? AND private != 0 AND held_until IS NULL`, ts, x.Name, x.MemberID); err != nil {
					return err
				}
			} else {
				if _, err := c.ExecContext(ctx, `DELETE FROM names WHERE name = ? AND member_id = ? AND private = 0 AND held_until IS NULL`, x.Name, x.MemberID); err != nil {
					return err
				}
			}
		}
		if audit != nil {
			if err := insertAuditTx(ctx, c, ts, *audit); err != nil {
				return err
			}
		}
		return nil
	})
}

// RetireNames unpoints all of a member's names and retires them permanently.
func (s *Store) RetireNames(memberID int64) (int64, error) {
	res, err := s.db.Exec(`UPDATE names SET device_id = NULL, held_until = ?, note = '' WHERE member_id = ?`, s.unixNow(), memberID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ResolvableNames are names that should appear in DNS: pointed at a live device
// of a member who has not been removed.
func (s *Store) ResolvableNames() ([]*Name, error) {
	return s.queryNames(`WHERE n.held_until IS NULL AND d.id IS NOT NULL AND m.status != 'removed'`)
}

// ResolvableName returns one name if it should appear in DNS right now.
func (s *Store) ResolvableName(name string) (*Name, error) {
	ns, err := s.queryNames(`WHERE n.name = ? AND n.held_until IS NULL AND d.id IS NOT NULL AND m.status != 'removed'`, name)
	if err != nil {
		return nil, err
	}
	if len(ns) == 0 {
		return nil, ErrNotFound
	}
	return ns[0], nil
}

// HasResolvableChild reports whether any resolvable subdomain exists under name.
func (s *Store) HasResolvableChild(name string) (bool, error) {
	escaped := "%." + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(name)
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM names n
		JOIN members m ON m.id = n.member_id
		JOIN devices d ON d.id = n.device_id AND d.removed_at IS NULL
		WHERE n.held_until IS NULL AND m.status != 'removed' AND n.name LIKE ? ESCAPE '\' LIMIT 1`, escaped).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
