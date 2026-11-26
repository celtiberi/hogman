package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the registrar's ledger: the source of truth for who is a member,
// which devices belong to whom, invites, names and the audit log.
type Store struct {
	db   *sql.DB
	path string
}

const schema = `
CREATE TABLE IF NOT EXISTS members (
	id          INTEGER PRIMARY KEY,
	handle      TEXT NOT NULL UNIQUE,
	role        TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
	status      TEXT NOT NULL CHECK (status IN ('active','suspended','removed')),
	invited_by  INTEGER REFERENCES members(id),
	hs_user_id  TEXT NOT NULL,
	created_at  INTEGER NOT NULL,
	removed_at  INTEGER
);
CREATE TABLE IF NOT EXISTS invites (
	id           INTEGER PRIMARY KEY,
	token_hash   TEXT NOT NULL UNIQUE,
	minted_by    INTEGER REFERENCES members(id),   -- NULL: minted from the server CLI
	role         TEXT NOT NULL,
	note         TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	redeemed_by  INTEGER REFERENCES members(id),
	redeemed_at  INTEGER,
	revoked_at   INTEGER
);
-- Every one-time device key the registrar has asked Headscale for. A device
-- that joins with one of these keys belongs to that key's member.
CREATE TABLE IF NOT EXISTS device_keys (
	id          INTEGER PRIMARY KEY,
	member_id   INTEGER NOT NULL REFERENCES members(id),
	kind        TEXT NOT NULL CHECK (kind IN ('personal','server')),
	hs_key_id   TEXT NOT NULL UNIQUE,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	used_at     INTEGER,
	revoked_at  INTEGER,
	bypass_cap  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS device_keys_open ON device_keys(expires_at) WHERE used_at IS NULL AND revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS devices (
	id                INTEGER PRIMARY KEY,
	member_id         INTEGER NOT NULL REFERENCES members(id),
	kind              TEXT NOT NULL,
	hs_node_id        TEXT NOT NULL,
	node_key          TEXT NOT NULL DEFAULT '',
	machine_key       TEXT NOT NULL DEFAULT '',
	name              TEXT NOT NULL,
	ipv4              TEXT NOT NULL DEFAULT '',
	ipv6              TEXT NOT NULL DEFAULT '',
	created_at        INTEGER NOT NULL,
	removed_at        INTEGER,
	hs_delete_pending INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS devices_live_node ON devices(hs_node_id) WHERE removed_at IS NULL;
-- Monotonic policy generation counter bumped automatically by SQLite triggers
-- on every table read by buildPolicy() (members and devices), so concurrent
-- registrar serve and CLI mutations can never lose a pending policy push.
CREATE TABLE IF NOT EXISTS sync_state (
	id          INTEGER PRIMARY KEY CHECK (id = 1),
	policy_gen  INTEGER NOT NULL DEFAULT 0,
	applied_gen INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO sync_state (id, policy_gen, applied_gen) VALUES (1, 0, 0);
-- A brand-new member has 0 devices and cannot change buildPolicy() output;
-- upgraded databases drop legacy members_policy_gen_ai and update
-- devices_policy_gen_au via migratePolicyTriggers so read-only CLI opens do
-- not rewrite sqlite_master.
CREATE TRIGGER IF NOT EXISTS members_policy_gen_au AFTER UPDATE OF role, status ON members WHEN OLD.role IS NOT NEW.role OR OLD.status IS NOT NEW.status BEGIN UPDATE sync_state SET policy_gen = policy_gen + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS members_policy_gen_ad AFTER DELETE ON members BEGIN UPDATE sync_state SET policy_gen = policy_gen + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS devices_policy_gen_ai AFTER INSERT ON devices BEGIN UPDATE sync_state SET policy_gen = policy_gen + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS devices_policy_gen_au AFTER UPDATE OF member_id, kind, ipv4, removed_at ON devices WHEN OLD.member_id IS NOT NEW.member_id OR OLD.kind IS NOT NEW.kind OR OLD.ipv4 IS NOT NEW.ipv4 OR OLD.removed_at IS NOT NEW.removed_at BEGIN UPDATE sync_state SET policy_gen = policy_gen + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS devices_policy_gen_ad AFTER DELETE ON devices BEGIN UPDATE sync_state SET policy_gen = policy_gen + 1 WHERE id = 1; END;
CREATE TABLE IF NOT EXISTS names (
	name        TEXT PRIMARY KEY,        -- relative to the zone: "alice", "blog.alice"
	member_id   INTEGER NOT NULL REFERENCES members(id),
	device_id   INTEGER REFERENCES devices(id),
	note        TEXT NOT NULL DEFAULT '',
	private     INTEGER NOT NULL DEFAULT 0,
	held_until  INTEGER,                 -- non-NULL once the owner is removed or private name released; permanently retired (never reused)
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
	id      INTEGER PRIMARY KEY,
	at      INTEGER NOT NULL,
	actor   TEXT NOT NULL,
	action  TEXT NOT NULL,
	target  TEXT NOT NULL,
	detail  TEXT NOT NULL DEFAULT ''
);
`

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer; keeps transactions simple
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	for _, m := range []struct{ table, col, def string }{
		{"names", "note", "TEXT NOT NULL DEFAULT ''"},
		{"names", "private", "INTEGER NOT NULL DEFAULT 0"},
		{"devices", "node_key", "TEXT NOT NULL DEFAULT ''"},
		{"devices", "machine_key", "TEXT NOT NULL DEFAULT ''"},
		{"devices", "hs_delete_pending", "INTEGER NOT NULL DEFAULT 0"},
		{"device_keys", "bypass_cap", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := ensureColumn(db, m.table, m.col, m.def); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate %s.%s: %w", m.table, m.col, err)
		}
	}
	if err := migratePolicyTriggers(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate policy triggers: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

func (s *Store) lockAdvisoryFile(suffix string) (func(), error) {
	if s.path == "" || s.path == ":memory:" || strings.HasPrefix(s.path, "file::memory:") {
		return func() {}, nil
	}
	f, err := os.OpenFile(s.path+suffix, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// lockPolicyFile serializes Headscale policy builds and pushes across
// concurrent registrar serve and CLI processes using an advisory file lock.
func (s *Store) lockPolicyFile() (func(), error) {
	return s.lockAdvisoryFile(".policy.lock")
}

// lockMemberFile serializes Headscale user creation and rollback across
// concurrent registrar serve and CLI processes so a cap-rollback DeleteUser
// can never delete a Headscale user adopted by a concurrent member add.
func (s *Store) lockMemberFile() (func(), error) {
	return s.lockAdvisoryFile(".member.lock")
}

// Close closes the underlying SQLite database handle.
func (s *Store) Close() error { return s.db.Close() }

func hasColumn(db *sql.DB, table, col string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}

func ensureColumn(db *sql.DB, table, col, def string) error {
	if has, err := hasColumn(db, table, col); err != nil || has {
		return err
	}
	if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, col, def)); err != nil {
		if has, checkErr := hasColumn(db, table, col); checkErr == nil && has {
			return nil
		}
		return err
	}
	return nil
}

func withImmediateTx(db *sql.DB, fn func(*sql.Conn) error) error {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	if err := fn(conn); err != nil {
		_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		return err
	}
	return nil
}

// migratePolicyTriggers performs one-time trigger cleanups on upgraded DBs
// without acquiring write locks on steady-state read-only CLI opens:
//  1. Drops legacy members_policy_gen_ai (a new member has 0 devices).
//  2. Atomically (BEGIN IMMEDIATE) recreates devices_policy_gen_au without ipv6
//     (policy is IPv4-only), so concurrent processes cannot slip a mutation
//     through between DROP and CREATE.
func migratePolicyTriggers(db *sql.DB) error {
	var legacyMemberTrig int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = 'members_policy_gen_ai'`).Scan(&legacyMemberTrig); err != nil {
		return err
	}
	var devTrigSQL sql.NullString
	err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'devices_policy_gen_au'`).Scan(&devTrigSQL)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	needDevTrig := devTrigSQL.Valid && strings.Contains(strings.ToLower(devTrigSQL.String), "ipv6")
	if legacyMemberTrig == 0 && !needDevTrig {
		return nil
	}
	return withImmediateTx(db, func(c *sql.Conn) error {
		ctx := context.Background()
		if legacyMemberTrig > 0 {
			if _, err := c.ExecContext(ctx, `DROP TRIGGER IF EXISTS members_policy_gen_ai`); err != nil {
				return err
			}
		}
		if needDevTrig {
			var cur sql.NullString
			if err := c.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'devices_policy_gen_au'`).Scan(&cur); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if cur.Valid && strings.Contains(strings.ToLower(cur.String), "ipv6") {
				if _, err := c.ExecContext(ctx, `DROP TRIGGER IF EXISTS devices_policy_gen_au`); err != nil {
					return err
				}
				if _, err := c.ExecContext(ctx, `CREATE TRIGGER IF NOT EXISTS devices_policy_gen_au
					AFTER UPDATE OF member_id, kind, ipv4, removed_at ON devices
					WHEN OLD.member_id IS NOT NEW.member_id
					  OR OLD.kind IS NOT NEW.kind
					  OR OLD.ipv4 IS NOT NEW.ipv4
					  OR OLD.removed_at IS NOT NEW.removed_at
					BEGIN UPDATE sync_state SET policy_gen = policy_gen + 1 WHERE id = 1; END`); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

var ErrNotFound = errors.New("not found")

func now() int64 { return time.Now().Unix() }

// ---------------------------------------------------------------- members --

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

var (
	ErrMemberCapReached      = errors.New("member limit reached")
	ErrDeviceCapReached      = errors.New("device limit reached")
	ErrOpenKeyCapReached     = errors.New("open device key limit reached")
	ErrDeviceAlreadyEnrolled = errors.New("device already enrolled")
)

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
		res, err := c.ExecContext(ctx, `INSERT INTO members (handle, role, status, invited_by, hs_user_id, created_at) VALUES (?,?,?,?,?,?)`,
			m.Handle, m.Role, m.Status, m.InvitedBy, m.HSUserID, now())
		if err != nil {
			return err
		}
		m.ID, _ = res.LastInsertId()
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
	var removed any
	if status == "removed" {
		removed = now()
	}
	res, err := s.db.Exec(`UPDATE members SET status = ?, removed_at = ? WHERE id = ? AND status != 'removed'`, status, removed, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return conflict("member has already been removed")
	}
	return nil
}

func (s *Store) SetMemberRole(id int64, role string) error {
	_, err := s.db.Exec(`UPDATE members SET role = ? WHERE id = ?`, role, id)
	return err
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

func (s *Store) CountOwners() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM members WHERE role = 'owner' AND status != 'removed'`).Scan(&n)
	return n, err
}

func (s *Store) DeleteMember(id int64) error {
	_, err := s.db.Exec(`DELETE FROM members WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------- invites --

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
	switch {
	case i.RedeemedAt != nil:
		return "redeemed"
	case i.RevokedAt != nil:
		return "revoked"
	case i.ExpiresAt <= now():
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
	res, err := s.db.Exec(`INSERT INTO invites (token_hash, minted_by, role, note, created_at, expires_at) VALUES (?,?,?,?,?,?)`,
		tokenHash, i.MintedBy, i.Role, i.Note, i.CreatedAt, i.ExpiresAt)
	if err != nil {
		return err
	}
	i.ID, _ = res.LastInsertId()
	return nil
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
		ORDER BY id DESC LIMIT ?`, now(), limit)
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
	res, err := s.db.Exec(`UPDATE invites SET redeemed_by = ?, redeemed_at = ?
		WHERE id = ? AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, memberID, now(), id, now())
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
	_, err := s.db.Exec(`UPDATE invites SET revoked_at = ? WHERE id = ? AND redeemed_at IS NULL AND revoked_at IS NULL`, now(), id)
	return err
}

func (s *Store) RevokeOpenInvitesBy(memberID int64) (int64, error) {
	res, err := s.db.Exec(`UPDATE invites SET revoked_at = ? WHERE minted_by = ? AND redeemed_at IS NULL AND revoked_at IS NULL`, now(), memberID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

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
		now()).Scan(&live, &openKeys)
	return live, openKeys, err
}

// CountMemberPersonalSlots returns a member's live personal devices plus open
// personal device keys (used for D-16 per-owner personal lockout headroom).
func (s *Store) CountMemberPersonalSlots(memberID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM devices WHERE removed_at IS NULL AND member_id = ? AND kind = 'personal') +
		(SELECT COUNT(*) FROM device_keys WHERE member_id = ? AND kind = 'personal' AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?)`,
		memberID, memberID, now()).Scan(&n)
	return n, err
}

// InsertDeviceKeyCapped inserts a device key inside BEGIN IMMEDIATE, atomically
// enforcing per-member open-key limits (maxOpenForMember > 0) and pen-wide
// live_devices + open_device_keys limits (maxDevices > 0). When ownerPersonalFloor
// > 0, an active owner's personal key is also allowed whenever that owner holds
// fewer than ownerPersonalFloor live+open personal slots (D-16 lockout protection
// on grandfathered over-cap pens).
func (s *Store) InsertDeviceKeyCapped(k *DeviceKey, maxDevices, maxOpenForMember, ownerPersonalFloor int) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		ts := now()
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
		WHERE member_id = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, memberID, now()).Scan(&n)
	return n, err
}

// HasOpenDeviceKeys reports whether any member has an unused, unrevoked,
// unexpired device key awaiting enrolment.
func (s *Store) HasOpenDeviceKeys() (bool, error) {
	var exists int
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM device_keys
		WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?)`, now()).Scan(&exists)
	return exists != 0, err
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

// PolicyGenerations returns the monotonic policy_gen bumped by SQLite triggers
// on every members/devices change and the highest generation confirmed applied
// to Headscale.
func (s *Store) PolicyGenerations() (policyGen, appliedGen int64, err error) {
	err = s.db.QueryRow(`SELECT policy_gen, applied_gen FROM sync_state WHERE id = 1`).Scan(&policyGen, &appliedGen)
	return policyGen, appliedGen, err
}

// MarkPolicyApplied records that Headscale has accepted policy state up through gen.
func (s *Store) MarkPolicyApplied(gen int64) error {
	_, err := s.db.Exec(`UPDATE sync_state SET applied_gen = MAX(applied_gen, ?) WHERE id = 1`, gen)
	return err
}

func (s *Store) CountOpenInvites(memberID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM invites
		WHERE minted_by = ? AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, memberID, now()).Scan(&n)
	return n, err
}

func (s *Store) CountMemberNames(memberID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM names WHERE member_id = ? AND held_until IS NULL`, memberID).Scan(&n)
	return n, err
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
	_, err := s.db.Exec(`UPDATE device_keys SET used_at = ? WHERE id = ? AND used_at IS NULL`, now(), id)
	return err
}

// OpenDeviceKeys returns keys of a member that are unused, unrevoked and unexpired.
func (s *Store) OpenDeviceKeys(memberID int64) ([]*DeviceKey, error) {
	rows, err := s.db.Query(`SELECT id, member_id, kind, hs_key_id, expires_at FROM device_keys
		WHERE member_id = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, memberID, now())
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
	_, err := s.db.Exec(`UPDATE device_keys SET revoked_at = ? WHERE id = ?`, now(), id)
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
		ts := now()
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
	res, err := s.db.Exec(`UPDATE devices SET node_key = ?
		WHERE id = ? AND node_key = ? AND machine_key = ? AND removed_at IS NULL
		  AND EXISTS (SELECT 1 FROM members WHERE id = devices.member_id AND status = 'active')`,
		newNodeKey, id, oldNodeKey, machineKey)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

type sqlExecContexter interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// releaseLeafNamesOfDevice frees active leaf names pointing at a device while
// unpointing (instead of deleting) any parent name that still has child
// subdomains elsewhere, and permanently retiring private random labels (D-21).
// Shared by DeleteNamesOfDevice and CommitSelfDelete.
func releaseLeafNamesOfDevice(ctx context.Context, ex sqlExecContexter, deviceID int64) error {
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
		WHERE device_id = ? AND held_until IS NULL AND private != 0`, now(), deviceID); err != nil {
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
		return releaseLeafNamesOfDevice(context.Background(), c, deviceID)
	})
}

// MarkDeviceRemoved retires a device and unpoints any names aimed at it.
func (s *Store) MarkDeviceRemoved(id int64) error {
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		if _, err := c.ExecContext(ctx, `UPDATE devices SET removed_at = ? WHERE id = ? AND removed_at IS NULL`, now(), id); err != nil {
			return err
		}
		if _, err := c.ExecContext(ctx, `UPDATE names SET device_id = NULL WHERE device_id = ?`, id); err != nil {
			return err
		}
		return nil
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
				return forbidden("membership removed")
			}
			return err
		}
		if status != "active" {
			return forbidden("membership %s", status)
		}
		d, err := scanDevice(c.QueryRowContext(ctx, `SELECT `+deviceCols+deviceFrom+`WHERE d.id = ?`, deviceID))
		if errors.Is(err, ErrNotFound) || (err == nil && d.RemovedAt != nil) {
			return missing("no device %d", deviceID)
		} else if err != nil {
			return err
		}
		if d.MemberID != memberID {
			return forbidden("not your device")
		}
		// Release leaf names served by this device (preserving parent names that
		// still have child subdomains elsewhere), shared with DeleteNamesOfDevice.
		if err := releaseLeafNamesOfDevice(ctx, c, d.ID); err != nil {
			return err
		}
		ts := now()
		res, err := c.ExecContext(ctx, `UPDATE devices SET removed_at = ?, hs_delete_pending = 1 WHERE id = ? AND removed_at IS NULL`, ts, d.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return missing("no device %d", deviceID)
		}
		if _, err := c.ExecContext(ctx, `UPDATE names SET device_id = NULL WHERE device_id = ?`, d.ID); err != nil {
			return err
		}
		if _, err := c.ExecContext(ctx, `INSERT INTO audit (at, actor, action, target, detail) VALUES (?,?,?,?,?)`,
			ts, actor, "device.remove", fmt.Sprintf("%s/%s#%d", handle, d.Name, d.ID), ""); err != nil {
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

// ------------------------------------------------------------------ names --

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

func (s *Store) UpsertName(name string, memberID int64, deviceID *int64, note string) error {
	return s.UpsertNameWithPrivate(name, memberID, deviceID, note, false)
}

func (s *Store) UpsertNameWithPrivate(name string, memberID int64, deviceID *int64, note string, private bool) error {
	priv := 0
	if private {
		priv = 1
	}
	res, err := s.db.Exec(`INSERT INTO names (name, member_id, device_id, note, private, created_at) VALUES (?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
			member_id = excluded.member_id,
			device_id = excluded.device_id,
			note = excluded.note,
			private = CASE WHEN names.private = 1 THEN 1 ELSE excluded.private END
		WHERE names.held_until IS NULL`,
		name, memberID, deviceID, note, priv, now())
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("name %s is retired", name)
	}
	return nil
}

func (s *Store) DeleteName(name string) error {
	_, err := s.db.Exec(`DELETE FROM names WHERE name = ? AND held_until IS NULL`, name)
	return err
}

// RetireName unpoints a single name and permanently retires it (random private
// labels are never recycled once released).
func (s *Store) RetireName(name string) error {
	_, err := s.db.Exec(`UPDATE names SET device_id = NULL, held_until = ?, note = '' WHERE name = ? AND held_until IS NULL`, now(), name)
	return err
}

// ReleaseNames atomically releases a set of active names, permanently retiring
// private random labels and deleting non-private names.
func (s *Store) ReleaseNames(rows []*Name) error {
	if len(rows) == 0 {
		return nil
	}
	return withImmediateTx(s.db, func(c *sql.Conn) error {
		ctx := context.Background()
		ts := now()
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
		return nil
	})
}

// RetireNames unpoints all of a member's names and retires them permanently.
func (s *Store) RetireNames(memberID int64) (int64, error) {
	res, err := s.db.Exec(`UPDATE names SET device_id = NULL, held_until = ?, note = '' WHERE member_id = ?`, now(), memberID)
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

// ------------------------------------------------------------------ audit --

type AuditEntry struct {
	At     int64  `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail,omitempty"`
}

func (s *Store) Audit(actor, action, target, detail string) {
	if _, err := s.db.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?,?,?,?,?)`, now(), actor, action, target, detail); err != nil {
		// Never fail the action over its audit line, but don't lose it silently either.
		log.Printf("audit %s %s %s: %v", actor, action, target, err)
	}
}

func (s *Store) AuditLog(limit int) ([]*AuditEntry, error) {
	rows, err := s.db.Query(`SELECT at, actor, action, target, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.At, &a.Actor, &a.Action, &a.Target, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}
