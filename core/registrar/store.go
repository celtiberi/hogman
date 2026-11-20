package main

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the registrar's ledger: the source of truth for who is a member,
// which devices belong to whom, invites, names and the audit log.
type Store struct{ db *sql.DB }

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
	revoked_at  INTEGER
);
CREATE TABLE IF NOT EXISTS devices (
	id          INTEGER PRIMARY KEY,
	member_id   INTEGER NOT NULL REFERENCES members(id),
	kind        TEXT NOT NULL,
	hs_node_id  TEXT NOT NULL,
	name        TEXT NOT NULL,
	ipv4        TEXT NOT NULL DEFAULT '',
	ipv6        TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	removed_at  INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS devices_live_node ON devices(hs_node_id) WHERE removed_at IS NULL;
CREATE TABLE IF NOT EXISTS names (
	name        TEXT PRIMARY KEY,        -- relative to the zone: "alice", "blog.alice"
	member_id   INTEGER NOT NULL REFERENCES members(id),
	device_id   INTEGER REFERENCES devices(id),
	held_until  INTEGER,                 -- set when the owner is removed; nobody may claim it until then
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
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer; keeps transactions simple
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
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

func (s *Store) InsertMember(m *Member) error {
	res, err := s.db.Exec(`INSERT INTO members (handle, role, status, invited_by, hs_user_id, created_at) VALUES (?,?,?,?,?,?)`,
		m.Handle, m.Role, m.Status, m.InvitedBy, m.HSUserID, now())
	if err != nil {
		return err
	}
	m.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) SetMemberStatus(id int64, status string) error {
	var removed any
	if status == "removed" {
		removed = now()
	}
	_, err := s.db.Exec(`UPDATE members SET status = ?, removed_at = ? WHERE id = ?`, status, removed, id)
	return err
}

func (s *Store) SetMemberRole(id int64, role string) error {
	_, err := s.db.Exec(`UPDATE members SET role = ? WHERE id = ?`, role, id)
	return err
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
}

func (s *Store) InsertDeviceKey(k *DeviceKey) error {
	res, err := s.db.Exec(`INSERT INTO device_keys (member_id, kind, hs_key_id, created_at, expires_at) VALUES (?,?,?,?,?)`,
		k.MemberID, k.Kind, k.HSKeyID, now(), k.ExpiresAt)
	if err != nil {
		return err
	}
	k.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) PendingDeviceKeys(cutoff int64) (map[string]*DeviceKey, error) {
	rows, err := s.db.Query(`SELECT id, member_id, kind, hs_key_id, expires_at, used_at, revoked_at FROM device_keys
		WHERE used_at IS NULL AND expires_at > ?`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*DeviceKey{}
	for rows.Next() {
		var k DeviceKey
		if err := rows.Scan(&k.ID, &k.MemberID, &k.Kind, &k.HSKeyID, &k.ExpiresAt, &k.UsedAt, &k.RevokedAt); err != nil {
			return nil, err
		}
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
	ID        int64  `json:"id"`
	MemberID  int64  `json:"member_id"`
	Member    string `json:"member"`
	Kind      string `json:"kind"`
	HSNodeID  string `json:"-"`
	Name      string `json:"name"`
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6,omitempty"`
	CreatedAt int64  `json:"created_at"`
	RemovedAt *int64 `json:"removed_at,omitempty"`
}

const deviceCols = `d.id, d.member_id, m.handle, d.kind, d.hs_node_id, d.name, d.ipv4, d.ipv6, d.created_at, d.removed_at`
const deviceFrom = ` FROM devices d JOIN members m ON m.id = d.member_id `

func scanDevice(r interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	err := r.Scan(&d.ID, &d.MemberID, &d.Member, &d.Kind, &d.HSNodeID, &d.Name, &d.IPv4, &d.IPv6, &d.CreatedAt, &d.RemovedAt)
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

func (s *Store) InsertDevice(d *Device) error {
	res, err := s.db.Exec(`INSERT INTO devices (member_id, kind, hs_node_id, name, ipv4, ipv6, created_at) VALUES (?,?,?,?,?,?,?)`,
		d.MemberID, d.Kind, d.HSNodeID, d.Name, d.IPv4, d.IPv6, now())
	if err != nil {
		return err
	}
	d.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateDevice(id int64, name, v4, v6 string) error {
	_, err := s.db.Exec(`UPDATE devices SET name = ?, ipv4 = ?, ipv6 = ? WHERE id = ?`, name, v4, v6, id)
	return err
}

// MarkDeviceRemoved retires a device and unpoints any names aimed at it.
func (s *Store) MarkDeviceRemoved(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE devices SET removed_at = ? WHERE id = ? AND removed_at IS NULL`, now(), id); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE names SET device_id = NULL WHERE device_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ------------------------------------------------------------------ names --

type Name struct {
	Name      string `json:"name"`
	MemberID  int64  `json:"member_id"`
	Member    string `json:"member"`
	DeviceID  *int64 `json:"device_id,omitempty"`
	IPv4      string `json:"ipv4,omitempty"`
	IPv6      string `json:"ipv6,omitempty"`
	HeldUntil *int64 `json:"held_until,omitempty"`
}

func (s *Store) queryNames(where string, args ...any) ([]*Name, error) {
	rows, err := s.db.Query(`SELECT n.name, n.member_id, m.handle, n.device_id, COALESCE(d.ipv4, ''), COALESCE(d.ipv6, ''), n.held_until
		FROM names n JOIN members m ON m.id = n.member_id
		LEFT JOIN devices d ON d.id = n.device_id AND d.removed_at IS NULL `+where+` ORDER BY n.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Name
	for rows.Next() {
		var n Name
		if err := rows.Scan(&n.Name, &n.MemberID, &n.Member, &n.DeviceID, &n.IPv4, &n.IPv6, &n.HeldUntil); err != nil {
			return nil, err
		}
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

func (s *Store) UpsertName(name string, memberID int64, deviceID *int64) error {
	_, err := s.db.Exec(`INSERT INTO names (name, member_id, device_id, created_at) VALUES (?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET member_id = excluded.member_id, device_id = excluded.device_id, held_until = NULL`,
		name, memberID, deviceID, now())
	return err
}

func (s *Store) DeleteName(name string) error {
	_, err := s.db.Exec(`DELETE FROM names WHERE name = ?`, name)
	return err
}

// HoldNames unpoints all of a member's names and blocks anyone claiming them until `until`.
func (s *Store) HoldNames(memberID, until int64) (int64, error) {
	res, err := s.db.Exec(`UPDATE names SET device_id = NULL, held_until = ? WHERE member_id = ?`, until, memberID)
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

// ------------------------------------------------------------------ audit --

type AuditEntry struct {
	At     int64  `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail,omitempty"`
}

func (s *Store) Audit(actor, action, target, detail string) {
	_, _ = s.db.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?,?,?,?,?)`, now(), actor, action, target, detail)
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
