package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the registrar's ledger: the source of truth for who is a member,
// which devices belong to whom, invites, names and the audit log.
type Store struct {
	db      *sql.DB
	path    string
	logger  *slog.Logger
	clockMu sync.RWMutex
	clock   func() time.Time
}

// SetClock binds the store's unix timestamp source to fn (no-op if already set
// or if fn is nil), keeping Service and Store on a single injected clock.
func (s *Store) SetClock(fn func() time.Time) {
	if s == nil || fn == nil {
		return
	}
	s.clockMu.Lock()
	if s.clock == nil {
		s.clock = fn
	}
	s.clockMu.Unlock()
}

func (s *Store) unixNow() int64 {
	if s != nil {
		s.clockMu.RLock()
		fn := s.clock
		s.clockMu.RUnlock()
		if fn != nil {
			return fn().Unix()
		}
	}
	return time.Now().Unix()
}

func (s *Store) loggerOrDefault() *slog.Logger {
	if s != nil && s.logger != nil {
		return s.logger
	}
	return slog.Default()
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
	return &Store{db: db, path: path, logger: slog.Default()}, nil
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

type sqlExecContexter interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

var (
	ErrNotFound              = errors.New("not found")
	ErrMemberCapReached      = errors.New("member limit reached")
	ErrDeviceCapReached      = errors.New("device limit reached")
	ErrOpenKeyCapReached     = errors.New("open device key limit reached")
	ErrDeviceAlreadyEnrolled = errors.New("device already enrolled")
)

func now() int64 { return time.Now().Unix() }
