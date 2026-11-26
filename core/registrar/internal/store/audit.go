package store

import "context"

type AuditEntry struct {
	At     int64  `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail,omitempty"`
}

// AuditRecord carries the fields written to the audit table inside a
// transactional mutation so state changes and their audit lines commit
// atomically.
type AuditRecord struct {
	Actor  string
	Action string
	Target string
	Detail string
}

func insertAuditTx(ctx context.Context, ex sqlExecContexter, ts int64, rec AuditRecord) error {
	_, err := ex.ExecContext(ctx, `INSERT INTO audit (at, actor, action, target, detail) VALUES (?,?,?,?,?)`,
		ts, rec.Actor, rec.Action, rec.Target, rec.Detail)
	return err
}

func (s *Store) Audit(actor, action, target, detail string) {
	if _, err := s.db.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?,?,?,?,?)`, s.unixNow(), actor, action, target, detail); err != nil {
		// Never fail the action over its audit line, but don't lose it silently either.
		s.loggerOrDefault().Error("audit write failed", "actor", actor, "action", action, "target", target, "err", err)
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
