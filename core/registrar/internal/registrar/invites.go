package registrar

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"hogman/registrar/internal/store"
)

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "hmi_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

type MintedInvite struct {
	*store.Invite
	Token string `json:"token"`
	URL   string `json:"url"`
}

func cleanInviteNote(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r == '\r' || r == '\n' || r == '\t' || r == '\u2028' || r == '\u2029':
			b.WriteByte(' ')
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			continue
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func (s *Service) MintInvite(a Actor, role, note string, ttl time.Duration) (*MintedInvite, error) {
	if role == "" {
		role = "member"
	}
	if role != "member" && role != "admin" {
		return nil, bad("invites can be for members or admins")
	}
	if ttl <= 0 {
		ttl = s.cfg.InviteTTL
	}
	if ttl > 30*24*time.Hour {
		return nil, bad("invites can last at most 30 days")
	}
	if len(note) > s.cfg.MaxInviteNoteLen {
		return nil, bad("invite note must be at most %d characters", s.cfg.MaxInviteNoteLen)
	}
	note = cleanInviteNote(note)
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return nil, err
	}
	switch {
	case role == "admin" && !a.IsOwner():
		return nil, forbidden("only the owner can invite admins")
	case !a.IsAdmin() && !s.cfg.MembersCanInvite:
		return nil, forbidden("on this network only admins can invite")
	}
	if !a.CLI {
		count, err := s.st.CountActiveMembers()
		if err != nil {
			return nil, err
		}
		if count >= s.cfg.MaxMembers {
			return nil, conflict("this network has reached its member limit (%d)", s.cfg.MaxMembers)
		}
	}
	if !a.IsAdmin() && a.memberID() != nil {
		n, err := s.st.CountOpenInvites(*a.memberID())
		if err != nil {
			return nil, err
		}
		if n >= s.cfg.MaxOpenInvites {
			return nil, conflict("too many open invites")
		}
	}
	tok := newToken()
	ts := s.clock()
	inv := &store.Invite{MintedBy: a.memberID(), Role: role, Note: note, CreatedAt: ts.Unix(), ExpiresAt: ts.Add(ttl).Unix()}
	actorName := a.String()
	if err := s.st.InsertInviteAudited(hashToken(tok), inv, func(id int64) store.AuditRecord {
		return store.AuditRecord{
			Actor:  actorName,
			Action: "invite.mint",
			Target: fmt.Sprintf("invite#%d", id),
			Detail: "role=" + role,
		}
	}); err != nil {
		return nil, err
	}
	return &MintedInvite{Invite: inv, Token: tok, URL: s.InviteLink(tok)}, nil
}

func (s *Service) RevokeInvite(a Actor, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
	inv, err := s.st.InviteByID(id)
	if errors.Is(err, ErrNotFound) {
		return missing("no invite %d", id)
	} else if err != nil {
		return err
	}
	mine := inv.MintedBy != nil && a.memberID() != nil && *inv.MintedBy == *a.memberID()
	if !a.IsAdmin() && !mine {
		return forbidden("not your invite")
	}
	if st := inv.StateAt(s.clock().Unix()); st != "open" {
		return conflict("invite %d is %s", id, st)
	}
	return s.st.RevokeInviteAudited(id, &store.AuditRecord{
		Actor:  a.String(),
		Action: "invite.revoke",
		Target: fmt.Sprintf("invite#%d", id),
	})
}

type Enrolment struct {
	Handle         string `json:"handle"`
	Zone           string `json:"zone"`
	LoginServer    string `json:"login_server"`
	AuthKey        string `json:"auth_key"`
	AuthKeyExpires int64  `json:"auth_key_expires"`
	Portal         string `json:"portal"`
}

// Redeem turns an invite into a membership plus a key for the first device.
// This is the only operation reachable from the public internet.
func (s *Service) Redeem(ctx context.Context, token, handle string) (*Enrolment, error) {
	tok := strings.TrimSpace(token)
	if !strings.HasPrefix(tok, "hmi_") {
		return nil, forbidden("invite not valid")
	}
	hash := hashToken(tok)
	inv, err := s.st.InviteByHash(hash)
	if errors.Is(err, ErrNotFound) {
		return nil, forbidden("invite not valid")
	} else if err != nil {
		return nil, err
	}
	if st := inv.StateAt(s.clock().Unix()); st != "open" {
		return nil, forbidden("invite %s", st)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	inv, err = s.st.InviteByHash(hash)
	if errors.Is(err, ErrNotFound) {
		return nil, forbidden("invite not valid")
	} else if err != nil {
		return nil, err
	}
	if st := inv.StateAt(s.clock().Unix()); st != "open" {
		return nil, forbidden("invite %s", st)
	}
	if inv.MintedBy != nil {
		minter, err := s.st.MemberByID(*inv.MintedBy)
		if err != nil || minter.Status != "active" || !s.mayMint(minter, inv.Role) {
			return nil, forbidden("invite not valid")
		}
	}
	// Check pen-wide caps only AFTER invite & minter validation so callers
	// without a valid open invite cannot probe pen fullness. Never leak counts
	// or which cap was hit on this public endpoint.
	const redeemFullMsg = "this network cannot accept new members right now"
	if count, err := s.st.CountActiveMembers(); err != nil {
		return nil, err
	} else if count >= s.cfg.MaxMembers {
		return nil, conflict(redeemFullMsg)
	}
	if live, openKeys, err := s.st.CountDeviceSlots(); err != nil {
		return nil, err
	} else if live+openKeys >= s.cfg.MaxDevices {
		return nil, conflict(redeemFullMsg)
	}

	logger := s.loggerOrDefault()
	// Serialize Headscale user creation/rollback across serve and CLI processes
	// so a cap-rollback DeleteUser can never delete a user adopted by a concurrent add.
	if unlock, lockErr := s.st.LockMemberFile(); lockErr == nil {
		defer unlock()
	} else {
		logger.Warn("member advisory lock failed", "err", lockErr)
	}

	m, err := s.createMember(ctx, handle, inv.Role, inv.MintedBy, s.cfg.MaxMembers, nil)
	if err != nil {
		if errors.Is(err, store.ErrMemberCapReached) {
			return nil, conflict(redeemFullMsg)
		}
		return nil, err
	}
	if ok, err := s.st.ClaimInvite(inv.ID, m.ID); err != nil || !ok {
		rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		if herr := s.hs.DeleteUser(rbCtx, m.HSUserID); herr != nil {
			logger.Warn("redeem rollback headscale user failed", "hs_user_id", m.HSUserID, "err", herr)
		}
		rbCancel()
		if derr := s.st.DeleteMember(m.ID); derr != nil {
			logger.Warn("redeem rollback member failed", "member_id", m.ID, "err", derr)
		}
		return nil, forbidden("invite not valid")
	}
	key, exp, err := s.issueKeyCapped(ctx, m, "personal", s.cfg.MaxDevices, 0, 0, false, &store.AuditRecord{
		Actor:  handle,
		Action: "invite.redeem",
		Target: fmt.Sprintf("invite#%d", inv.ID),
	})
	if err != nil {
		// Delete Headscale user BEFORE removing the SQLite member row (while
		// still holding lockMemberFile) so no concurrent CLI member add can
		// adopt m.HSUserID before DeleteUser runs.
		rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		if herr := s.hs.DeleteUser(rbCtx, m.HSUserID); herr != nil {
			logger.Warn("redeem rollback headscale user failed", "hs_user_id", m.HSUserID, "err", herr)
		}
		rbCancel()
		if rerr := s.st.RollbackRedeem(inv.ID, m.ID); rerr != nil {
			logger.Warn("redeem rollback invite/member failed", "invite_id", inv.ID, "member_id", m.ID, "err", rerr)
		}
		if errors.Is(err, store.ErrDeviceCapReached) {
			return nil, conflict(redeemFullMsg)
		}
		return nil, err
	}
	return &Enrolment{
		Handle: handle, Zone: s.cfg.Zone, LoginServer: s.LoginServer(),
		AuthKey: key, AuthKeyExpires: exp,
		Portal: "https://home." + s.cfg.Zone,
	}, nil
}
