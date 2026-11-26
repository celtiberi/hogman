package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// AddMember creates a member directly, without an invite. Used to create the
// owner, and by admins who want to skip the invite step.
func (s *Service) AddMember(ctx context.Context, a Actor, handle, role string) (*Member, error) {
	if !validRoles[role] {
		return nil, bad("role must be owner, admin or member")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return nil, err
	}
	if !a.IsAdmin() {
		return nil, forbidden("only admins can add members directly")
	}
	if role != "member" && !a.IsOwner() {
		return nil, forbidden("only the owner can create admins or owners")
	}
	maxMembers := s.cfg.MaxMembers
	if a.CLI {
		maxMembers = 0 // operator CLI override (D-16)
	}
	if unlock, lockErr := s.st.lockMemberFile(); lockErr == nil {
		defer unlock()
	} else {
		s.loggerOrDefault().Warn("member advisory lock failed", "err", lockErr)
	}
	audit := &AuditRecord{
		Actor:  a.String(),
		Action: "member.add",
		Target: handle,
		Detail: "role=" + role,
	}
	m, err := s.createMember(ctx, handle, role, a.memberID(), maxMembers, audit)
	if err != nil {
		if errors.Is(err, ErrMemberCapReached) {
			return nil, conflict("this network has reached its member limit (%d)", s.cfg.MaxMembers)
		}
		return nil, err
	}
	return m, nil
}

func (s *Service) createMember(ctx context.Context, handle, role string, invitedBy *int64, maxMembers int, audit *AuditRecord) (*Member, error) {
	if !handleRE.MatchString(handle) {
		return nil, bad("handle must be 2-32 lowercase letters, digits or dashes, starting with a letter")
	}
	if _, err := s.st.MemberByHandle(handle); err == nil {
		return nil, conflict("handle %q is taken", handle)
	}
	if maxMembers > 0 {
		count, err := s.st.CountActiveMembers()
		if err != nil {
			return nil, err
		}
		if count >= maxMembers {
			return nil, ErrMemberCapReached
		}
	}
	u, err := s.hs.EnsureUser(ctx, handle)
	if err != nil {
		return nil, err
	}
	m := &Member{Handle: handle, Role: role, Status: "active", InvitedBy: invitedBy, HSUserID: u.ID}
	if err := s.st.InsertMemberCappedAudited(m, maxMembers, audit); err != nil {
		if errors.Is(err, ErrMemberCapReached) {
			rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			if herr := s.hs.DeleteUser(rbCtx, u.ID); herr != nil {
				s.loggerOrDefault().Warn("createMember cap rollback headscale user failed", "hs_user_id", u.ID, "err", herr)
			}
			rbCancel()
		}
		return nil, err
	}
	return m, nil
}

func (s *Service) SetRole(ctx context.Context, a Actor, handle, role string) error {
	if !validRoles[role] {
		return bad("role must be owner, admin or member")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
	if !a.IsOwner() {
		return forbidden("only the owner can change roles")
	}
	m, err := s.member(handle)
	if err != nil {
		return err
	}
	if m.Status == "removed" {
		return conflict("%s has been removed", handle)
	}
	// Invites carry their maker's authority. When that shrinks, the invites
	// they left open go too (Redeem also re-checks the maker's role).
	revokeOpen := roleRank[role] < roleRank[m.Role]
	audit := AuditRecord{
		Actor:  a.String(),
		Action: "member.role",
		Target: handle,
		Detail: m.Role + " -> " + role,
	}
	if m.Role == "owner" && role != "owner" {
		ok, err := s.st.DemoteOwnerAudited(m.ID, role, revokeOpen, audit)
		if err != nil {
			return err
		}
		if !ok {
			return conflict("%s is the only owner", handle)
		}
	} else if err := s.st.SetMemberRoleAudited(m.ID, role, revokeOpen, audit); err != nil {
		return err
	}
	// In renew_only mode, policy depends on owner/admin role membership.
	if s.isRenewOnly() {
		return s.applyPolicy(ctx)
	}
	return nil
}

var roleRank = map[string]int{"member": 0, "admin": 1, "owner": 2}

// mayMint reports whether a member, as they are now, may hand out an invite
// for this role. MintInvite applies the same rules when the invite is made.
func (s *Service) mayMint(m *Member, role string) bool {
	switch role {
	case "admin":
		return m.Role == "owner"
	case "member":
		return m.Role == "owner" || m.Role == "admin" || s.cfg.MembersCanInvite
	}
	return false
}

// canRemove enforces owner-protection and role hierarchy for suspend, resume, and kick.
func canRemove(a Actor, m *Member) error {
	switch {
	case !a.IsAdmin():
		return forbidden("only admins can do that")
	case m.Role == "owner":
		return forbidden("the owner cannot be suspended or removed")
	case m.Role == "admin" && !a.IsOwner():
		return forbidden("only the owner can suspend or remove an admin")
	case a.Is(m):
		return forbidden("you cannot do that to yourself")
	}
	return nil
}

func (s *Service) revokeOpenKeys(ctx context.Context, memberID int64, action string) int {
	logger := s.loggerOrDefault()
	keys, err := s.st.OpenDeviceKeys(memberID)
	if err != nil {
		logger.Warn("list open device keys failed", "action", action, "err", err)
		return 0
	}
	count := 0
	for _, k := range keys {
		if err := s.hs.ExpireKey(ctx, k.HSKeyID); err != nil {
			logger.Warn("expire headscale device key failed", "action", action, "hs_key_id", k.HSKeyID, "err", err)
		}
		if err := s.st.RevokeDeviceKey(k.ID); err != nil {
			logger.Warn("revoke device key failed", "action", action, "key_id", k.ID, "err", err)
			continue
		}
		count++
	}
	return count
}

func (s *Service) Suspend(ctx context.Context, a Actor, handle, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
	m, err := s.member(handle)
	if err != nil {
		return err
	}
	if err := canRemove(a, m); err != nil {
		return err
	}
	if m.Status != "active" {
		return conflict("%s is %s", handle, m.Status)
	}
	if err := s.st.SetMemberStatusAudited(m.ID, "suspended", &AuditRecord{
		Actor:  a.String(),
		Action: "member.suspend",
		Target: handle,
		Detail: reason,
	}); err != nil {
		return err
	}
	s.revokeOpenKeys(ctx, m.ID, "suspend "+handle)
	return s.applyPolicy(ctx) // their devices drop out of every grant
}

func (s *Service) Resume(ctx context.Context, a Actor, handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
	m, err := s.member(handle)
	if err != nil {
		return err
	}
	if err := canRemove(a, m); err != nil {
		return err
	}
	if m.Status != "suspended" {
		return conflict("%s is %s, not suspended", handle, m.Status)
	}
	if err := s.st.SetMemberStatusAudited(m.ID, "active", &AuditRecord{
		Actor:  a.String(),
		Action: "member.resume",
		Target: handle,
	}); err != nil {
		return err
	}
	return s.applyPolicy(ctx)
}

type KickReport struct {
	Devices      int `json:"devices_removed"`
	Keys         int `json:"keys_revoked"`
	Invites      int `json:"invites_revoked"`
	NamesRetired int `json:"names_retired"`
}

// Kick ends a membership. Order matters: mark removed and drop from policy
// first (instant cut-off), then delete their devices from the mesh.
func (s *Service) Kick(ctx context.Context, a Actor, handle, reason string) (*KickReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return nil, err
	}
	m, err := s.member(handle)
	if err != nil {
		return nil, err
	}
	if err := canRemove(a, m); err != nil {
		return nil, err
	}
	if m.Status == "removed" {
		return nil, conflict("%s has already been removed", handle)
	}
	logger := s.loggerOrDefault()
	rep := &KickReport{}

	// 1. From now on the registrar refuses them everything.
	if err := s.st.SetMemberStatus(m.ID, "removed"); err != nil {
		return nil, err
	}
	// 2. Cut them out of the access policy straight away.
	if err := s.applyPolicy(ctx); err != nil {
		logger.Warn("kick policy push failed", "handle", handle, "err", err)
	}
	// 3. Unused device keys and invites they minted.
	rep.Keys = s.revokeOpenKeys(ctx, m.ID, "kick "+handle)
	n, err := s.st.RevokeOpenInvitesBy(m.ID)
	if err != nil {
		logger.Warn("kick revoke invites failed", "handle", handle, "err", err)
	}
	rep.Invites = int(n)
	// 4. Delete every device they own, personal and server.
	devs, err := s.st.MemberDevices(m.ID)
	if err != nil {
		logger.Warn("kick list devices failed", "handle", handle, "err", err)
	}
	for _, d := range devs {
		if err := s.hs.DeleteNode(ctx, d.HSNodeID); err != nil {
			logger.Warn("kick delete node failed (sync will retry)", "handle", handle, "hs_node_id", d.HSNodeID, "err", err)
			continue
		}
		if err := s.st.MarkDeviceRemoved(d.ID); err != nil {
			logger.Warn("kick mark device removed failed", "handle", handle, "device_id", d.ID, "err", err)
			continue
		}
		rep.Devices++
	}
	// 5. Their Headscale user. Fails harmlessly if a device deletion failed; sync retries the devices.
	if m.HSUserID != "" {
		if err := s.hs.DeleteUser(ctx, m.HSUserID); err == nil || isHSNotFound(err) {
			if err := s.st.ClearMemberHSUserID(m.ID); err != nil {
				logger.Warn("kick clear headscale user id failed", "handle", handle, "err", err)
			}
		} else {
			logger.Warn("kick delete headscale user failed", "handle", handle, "err", err)
		}
	}
	// 6. Withdraw their names and retire them permanently so nobody can impersonate their sites.
	retired, err := s.st.RetireNames(m.ID)
	if err != nil {
		logger.Warn("kick retire names failed", "handle", handle, "err", err)
	}
	rep.NamesRetired = int(retired)
	// 7. Audit.
	detail, _ := json.Marshal(rep)
	if reason != "" {
		detail = append(detail, []byte(" reason: "+reason)...)
	}
	s.st.Audit(a.String(), "member.kick", handle, string(detail))
	return rep, nil
}
