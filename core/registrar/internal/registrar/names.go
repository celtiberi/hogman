package registrar

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode"

	"hogman/registrar/internal/store"
)

const maxNameNoteRunes = 140

// cleanNameNote turns a site description into a single plain-text line capped at
// 140 runes, replacing line/tab breaks with spaces and dropping control,
// invisible filler, and Unicode format characters (including bidi overrides)
// while preserving ZWJ/ZWNJ for normal emoji and script shaping.
func cleanNameNote(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r == '\r' || r == '\n' || r == '\t' || r == '\u2028' || r == '\u2029':
			b.WriteByte(' ')
		case r == '\u200c' || r == '\u200d':
			b.WriteRune(r)
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u034f' || r == '\u2800' || r == '\u3164' || r == '\uffa0':
			continue
		default:
			b.WriteRune(r)
		}
	}
	collapsed := strings.Join(strings.Fields(b.String()), " ")
	runes := []rune(collapsed)
	if len(runes) > maxNameNoteRunes {
		return strings.TrimRight(string(runes[:maxNameNoteRunes]), " ")
	}
	return collapsed
}

const (
	privateLabelLen         = 12
	maxPrivateLabelAttempts = 8
	privateLabelFirstChars  = "abcdefghijklmnopqrstuvwxyz"
	privateLabelRestChars   = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// generatePrivateLabel returns a 12-character random DNS label starting with a
// lowercase letter followed by 11 lowercase letters or digits (~61.6 bits).
func generatePrivateLabel() (string, error) {
	var b strings.Builder
	b.Grow(privateLabelLen)
	firstMax := big.NewInt(int64(len(privateLabelFirstChars)))
	restMax := big.NewInt(int64(len(privateLabelRestChars)))
	n, err := rand.Int(rand.Reader, firstMax)
	if err != nil {
		return "", fmt.Errorf("generate private label: %w", err)
	}
	b.WriteByte(privateLabelFirstChars[n.Int64()])
	for i := 1; i < privateLabelLen; i++ {
		n, err := rand.Int(rand.Reader, restMax)
		if err != nil {
			return "", fmt.Errorf("generate private label: %w", err)
		}
		b.WriteByte(privateLabelRestChars[n.Int64()])
	}
	return b.String(), nil
}

// allocatePrivateLabelLocked (s.mu held) picks a random label not present in
// names (active or retired) and not reserved. Fails cleanly after 8 collisions.
func (s *Service) allocatePrivateLabelLocked() (string, error) {
	gen := s.privateLabelFn
	if gen == nil {
		gen = generatePrivateLabel
	}
	all, err := s.st.Names()
	if err != nil {
		return "", err
	}
	used := make(map[string]struct{}, len(all))
	for _, x := range all {
		used[x.Name] = struct{}{}
		used[topLabel(x.Name)] = struct{}{}
	}
	for attempt := 0; attempt < maxPrivateLabelAttempts; attempt++ {
		cand, err := gen()
		if err != nil {
			return "", err
		}
		name, err := s.normaliseName(cand)
		if err != nil || topLabel(name) != name {
			continue
		}
		if _, exists := used[name]; exists {
			continue
		}
		return name, nil
	}
	return "", unavailable("could not allocate a unique private name after %d attempts", maxPrivateLabelAttempts)
}

func (s *Service) Claim(a Actor, handle, rawName string, deviceID int64, note *string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.claimLocked(a, handle, rawName, deviceID, note, nil, false)
}

// ClaimPrivate allocates a random private label for a server device owned by handle.
func (s *Service) ClaimPrivate(a Actor, handle string, deviceID int64, note *string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.claimLocked(a, handle, "", deviceID, note, nil, true)
}

// ServerClaim is a server naming itself (what `hogman share` does). The
// checks run under s.mu together with the claim, so two servers can't race.
func (s *Service) ServerClaim(a Actor, d *store.Device, rawName string, note *string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.serverMayUse(d, rawName); err != nil {
		return "", err
	}
	return s.claimLocked(a, a.Member.Handle, rawName, d.ID, note, d, false)
}

// ServerClaimPrivate allocates a random private label for the calling server
// device. If this exact server device already owns a single active private name
// (e.g. crash right after claiming before writing share.json), returns that
// existing private name and updates its note if provided. Refuses if the server
// already owns a non-private name or multiple names.
func (s *Service) ServerClaimPrivate(a Actor, d *store.Device, note *string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return "", err
	}
	if d == nil || d.Kind != "server" {
		return "", forbidden("server devices only")
	}
	all, err := s.st.Names()
	if err != nil {
		return "", err
	}
	var owned []*store.Name
	for _, n := range all {
		if n.RetiredAt == nil && n.MemberID == d.MemberID && n.DeviceID != nil && *n.DeviceID == d.ID {
			owned = append(owned, n)
		}
	}
	if len(owned) == 1 && owned[0].Private {
		return s.claimLocked(a, a.Member.Handle, owned[0].Name, d.ID, note, d, false)
	}
	if len(owned) > 0 {
		return "", conflict("this server already has a claimed name; pass its existing name")
	}
	return s.claimLocked(a, a.Member.Handle, "", d.ID, note, d, true)
}

// claimLocked: s.mu held. server is the calling server device, or nil.
// When allocatePrivate is true, rawName must be empty and a fresh 12-char
// random label is allocated under s.mu and stored with private=1.
func (s *Service) claimLocked(a Actor, handle, rawName string, deviceID int64, rawNote *string, server *store.Device, allocatePrivate bool) (string, error) {
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return "", err
	}
	m, err := s.member(handle)
	if err != nil {
		return "", err
	}
	if err := requireSelfOrManageable(a, m,
		"you can only claim names for yourself",
		"only the owner can claim names for an owner or admin",
	); err != nil {
		return "", err
	}
	if m.Status != "active" {
		return "", conflict("%s is %s", handle, m.Status)
	}
	if allocatePrivate && strings.TrimSpace(rawName) != "" {
		return "", bad("cannot pass both a name and private: true")
	}

	var name string
	var existing *store.Name
	var d *store.Device
	if allocatePrivate {
		// Validate device and cap before allocating a random label.
		d, err = s.st.DeviceByID(deviceID)
		if err != nil || d.RemovedAt != nil || d.MemberID != m.ID {
			return "", bad("device %d is not one of %s's devices", deviceID, handle)
		}
		if d.Kind != "server" {
			return "", bad("device %d is a personal device; names point at servers (personal devices accept no connections)", deviceID)
		}
		if !a.IsOwner() || server != nil {
			count, err := s.st.CountMemberNames(m.ID)
			if err != nil {
				return "", err
			}
			if count >= s.cfg.MaxNamesPerMember {
				return "", conflict("too many names claimed")
			}
		}
		name, err = s.allocatePrivateLabelLocked()
		if err != nil {
			return "", err
		}
	} else {
		name, err = s.normaliseName(rawName)
		if err != nil {
			return "", err
		}
		existing, err = s.st.NameByName(name)
		switch {
		case errors.Is(err, ErrNotFound):
			existing = nil
		case err != nil:
			return "", err
		case existing.RetiredAt != nil:
			return "", conflict("%s is retired and cannot be reused", name)
		case existing.MemberID != m.ID && !a.IsOwner():
			return "", conflict("%s belongs to %s", name, existing.Member)
		}
		// If claiming an unclaimed top-level name, refuse if another member (or a
		// retired record) already owns a subdomain under it.
		if existing == nil && topLabel(name) == name {
			all, err := s.st.Names()
			if err != nil {
				return "", err
			}
			for _, x := range all {
				if !strings.HasSuffix(x.Name, "."+name) {
					continue
				}
				if x.RetiredAt != nil {
					return "", conflict("%s has retired subdomains and cannot be reused", name)
				}
				if x.MemberID != m.ID && !a.IsOwner() {
					return "", conflict("%s has subdomains belonging to %s", name, x.Member)
				}
			}
		}
		// A server always counts against the cap, even the owner's: a leaked server
		// link must not be able to claim names without limit.
		if (!a.IsOwner() || server != nil) && (existing == nil || existing.MemberID != m.ID) {
			count, err := s.st.CountMemberNames(m.ID)
			if err != nil {
				return "", err
			}
			if count >= s.cfg.MaxNamesPerMember {
				return "", conflict("too many names claimed")
			}
		}
		if top := topLabel(name); top != name {
			parent, err := s.st.NameByName(top)
			if err == nil && parent.RetiredAt != nil {
				return "", conflict("%s is retired and cannot be reused", top)
			}
			if err != nil || parent.MemberID != m.ID {
				return "", forbidden("claim %s first; names under it belong to whoever owns it", top)
			}
		}
		d, err = s.st.DeviceByID(deviceID)
		if err != nil || d.RemovedAt != nil || d.MemberID != m.ID {
			return "", bad("device %d is not one of %s's devices", deviceID, handle)
		}
		if d.Kind != "server" {
			return "", bad("device %d is a personal device; names point at servers (personal devices accept no connections)", deviceID)
		}
		if existing != nil && existing.MemberID != m.ID && topLabel(name) == name {
			all, err := s.st.Names()
			if err != nil {
				return "", err
			}
			for _, x := range all {
				if strings.HasSuffix(x.Name, "."+name) && x.MemberID != m.ID && x.RetiredAt == nil {
					if err := s.st.DeleteName(x.Name); err != nil {
						return "", err
					}
				}
			}
		}
	}
	note := ""
	if rawNote != nil {
		note = cleanNameNote(*rawNote)
	} else if existing != nil && existing.RetiredAt == nil && existing.MemberID == m.ID {
		note = existing.Note
	}
	isPrivate := allocatePrivate || (existing != nil && existing.Private)
	detail := fmt.Sprintf("member=%s device=%d", handle, d.ID)
	if isPrivate {
		detail += " private=true"
	}
	fqdn := name + "." + s.cfg.Zone
	if err := s.st.UpsertNameWithPrivateAudited(name, m.ID, &d.ID, note, isPrivate, &store.AuditRecord{
		Actor:  a.String(),
		Action: "name.claim",
		Target: fqdn,
		Detail: detail,
	}); err != nil {
		return "", err
	}
	return fqdn, nil
}

// serverMayUse (s.mu held): a server naming itself may take a name that is
// free or already points at it, never a retired name or one of its member's
// other names; and a name under another (x.blog) only if the parent points at
// it too, so one server can't squat under another's name.
func (s *Service) serverMayUse(d *store.Device, rawName string) error {
	name, err := s.normaliseName(rawName)
	if err != nil {
		return err
	}
	pointsHere := func(n *store.Name) bool {
		return n.MemberID == d.MemberID && n.RetiredAt == nil && n.DeviceID != nil && *n.DeviceID == d.ID
	}
	n, err := s.st.NameByName(name)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return err
	case n.RetiredAt != nil:
		return conflict("%s is retired and cannot be reused", name)
	case !pointsHere(n):
		return conflict("%s is already taken; pick another name", name)
	}
	if top := topLabel(name); top != name {
		p, err := s.st.NameByName(top)
		if err == nil && p.RetiredAt != nil {
			return conflict("%s is retired and cannot be reused", top)
		}
		if err != nil || !pointsHere(p) {
			return forbidden("%s belongs under %s, which doesn't point at this server", name, top)
		}
	}
	return nil
}

// serverOwnsName (s.mu held): a server may release a name only if it, and
// every name under it, points at that server.
func (s *Service) serverOwnsName(d *store.Device, rawName string) error {
	name, err := s.normaliseName(rawName)
	if err != nil {
		return err
	}
	all, err := s.st.Names()
	if err != nil {
		return err
	}
	found := false
	for _, x := range all {
		if x.Name != name && !strings.HasSuffix(x.Name, "."+name) {
			continue
		}
		if x.MemberID != d.MemberID || x.RetiredAt != nil || x.DeviceID == nil || *x.DeviceID != d.ID {
			return forbidden("%s does not point at this server", x.Name)
		}
		found = found || x.Name == name
	}
	if !found {
		return missing("%s is not claimed", name)
	}
	return nil
}

// Release frees a name and everything under it.
func (s *Service) Release(a Actor, rawName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.releaseLocked(a, rawName)
}

// ServerRelease is a server giving back a name that points only at it.
func (s *Service) ServerRelease(a Actor, d *store.Device, rawName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.serverOwnsName(d, rawName); err != nil {
		return err
	}
	return s.releaseLocked(a, rawName)
}

func (s *Service) releaseLocked(a Actor, rawName string) error {
	var err error
	if a, err = s.refreshActorLocked(a); err != nil {
		return err
	}
	name := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rawName)), "."), "."+s.cfg.Zone)
	n, err := s.st.NameByName(name)
	if errors.Is(err, ErrNotFound) {
		return missing("%s is not claimed", name)
	} else if err != nil {
		return err
	}
	if n.RetiredAt != nil {
		return conflict("%s is retired and cannot be released", name)
	}
	canReleaseRow := func(row *store.Name) error {
		if a.IsOwner() {
			return nil
		}
		owner, err := s.st.MemberByID(row.MemberID)
		if err != nil {
			return err
		}
		switch {
		case a.Member != nil && a.Member.ID == row.MemberID:
			return nil
		case a.IsAdmin() && owner.Role == "member":
			return nil
		case a.IsAdmin():
			return forbidden("only the owner can release names belonging to an owner or admin")
		default:
			return forbidden("%s is not yours", row.Name)
		}
	}
	if err := canReleaseRow(n); err != nil {
		return err
	}
	all, err := s.st.Names()
	if err != nil {
		return err
	}
	var toRelease []*store.Name
	for _, x := range all {
		if x.RetiredAt != nil {
			continue
		}
		if x.Name == name || strings.HasSuffix(x.Name, "."+name) {
			if err := canReleaseRow(x); err != nil {
				return err
			}
			toRelease = append(toRelease, x)
		}
	}
	return s.st.ReleaseNamesAudited(toRelease, &store.AuditRecord{
		Actor:  a.String(),
		Action: "name.release",
		Target: name + "." + s.cfg.Zone,
	})
}
