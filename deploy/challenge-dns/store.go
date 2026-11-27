package main

// The rules, kept apart from DNS and HTTP so they are easy to test:
// credentials and what each may write (scope), the hourly/weekly caps on new
// names, and the challenge records themselves (in memory only).

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	txtTTL                     = 10 * time.Minute // a challenge record lives this long unless refreshed
	maxLivePer                 = 2                // live values per name (ACME may ask for two at once)
	hourlyWindow               = time.Hour
	capWindow                  = 7 * 24 * time.Hour
	defaultHourlyCap           = 5   // distinct new names per personal pen per rolling hour (CDNS_HOURLY_CAP)
	defaultCapNames            = 20  // distinct new names per personal pen per 7 days (CDNS_WEEKLY_CAP)
	defaultWorkHourlyCap       = 40  // distinct new names per work pen per rolling hour (CDNS_WORK_HOURLY_CAP)
	defaultWorkWeeklyCap       = 120 // distinct new names per work pen per 7 days (CDNS_WORK_WEEKLY_CAP)
	defaultGlobalHourlyCap     = 80  // soft global hourly cap across all pens (CDNS_GLOBAL_HOURLY_CAP)
	defaultGlobalHardHourlyCap = 120 // hard global hourly ceiling with reserved quiet-pen floor (CDNS_GLOBAL_HARD_HOURLY_CAP)
	defaultLEWeeklyAllowance   = 300 // Let's Encrypt 7-day registered-domain allowance for alerting (CDNS_LE_WEEKLY_ALLOWANCE)
	weeklyAlertPct             = 80  // alert threshold percentage of LE weekly allowance (240 of 300)
	weeklyAlertCooldown        = 24 * time.Hour
	quietPenHourlyFloor        = 2 // pens with <2 new names in the last hour may use soft..hard headroom
	planPersonal               = "personal"
	planWork                   = "work"
	acmePrefix                 = "_acme-challenge."
	maxSiteDepth               = 4 // labels before the pen name, as site names allow
)

func normalizePlan(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", planPersonal:
		return "", nil
	case planWork:
		return planWork, nil
	default:
		return "", fmt.Errorf("unknown plan %q (want personal or work): %w", raw, errInvalidInput)
	}
}

var (
	penRE              = regexp.MustCompile(`^[a-z][a-z0-9-]{1,28}[a-z0-9]$`)
	labelRE            = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	valueRE            = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	errScope           = errors.New("not allowed for this credential")
	errCap             = errors.New("this pen's weekly limit on new certificate names is reached")
	errHourlyCap       = errors.New("too many new certificate names for this pen in the last hour")
	errGlobalHourlyCap = errors.New("the network is busy; too many new certificate names in the last hour")
	errEABHourlyCap    = errors.New("too many fallback account keys for this credential in the last hour")
	errEABWeeklyCap    = errors.New("this credential's weekly allowance of fallback account keys is used")
	errFull            = errors.New("too many live challenge values for this name")
	errValue           = errors.New("challenge value must be 16-128 characters of A-Z a-z 0-9 _ -")
	errRevoked         = errors.New("credential revoked")
	errNotFound        = errors.New("not found")
	errInvalidInput    = errors.New("invalid input")
)

// rateLimitError pairs a rate-limit sentinel with a Retry-After duration.
type rateLimitError struct {
	cause      error
	retryAfter time.Duration
}

func (e *rateLimitError) Error() string { return e.cause.Error() }
func (e *rateLimitError) Unwrap() error { return e.cause }

func retryAfterFromOldest(oldest, now time.Time, window time.Duration) time.Duration {
	if oldest.IsZero() {
		return time.Minute
	}
	rem := oldest.Add(window).Sub(now)
	if rem < time.Second {
		return time.Second
	}
	return ((rem + time.Second - 1) / time.Second) * time.Second
}

// Cred is one API credential. Kind is "pen" (scoped to PenID) or "host"
// (only the front door's wildcard challenge). Only the token's hash is kept.
// Plan is "" (personal) or "work" (higher per-pen certificate caps).
type Cred struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	PenID          string    `json:"pen_id,omitempty"`
	Plan           string    `json:"plan,omitempty"`
	Hash           string    `json:"hash"`
	Created        time.Time `json:"created"`
	EverChallenged bool      `json:"ever_challenged,omitempty"`
}

// state is what survives a restart, and deliberately little of it:
//   - credentials, as token hashes only;
//   - for the hourly and weekly caps, which names each pen wrote in the last
//     7 days (pruned as the window moves);
//   - recent fallback-key mints in the last 7 days;
//   - the names of pens that ever had a credential, so a deleted pen's name
//     is never given out again. Just the name: it's public in the certificate
//     logs anyway.
//
// Challenge values are never written to disk.
type state struct {
	Creds           []Cred                          `json:"creds"`
	Seen            map[string]map[string]time.Time `json:"seen"`                        // cred ID -> fqdn -> first write in window
	EAB             map[string][]time.Time          `json:"eab"`                         // cred ID -> recent EAB mints
	Used            []string                        `json:"used"`                        // pen names ever credentialed, kept after removal
	LastWeeklyAlert time.Time                       `json:"last_weekly_alert,omitempty"` // last 80% global 7-day LE-budget alert
}

func cloneState(st state) state {
	out := state{
		Creds:           append([]Cred(nil), st.Creds...),
		Seen:            make(map[string]map[string]time.Time, len(st.Seen)),
		EAB:             make(map[string][]time.Time, len(st.EAB)),
		Used:            append([]string(nil), st.Used...),
		LastWeeklyAlert: st.LastWeeklyAlert,
	}
	for id, names := range st.Seen {
		cp := make(map[string]time.Time, len(names))
		for k, v := range names {
			cp[k] = v
		}
		out.Seen[id] = cp
	}
	for id, times := range st.EAB {
		out.EAB[id] = append([]time.Time(nil), times...)
	}
	return out
}

type txtValue struct {
	value   string
	expires time.Time
}

// Store holds the state (persisted) and the live challenge records (not).
type Store struct {
	mu            sync.Mutex
	path          string
	zones         Zones
	st            state
	txt           map[string][]txtValue // fqdn -> live values
	inFlightEAB   map[string]int        // cred ID -> in-flight upstream EAB mints
	now           func() time.Time
	caps          CapsConfig
	onWeeklyAlert func(used, allowance, threshold int) // invoked outside s.mu when 7-day global usage >= 80% of LE allowance
}

// Zones are the names this server answers for.
type Zones struct {
	Pens string // e.g. pens.hogman.network
	Gate string // e.g. _acme-challenge.gate.hogman.network
}

func (z Zones) gateTXT() string { return z.Gate }

func OpenStore(path string, z Zones) (*Store, error) {
	s := &Store{
		path:        path,
		zones:       z,
		txt:         map[string][]txtValue{},
		inFlightEAB: map[string]int{},
		now:         time.Now,
		st:          state{Seen: map[string]map[string]time.Time{}, EAB: map[string][]time.Time{}},
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.saveLocked()
	} else if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.st); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.st.Seen == nil {
		s.st.Seen = map[string]map[string]time.Time{}
	}
	if s.st.EAB == nil {
		s.st.EAB = map[string][]time.Time{}
	}
	return s, nil
}

// writeFileAtomic writes data to path via a same-directory temp file, fsyncing
// both the file and its parent directory so readers never observe partial state.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// saveLocked writes the state atomically, readable only by this process.
func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, b, 0o600)
}

// mutateLocked snapshots persisted state, executes fn, and atomically writes
// the updated state to disk. Any error from fn or saveLocked rolls back s.st
// to the pre-mutation snapshot so memory and disk never diverge.
func (s *Store) mutateLocked(fn func() error) error {
	prev := cloneState(s.st)
	if err := fn(); err != nil {
		s.st = prev
		return err
	}
	if err := s.saveLocked(); err != nil {
		s.st = prev
		return err
	}
	return nil
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func newSecret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// AddCred makes a credential with the default (personal) plan and returns its
// token, which is shown once.
func (s *Store) AddCred(kind, penID string) (Cred, string, error) {
	return s.AddCredWithPlan(kind, penID, "")
}

// AddCredWithPlan makes a credential with an optional plan ("personal" or "work"
// for pen credentials) and returns its token, which is shown once.
func (s *Store) AddCredWithPlan(kind, penID, rawPlan string) (Cred, string, error) {
	plan, err := normalizePlan(rawPlan)
	if err != nil {
		return Cred{}, "", err
	}
	switch kind {
	case "pen":
		if !penRE.MatchString(penID) {
			return Cred{}, "", fmt.Errorf("pen name must be 3-30 lowercase letters, digits and dashes, starting with a letter: %w", errInvalidInput)
		}
	case "host":
		if plan != "" {
			return Cred{}, "", fmt.Errorf("host credentials do not take a plan: %w", errInvalidInput)
		}
		penID = ""
	default:
		return Cred{}, "", fmt.Errorf("kind must be pen or host: %w", errInvalidInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.st.Creds {
		if kind == "pen" && c.Kind == "pen" && c.PenID == penID {
			return Cred{}, "", fmt.Errorf("pen %s already has a credential (%s): %w", penID, c.ID, errInvalidInput)
		}
	}
	if kind == "pen" && s.usedLocked(penID) {
		return Cred{}, "", fmt.Errorf("the pen name %s was used before and is never given out again: %w", penID, errInvalidInput)
	}
	tok := "hcd_" + newSecret(32)
	c := Cred{ID: newSecret(6), Kind: kind, PenID: penID, Plan: plan, Hash: hashToken(tok), Created: s.now().UTC()}
	if err := s.mutateLocked(func() error {
		s.st.Creds = append(s.st.Creds, c)
		if kind == "pen" {
			s.st.Used = append(s.st.Used, penID) // marked the moment it's taken, not only on removal
		}
		return nil
	}); err != nil {
		return Cred{}, "", err
	}
	return c, tok, nil
}

// SetCredPlan updates the plan ("personal" or "work") of an existing pen
// credential (matched by credential ID or pen name) and persists it.
func (s *Store) SetCredPlan(idOrPen, rawPlan string) (Cred, error) {
	plan, err := normalizePlan(rawPlan)
	if err != nil {
		return Cred{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i := range s.st.Creds {
		c := &s.st.Creds[i]
		if c.ID == idOrPen || (c.Kind == "pen" && c.PenID == idOrPen) {
			if c.Kind != "pen" {
				return Cred{}, fmt.Errorf("credential %q is not a pen credential: %w", idOrPen, errInvalidInput)
			}
			idx = i
			break
		}
	}
	if idx < 0 {
		return Cred{}, fmt.Errorf("no pen credential %q: %w", idOrPen, errNotFound)
	}
	var updated Cred
	if err := s.mutateLocked(func() error {
		s.st.Creds[idx].Plan = plan
		updated = s.st.Creds[idx]
		return nil
	}); err != nil {
		return Cred{}, err
	}
	return updated, nil
}

func (s *Store) usedLocked(name string) bool {
	for _, n := range s.st.Used {
		if n == name {
			return true
		}
	}
	return false
}

// NameUsed reports whether a pen name was ever given out (sign-up checks this).
func (s *Store) NameUsed(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usedLocked(normalize(name))
}

// RemoveCred revokes a credential while keeping its pen name permanently
// retired.
func (s *Store) RemoveCred(id string) error {
	_, err := s.RemoveCredWithOptions(id, false)
	return err
}

// RemoveCredWithOptions revokes a credential. When releaseIfUnused is true
// (used only by failed-provision rollback) and the pen credential never wrote
// an ACME TXT challenge or minted a fallback EAB key, its pen name is released
// from Used so a host-side provisioning failure does not burn the buyer's
// chosen name. Once any challenge or EAB mint occurred, the name stays retired
// forever.
func (s *Store) RemoveCredWithOptions(id string, releaseIfUnused bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	var target Cred
	for i, c := range s.st.Creds {
		if c.ID == id {
			idx, target = i, c
			break
		}
	}
	if idx < 0 {
		return false, fmt.Errorf("no credential %q: %w", id, errNotFound)
	}
	canRelease := releaseIfUnused && target.Kind == "pen" && !target.EverChallenged &&
		len(s.st.Seen[id]) == 0 && len(s.st.EAB[id]) == 0 && s.inFlightEAB[id] == 0
	if err := s.mutateLocked(func() error {
		s.st.Creds = append(s.st.Creds[:idx], s.st.Creds[idx+1:]...)
		delete(s.st.Seen, id)
		delete(s.st.EAB, id)
		if canRelease {
			kept := make([]string, 0, len(s.st.Used))
			for _, n := range s.st.Used {
				if n != target.PenID {
					kept = append(kept, n)
				}
			}
			s.st.Used = kept
		}
		return nil
	}); err != nil {
		return false, err
	}
	// Immediately purge any live challenge TXT records in scope of the revoked credential.
	for fqdn := range s.txt {
		if s.InScope(target, fqdn) {
			delete(s.txt, fqdn)
		}
	}
	return canRelease, nil
}

func (s *Store) credLocked(id string) (Cred, bool) {
	for _, c := range s.st.Creds {
		if c.ID == id {
			return c, true
		}
	}
	return Cred{}, false
}

func (s *Store) markChallengedLocked(id string) {
	for i := range s.st.Creds {
		if s.st.Creds[i].ID == id {
			s.st.Creds[i].EverChallenged = true
			return
		}
	}
}

func (s *Store) Creds() []Cred {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Cred(nil), s.st.Creds...)
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// Auth finds the credential for a bearer token, comparing hashes in constant time.
func (s *Store) Auth(tok string) (Cred, bool) {
	if tok == "" {
		return Cred{}, false
	}
	h := hashToken(tok)
	s.mu.Lock()
	defer s.mu.Unlock()
	var found Cred
	ok := false
	for _, c := range s.st.Creds {
		if subtle.ConstantTimeCompare([]byte(c.Hash), []byte(h)) == 1 {
			found, ok = c, true
		}
	}
	return found, ok
}

// normalize lowercases a name and drops a trailing dot.
func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// InScope reports whether a credential may write this challenge name.
//
//	pen <id>:  _acme-challenge.<1..4 labels>.<id>.<pens zone>
//	host:      exactly the gate challenge name (the front door's wildcard)
func (s *Store) InScope(c Cred, fqdn string) bool {
	fqdn = normalize(fqdn)
	switch c.Kind {
	case "host":
		return fqdn == s.zones.gateTXT()
	case "pen":
		suffix := "." + c.PenID + "." + s.zones.Pens
		rest, ok := strings.CutPrefix(fqdn, acmePrefix)
		if !ok {
			return false
		}
		site, ok := strings.CutSuffix(rest, suffix)
		if !ok || site == "" {
			return false
		}
		labels := strings.Split(site, ".")
		if len(labels) > maxSiteDepth {
			return false
		}
		for _, l := range labels {
			if !labelRE.MatchString(l) {
				return false
			}
		}
		return true
	}
	return false
}

// PutTXT adds or refreshes a challenge value. Idempotent for a live value.
func (s *Store) PutTXT(c Cred, fqdn, value string) error {
	fqdn = normalize(fqdn)
	if !s.InScope(c, fqdn) {
		return errScope
	}
	if !valueRE.MatchString(value) {
		return errValue
	}
	s.mu.Lock()
	liveCred, ok := s.credLocked(c.ID)
	if !ok {
		s.mu.Unlock()
		return errRevoked
	}
	c = liveCred
	now := s.now()
	live := s.liveLocked(fqdn, now)
	for i := range live {
		if live[i].value == value {
			live[i].expires = now.Add(txtTTL)
			s.txt[fqdn] = live
			s.mu.Unlock()
			return nil
		}
	}
	if len(live) >= maxLivePer {
		s.mu.Unlock()
		return errFull
	}
	var alertNeeded bool
	var alertUsed, alertAllowance, alertThreshold int
	var alertFn func(used, allowance, threshold int)
	if c.Kind == "pen" {
		var err error
		alertNeeded, alertUsed, err = s.countLocked(c, fqdn, now)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		if alertNeeded {
			alertAllowance = s.caps.LEWeekly()
			alertThreshold = s.caps.WeeklyAlertThreshold()
			alertFn = s.onWeeklyAlert
		}
	}
	s.txt[fqdn] = append(live, txtValue{value: value, expires: now.Add(txtTTL)})
	s.mu.Unlock()
	if alertNeeded && alertFn != nil {
		alertFn(alertUsed, alertAllowance, alertThreshold)
	}
	return nil
}

// countLocked applies the per-pen weekly cap, per-pen hourly burst cap, and
// global hourly cap across all pens, and checks whether total 7-day usage
// across all pens crossed the 80% Let's Encrypt allowance alert threshold.
// A name already counted in this pen's 7-day window (retries and renewals) is
// free; a new name counts on first TXT write (attempts count, not issued certs).
func (s *Store) countLocked(c Cred, fqdn string, now time.Time) (alertNeeded bool, globalWeekly int, err error) {
	// Prune expired 7-day entries across all credentials so global counts stay accurate.
	globalHourly := 0
	var oldestGlobalHourly time.Time
	for id, m := range s.st.Seen {
		for n, t := range m {
			if now.Sub(t) >= capWindow {
				delete(m, n)
				continue
			}
			globalWeekly++
			if now.Sub(t) < hourlyWindow {
				globalHourly++
				if oldestGlobalHourly.IsZero() || t.Before(oldestGlobalHourly) {
					oldestGlobalHourly = t
				}
			}
		}
		if len(m) == 0 && id != c.ID {
			delete(s.st.Seen, id)
		}
	}

	seen := s.st.Seen[c.ID]
	if seen == nil {
		seen = map[string]time.Time{}
	}
	_, alreadySeen := seen[fqdn]
	if !alreadySeen {
		penHourly := 0
		var oldestWeekly, oldestHourly time.Time
		for _, t := range seen {
			if oldestWeekly.IsZero() || t.Before(oldestWeekly) {
				oldestWeekly = t
			}
			if now.Sub(t) < hourlyWindow {
				penHourly++
				if oldestHourly.IsZero() || t.Before(oldestHourly) {
					oldestHourly = t
				}
			}
		}
		if len(seen) >= s.caps.WeeklyFor(c) {
			s.st.Seen[c.ID] = seen
			return false, globalWeekly, &rateLimitError{cause: errCap, retryAfter: retryAfterFromOldest(oldestWeekly, now, capWindow)}
		}
		if penHourly >= s.caps.HourlyFor(c) {
			s.st.Seen[c.ID] = seen
			return false, globalWeekly, &rateLimitError{cause: errHourlyCap, retryAfter: retryAfterFromOldest(oldestHourly, now, hourlyWindow)}
		}
		if globalHourly >= s.caps.GlobalHardHourly() {
			s.st.Seen[c.ID] = seen
			return false, globalWeekly, &rateLimitError{cause: errGlobalHourlyCap, retryAfter: retryAfterFromOldest(oldestGlobalHourly, now, hourlyWindow)}
		}
		if globalHourly >= s.caps.GlobalHourly() && penHourly >= quietPenHourlyFloor {
			s.st.Seen[c.ID] = seen
			return false, globalWeekly, &rateLimitError{cause: errGlobalHourlyCap, retryAfter: retryAfterFromOldest(oldestGlobalHourly, now, hourlyWindow)}
		}
		globalWeekly++
	}
	shouldAlert := globalWeekly >= s.caps.WeeklyAlertThreshold() &&
		(s.st.LastWeeklyAlert.IsZero() || now.Sub(s.st.LastWeeklyAlert) >= weeklyAlertCooldown)
	if alreadySeen && c.EverChallenged && !shouldAlert {
		return false, globalWeekly, nil
	}
	if err := s.mutateLocked(func() error {
		if s.st.Seen[c.ID] == nil {
			s.st.Seen[c.ID] = seen
		}
		if !alreadySeen {
			s.st.Seen[c.ID][fqdn] = now
		}
		if shouldAlert {
			s.st.LastWeeklyAlert = now
		}
		s.markChallengedLocked(c.ID)
		return nil
	}); err != nil {
		return false, globalWeekly, err
	}
	return shouldAlert, globalWeekly, nil
}

// DeleteTXT removes a value if present. Absent or expired is still success.
func (s *Store) DeleteTXT(c Cred, fqdn, value string) error {
	fqdn = normalize(fqdn)
	if !s.InScope(c, fqdn) {
		return errScope
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.credLocked(c.ID); !ok {
		return errRevoked
	}
	live := s.liveLocked(fqdn, s.now())
	out := live[:0]
	for _, v := range live {
		if v.value != value {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		delete(s.txt, fqdn)
	} else {
		s.txt[fqdn] = out
	}
	return nil
}

// TXT returns the live values for a name (for DNS answers).
func (s *Store) TXT(fqdn string) []string {
	fqdn = normalize(fqdn)
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.liveLocked(fqdn, s.now())
	vals := make([]string, 0, len(live))
	for _, v := range live {
		vals = append(vals, v.value)
	}
	return vals
}

func (s *Store) liveLocked(fqdn string, now time.Time) []txtValue {
	vals := s.txt[fqdn]
	out := vals[:0]
	for _, v := range vals {
		if now.Before(v.expires) {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		delete(s.txt, fqdn)
		return nil
	}
	s.txt[fqdn] = out
	return out
}

func (s *Store) checkEABLocked(id string, now time.Time) (Cred, []time.Time, error) {
	liveCred, ok := s.credLocked(id)
	if !ok {
		return Cred{}, nil, errRevoked
	}
	recent := make([]time.Time, 0, len(s.st.EAB[id]))
	hourly := 0
	var oldestWeekly, oldestHourly time.Time
	for _, t := range s.st.EAB[id] {
		if now.Sub(t) < capWindow {
			recent = append(recent, t)
			if oldestWeekly.IsZero() || t.Before(oldestWeekly) {
				oldestWeekly = t
			}
			if now.Sub(t) < hourlyWindow {
				hourly++
				if oldestHourly.IsZero() || t.Before(oldestHourly) {
					oldestHourly = t
				}
			}
		}
	}
	inFlight := s.inFlightEAB[id]
	weeklyCap := s.caps.WeeklyFor(liveCred)
	if len(recent)+inFlight >= weeklyCap {
		s.st.EAB[id] = recent
		retry := retryAfterFromOldest(oldestWeekly, now, capWindow)
		if inFlight > 0 && len(recent) < weeklyCap && retry > 30*time.Second {
			retry = 30 * time.Second
		}
		return Cred{}, nil, &rateLimitError{cause: errEABWeeklyCap, retryAfter: retry}
	}
	hourlyCap := s.caps.HourlyFor(liveCred)
	if hourly+inFlight >= hourlyCap {
		s.st.EAB[id] = recent
		retry := retryAfterFromOldest(oldestHourly, now, hourlyWindow)
		if inFlight > 0 && hourly < hourlyCap && retry > 30*time.Second {
			retry = 30 * time.Second
		}
		return Cred{}, nil, &rateLimitError{cause: errEABHourlyCap, retryAfter: retry}
	}
	return liveCred, recent, nil
}

type eabReservationState int

const (
	eabPending eabReservationState = iota
	eabCanceled
	eabCommitted
)

// eabReservation holds an in-memory per-credential EAB cap slot while an
// upstream EAB mint is in flight. Calling Cancel releases the slot without
// burning quota or marking EverChallenged; calling Commit persists the mint.
type eabReservation struct {
	store  *Store
	credID string
	state  eabReservationState
}

// ReserveEAB validates that a credential is active and within its hourly/weekly
// EAB caps, reserving one in-flight slot without writing to disk.
func (s *Store) ReserveEAB(c Cred) (*eabReservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, err := s.checkEABLocked(c.ID, s.now()); err != nil {
		return nil, err
	}
	if s.inFlightEAB == nil {
		s.inFlightEAB = map[string]int{}
	}
	s.inFlightEAB[c.ID]++
	return &eabReservation{store: s, credID: c.ID, state: eabPending}, nil
}

func (s *Store) releaseInFlightEABLocked(id string) {
	if n := s.inFlightEAB[id]; n <= 1 {
		delete(s.inFlightEAB, id)
	} else {
		s.inFlightEAB[id] = n - 1
	}
}

// Cancel releases an uncommitted EAB reservation. Safe to call more than once
// or after Commit.
func (r *eabReservation) Cancel() {
	if r == nil {
		return
	}
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	if r.state != eabPending {
		return
	}
	r.state = eabCanceled
	r.store.releaseInFlightEABLocked(r.credID)
}

// Commit converts a reserved EAB slot into a persisted EAB usage entry and
// marks the credential as EverChallenged. Because caps were already enforced
// at ReserveEAB time, Commit checks only that the credential has not been
// revoked while Mint was in flight.
func (r *eabReservation) Commit() error {
	if r == nil {
		return errors.New("nil EAB reservation")
	}
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	if r.state == eabCommitted {
		return nil
	}
	if r.state == eabCanceled {
		return errors.New("EAB reservation already canceled")
	}
	r.state = eabCommitted
	r.store.releaseInFlightEABLocked(r.credID)
	return r.store.persistEABLocked(r.credID, r.store.now())
}

func (s *Store) persistEABLocked(id string, now time.Time) error {
	if _, ok := s.credLocked(id); !ok {
		return errRevoked
	}
	recent := make([]time.Time, 0, len(s.st.EAB[id])+1)
	for _, t := range s.st.EAB[id] {
		if now.Sub(t) < capWindow {
			recent = append(recent, t)
		}
	}
	return s.mutateLocked(func() error {
		s.st.EAB[id] = append(recent, now)
		s.markChallengedLocked(id)
		return nil
	})
}

// AllowEAB records an EAB mint for a credential, gated by the same per-pen
// hourly and weekly caps as new certificate names.
func (s *Store) AllowEAB(c Cred) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if _, _, err := s.checkEABLocked(c.ID, now); err != nil {
		return err
	}
	return s.persistEABLocked(c.ID, now)
}
