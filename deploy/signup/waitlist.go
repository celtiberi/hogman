package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// The waiting list: people who'd like a pen when there's room, or who have no
// code yet. One line per person in $HOGMAN_HOME/signup/waitlist, tab-separated:
//
//	id  added-at  status  email  pen  note
//
// status is "waiting", or "invited <code>" once the keeper sends them a code.
// hogman-host waitlist reads and edits the same file, under the same lock.

const waitlistMax = 5000

// Strict printable-ASCII local-part allowlist: blocks NUL, ESC/ANSI, C1, and
// whitespace/quote/backslash characters so stored emails are safe in terminal
// output, bash fields, and Resend JSON payloads.
var emailRE = regexp.MustCompile("^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+$")

type waitEntry struct {
	ID     int
	At     string
	Status string
	Email  string
	Pen    string
	Note   string
}

func validEmail(e string) bool { return len(e) <= 254 && emailRE.MatchString(e) }

// cleanField keeps a field to one line with no tabs or control/BiDi characters,
// so the file stays parseable and safe to display in operator terminals.
func cleanField(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return strings.TrimSpace(s)
}

func (b *broker) waitPath() string { return filepath.Join(b.home, "signup", "waitlist") }

func (b *broker) readWaitlist() ([]waitEntry, error) {
	f, err := os.Open(b.waitPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []waitEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), "\t")
		if len(p) < 6 {
			continue
		}
		id, _ := strconv.Atoi(p[0])
		out = append(out, waitEntry{id, p[1], p[2], p[3], p[4], p[5]})
	}
	return out, sc.Err()
}

// joinWaitlist adds someone, unless they're already waiting. Returns their
// place among those still waiting.
func (b *broker) joinWaitlist(email, pen, note string) (place int, already bool, err error) {
	unlock, err := b.lock(b.waitPath() + ".lock")
	if err != nil {
		return 0, false, err
	}
	defer unlock()
	list, err := b.readWaitlist()
	if err != nil {
		return 0, false, err
	}
	maxID, waiting := 0, 0
	for _, e := range list {
		if e.ID > maxID {
			maxID = e.ID
		}
		if e.Status == "waiting" {
			waiting++
			if strings.EqualFold(e.Email, email) {
				return waiting, true, nil
			}
		}
	}
	if len(list) >= waitlistMax {
		return 0, false, errFull
	}
	if !b.allowWaitlistJoin(time.Now()) {
		return 0, false, errWaitlistBusy
	}
	f, err := os.OpenFile(b.waitPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%d\t%s\t%s\t%s\t%s\t%s\n", maxID+1, time.Now().UTC().Format(time.RFC3339), "waiting", email, pen, note)
	return waiting + 1, false, err
}

var (
	errFull         = fmt.Errorf("the waiting list is full")
	errWaitlistBusy = fmt.Errorf("waiting list is busy")
)

func (b *broker) waitlist(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
		Pen   string `json:"pen"`
		Note  string `json:"note"`
		Theme string `json:"theme,omitempty"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if !validEmail(email) {
		jsonOut(w, 400, map[string]string{"error": "that doesn't look like an email address"})
		return
	}
	pen := strings.ToLower(strings.TrimSpace(in.Pen))
	if pen != "" {
		if why, ok := validPen(pen); !ok {
			jsonOut(w, 400, map[string]string{"error": "pen name: " + why})
			return
		}
	}
	theme := strings.ToLower(strings.TrimSpace(in.Theme))
	if theme != "" && theme != "work" {
		jsonOut(w, 400, map[string]string{"error": "invalid theme"})
		return
	}
	place, already, err := b.joinWaitlist(email, pen, cleanField(in.Note, 280))
	switch {
	case err == errFull:
		jsonOut(w, 503, map[string]string{"error": "the waiting list is full right now; try again later"})
		return
	case err == errWaitlistBusy:
		jsonOut(w, 429, map[string]string{"error": "the waiting list is busy right now; try again later"})
		return
	case err != nil:
		log.Printf("waitlist: %v", err)
		jsonOut(w, 500, map[string]string{"error": "internal error"})
		return
	}
	if !already {
		log.Printf("waitlist: someone joined (%d waiting)", place)
		b.notifyKind("waitlist", fmt.Sprintf("Someone joined the waiting list. %d waiting. See: hogman-host waitlist", place))
		b.sendWaitlistAckAsync(email, place, theme == "work")
	}
	jsonOut(w, 200, map[string]any{"place": place, "already": already})
}

// waitlistAckEmail builds the plain-text confirmation email for a brand-new
// waiting-list entry. It intentionally never reflects the caller's free-form
// note so Hogman's mail domain cannot be abused to relay arbitrary text.
func waitlistAckEmail(place int, isWork bool, origin string) (subject, body string) {
	product := "Hogman"
	leaveLabel := "Take me off the list"
	if isWork {
		product = "Hogman for Work"
		leaveLabel = "Remove my email"
	}
	subject = fmt.Sprintf("You're on the %s waiting list", product)
	var sb strings.Builder
	fmt.Fprintf(&sb, "You're on the %s waiting list (spot #%d).\n\n", product, place)
	sb.WriteString("We'll email you a sign-up code for a free pen as soon as capacity opens.\n")
	if origin != "" {
		fmt.Fprintf(&sb, "\nDidn't request this, or want to leave the list? Remove your email anytime at:\n%s/#wait\n(Enter this email address and choose \"%s\".)\n", strings.TrimRight(origin, "/"), leaveLabel)
	}
	return subject, sb.String()
}

// sendWaitlistAckAsync sends a one-time confirmation email via Resend for a
// newly added waiting-list entry without blocking /waitlist (preserving
// uniform response timing and preventing mail failures from failing sign-ups).
func (b *broker) sendWaitlistAckAsync(email string, place int, isWork bool) {
	if b.alertSendFn == nil && (b.resendAPIKey == "" || b.billingFrom == "") {
		return
	}
	b.ensureLimits()
	// Take the in-flight slot before spending any rate-limit budget so a full
	// semaphore never burns a quota slot for mail that will not be sent.
	select {
	case b.mailSem <- struct{}{}:
	default:
		log.Printf("waitlist ack mail: too many emails in flight; skipping confirmation email")
		return
	}
	now := b.now()
	// Check the per-address 1/24h in-memory cap BEFORE the global cap so a
	// join -> leave -> join loop on one address cannot bomb a recipient or
	// exhaust the shared budget for real joiners.
	if !b.allowWaitlistAckAddr(email, now) {
		<-b.mailSem
		log.Printf("waitlist ack mail: per-address 24h cap hit; skipping confirmation email")
		return
	}
	if !b.allowWaitlistAckMail(now) {
		<-b.mailSem
		log.Printf("waitlist ack mail: rate cap hit; skipping confirmation email")
		return
	}
	plan := planPersonal
	if isWork {
		plan = planWork
	}
	origin := b.renewOriginForPen(plan)
	subject, body := waitlistAckEmail(place, isWork, origin)
	go func() {
		defer func() { <-b.mailSem }()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// Reuses the broker's Resend sender (RESEND_API_KEY_FILE / BILLING_FROM).
		if _, err := b.sendBillingAlert(ctx, []string{email}, subject, body); err != nil {
			log.Printf("waitlist ack mail: send failed: %v", err)
		}
	}()
}

// notifyKind pushes a capped note to the operator's ntfy topic without growing
// unbounded background requests. Never personal details: just that something happened.
func (b *broker) notifyKind(kind, msg string) {
	if b.ntfy == "" {
		return
	}
	u, err := url.Parse(b.ntfy)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return
	}
	if !b.notifyLimiter(kind).allow("*", time.Now()) {
		log.Printf("ntfy: rate cap hit for %s", kind)
		return
	}
	select {
	case b.ntfySem <- struct{}{}:
	default:
		log.Printf("ntfy: skipping %s push (too many in flight)", kind)
		return
	}
	go func() {
		defer func() { <-b.ntfySem }()
		req, _ := http.NewRequest("POST", u.String(), strings.NewReader(msg))
		req.Header.Set("Title", "Hogman sign-ups")
		req.Header.Set("Tags", "pig")
		c := &http.Client{Timeout: 15 * time.Second}
		if resp, err := c.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
}

// dropInvited deletes the waiting-list entry that was sent this code, if any:
// the page promises to delete someone's email once they've signed up.
func (b *broker) dropInvited(code string) error {
	unlock, err := b.lock(b.waitPath() + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	data, err := os.ReadFile(b.waitPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var keep []string
	dropped := false
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		p := strings.Split(line, "\t")
		if len(p) >= 3 && p[2] == "invited "+code {
			dropped = true
			continue
		}
		if line != "" {
			keep = append(keep, line)
		}
	}
	if !dropped {
		return nil
	}
	out := strings.Join(keep, "\n")
	if out != "" {
		out += "\n"
	}
	tmp := b.waitPath() + ".new"
	if err := os.WriteFile(tmp, []byte(out), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.waitPath())
}

// leaveWaitlist removes every waiting entry for this email. It answers the
// same whether or not the address was there, so nobody can use it to learn
// who is on the list.
func (b *broker) leaveWaitlist(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if !validEmail(email) {
		jsonOut(w, 400, map[string]string{"error": "that doesn't look like an email address"})
		return
	}
	if err := b.removeWaiting(email); err != nil {
		log.Printf("waitlist leave: %v", err)
		jsonOut(w, 500, map[string]string{"error": "internal error"})
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func (b *broker) removeWaiting(email string) error {
	unlock, err := b.lock(b.waitPath() + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	data, err := os.ReadFile(b.waitPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var keep []string
	removed := false
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		p := strings.Split(line, "\t")
		if len(p) >= 4 && p[2] == "waiting" && strings.EqualFold(p[3], email) {
			removed = true
			continue
		}
		if line != "" {
			keep = append(keep, line)
		}
	}
	if !removed {
		return nil
	}
	out := strings.Join(keep, "\n")
	if out != "" {
		out += "\n"
	}
	tmp := b.waitPath() + ".new"
	if err := os.WriteFile(tmp, []byte(out), 0o600); err != nil {
		return err
	}
	log.Printf("waitlist: someone took themselves off")
	return os.Rename(tmp, b.waitPath())
}
