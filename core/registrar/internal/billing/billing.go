package billing

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Status is the host-written grace/renew-only notice at
// /var/lib/registrar/billing-status.json.
type Status struct {
	Pen        string `json:"pen,omitempty"`
	State      string `json:"state"`
	PaidUntil  string `json:"paid_until,omitempty"`
	GraceUntil string `json:"grace_until,omitempty"`
	WakeUntil  string `json:"wake_until,omitempty"`
	RenewURL   string `json:"renew_url,omitempty"`
}

// View is the sanitized projection returned on GET /api/me (never exposes
// signing material or unauthenticated renewal URLs).
type View struct {
	State      string `json:"state"`
	PaidUntil  string `json:"paid_until,omitempty"`
	GraceUntil string `json:"grace_until,omitempty"`
	WakeUntil  string `json:"wake_until,omitempty"`
	CanRenew   bool   `json:"can_renew,omitempty"`
}

const (
	renewTokenPurpose  = "hogman-renew-v1:"
	deleteTokenPurpose = "hogman-delete-v1:"
	renewTokenTTL      = 15 * time.Minute
)

// HostMeta is written by the shared host at /var/lib/registrar/host-meta.json
// for hosted pens (free and paid) so active owners can initiate self-service
// deletion from active, grace, and renew_only states without altering the
// fail-closed semantics of billing-status.json.
type HostMeta struct {
	Pen             string `json:"pen,omitempty"`
	DeleteURL       string `json:"delete_url,omitempty"`
	HasSubscription bool   `json:"has_subscription,omitempty"`
}

// PenDeleteView is the owner-only summary returned on GET /api/me for hosted pens.
type PenDeleteView struct {
	Pen             string   `json:"pen"`
	CanDelete       bool     `json:"can_delete"`
	HasSubscription bool     `json:"has_subscription,omitempty"`
	OtherOwners     []string `json:"other_owners,omitempty"`
	MemberCount     int      `json:"member_count"`
	DeviceCount     int      `json:"device_count"`
}

// Policy reads host-managed billing state (.renew-only, billing-status.json,
// host-meta.json) and mints short-lived HMAC tokens for in-pen renewal and
// self-service pen deletion.
type Policy struct {
	statusPath string
}

func NewPolicy(statusPath string) *Policy {
	return &Policy{statusPath: statusPath}
}

func (p *Policy) IsRenewOnly() bool {
	if p == nil {
		return false
	}
	return isRenewOnlyMode(p.statusPath)
}

func (p *Policy) Status() *Status {
	if p == nil {
		return nil
	}
	return readBillingStatus(p.statusPath)
}

func (p *Policy) View(isAdmin bool) *View {
	if st := p.Status(); st != nil {
		return &View{
			State:      st.State,
			PaidUntil:  st.PaidUntil,
			GraceUntil: st.GraceUntil,
			WakeUntil:  st.WakeUntil,
			CanRenew:   isAdmin && st.Pen != "" && st.RenewURL != "",
		}
	}
	if p.IsRenewOnly() {
		return &View{
			State:    "renew_only",
			CanRenew: false,
		}
	}
	return nil
}

func (p *Policy) HostMeta() *HostMeta {
	if p == nil {
		return nil
	}
	return readHostMeta(hostMetaPath(p.statusPath))
}

func (p *Policy) KeyPath() string {
	if p == nil || p.statusPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(p.statusPath), "renew.key")
}

func (p *Policy) MintRenewToken(pen, handle, role string, now time.Time) (string, time.Time, error) {
	return mintSignedToken(p.KeyPath(), renewTokenPurpose, pen, handle, role, now)
}

func (p *Policy) MintDeleteToken(pen, handle string, now time.Time) (string, time.Time, error) {
	return mintSignedToken(p.KeyPath(), deleteTokenPurpose, pen, handle, "owner", now)
}

func hostMetaPath(billingStatusPath string) string {
	if billingStatusPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(billingStatusPath), "host-meta.json")
}

func readHostMeta(path string) *HostMeta {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 4096 {
		return nil
	}
	var m HostMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	m.Pen = strings.ToLower(strings.TrimSpace(m.Pen))
	if m.Pen == "" || strings.ContainsAny(m.Pen, "|/\\ \t\r\n") {
		return nil
	}
	if m.DeleteURL != "" {
		u, err := url.Parse(strings.TrimSpace(m.DeleteURL))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			m.DeleteURL = ""
		} else {
			m.DeleteURL = "https://" + u.Host
		}
	}
	if m.DeleteURL == "" {
		return nil
	}
	return &m
}

func loadOrCreateRenewKey(path string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil {
		if k, derr := hex.DecodeString(strings.TrimSpace(string(raw))); derr == nil && len(k) == 32 {
			return k, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	encoded := []byte(hex.EncodeToString(key) + "\n")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			raw, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil, rerr
			}
			k, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
			if derr != nil || len(k) != 32 {
				return nil, errors.New("corrupt renew.key")
			}
			return k, nil
		}
		return nil, err
	}
	_, werr := f.Write(encoded)
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(path)
		return nil, werr
	}
	if cerr != nil {
		_ = os.Remove(path)
		return nil, cerr
	}
	return key, nil
}

func mintSignedToken(keyPath, purpose, pen, handle, role string, now time.Time) (string, time.Time, error) {
	key, err := loadOrCreateRenewKey(keyPath)
	if err != nil {
		return "", time.Time{}, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", time.Time{}, err
	}
	exp := now.UTC().Add(renewTokenTTL)
	rawPayload := fmt.Sprintf("v1|%s|%s|%s|%d|%s", pen, handle, role, exp.Unix(), hex.EncodeToString(nonce))
	payload := base64.RawURLEncoding.EncodeToString([]byte(rawPayload))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(purpose))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig, exp, nil
}

func renewOnlyMarkerPath(billingStatusPath string) string {
	if billingStatusPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(billingStatusPath), ".renew-only")
}

// isRenewOnlyMode reports whether the pen must run in restricted renew_only
// mode. Fails closed:
//   - if the .renew-only marker exists (or cannot be stat'd for a reason other
//     than ENOENT), returns true even if billing-status.json is absent;
//   - if billing-status.json exists but is unreadable, oversized (>4096B),
//     unparseable JSON, or has state "renew_only", returns true.
func isRenewOnlyMode(billingStatusPath string) bool {
	if billingStatusPath == "" {
		return false
	}
	marker := renewOnlyMarkerPath(billingStatusPath)
	if _, err := os.Stat(marker); err == nil || !os.IsNotExist(err) {
		return true
	}
	fi, err := os.Stat(billingStatusPath)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil || fi.Size() > 4096 {
		return true
	}
	b, err := os.ReadFile(billingStatusPath)
	if err != nil || len(b) > 4096 {
		return true
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil {
		return true
	}
	return st.State != "grace"
}

func readBillingStatus(path string) *Status {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 4096 {
		return nil
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil || (st.State != "grace" && st.State != "renew_only") {
		return nil
	}
	st.Pen = strings.ToLower(strings.TrimSpace(st.Pen))
	if st.RenewURL != "" {
		u, err := url.Parse(strings.TrimSpace(st.RenewURL))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			st.RenewURL = ""
		} else {
			st.RenewURL = "https://" + u.Host
		}
	}
	return &st
}
