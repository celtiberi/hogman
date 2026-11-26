package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPolicyRenewOnlyFailClosed(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "billing-status.json")
	pol := NewPolicy(statusPath)

	if pol.IsRenewOnly() {
		t.Fatal("missing status and marker should not be renew_only")
	}
	if pol.View(true) != nil {
		t.Fatal("expected nil view when no billing state exists")
	}

	// Valid grace status is not renew_only and exposes CanRenew only to admins.
	if err := os.WriteFile(statusPath, []byte(`{"pen":"demo","state":"grace","renew_url":"https://signup.example/foo"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if pol.IsRenewOnly() {
		t.Fatal("grace state should not be renew_only")
	}
	if v := pol.View(true); v == nil || v.State != "grace" || !v.CanRenew {
		t.Fatalf("admin grace view = %+v, want grace+CanRenew", v)
	}
	if v := pol.View(false); v == nil || v.CanRenew {
		t.Fatalf("member grace view = %+v, want CanRenew=false", v)
	}
	if st := pol.Status(); st == nil || st.RenewURL != "https://signup.example" {
		t.Fatalf("expected RenewURL normalized to origin, got %+v", st)
	}

	// Corrupt JSON fails closed to renew_only.
	if err := os.WriteFile(statusPath, []byte(`{corrupt`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !pol.IsRenewOnly() {
		t.Fatal("corrupt billing-status.json must fail closed to renew_only")
	}
	if v := pol.View(true); v == nil || v.State != "renew_only" || v.CanRenew {
		t.Fatalf("corrupt view = %+v, want renew_only CanRenew=false", v)
	}

	// .renew-only marker wins even over valid grace status.
	if err := os.WriteFile(statusPath, []byte(`{"pen":"demo","state":"grace","renew_url":"https://signup.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".renew-only"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !pol.IsRenewOnly() {
		t.Fatal(".renew-only marker must force renew_only mode")
	}
}

func TestPolicyHostMetaAndTokenDomainSeparation(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "billing-status.json")
	metaPath := filepath.Join(dir, "host-meta.json")
	pol := NewPolicy(statusPath)

	// Invalid HTTP delete_url or pipe in pen name must be rejected.
	if err := os.WriteFile(metaPath, []byte(`{"pen":"bad|pen","delete_url":"https://signup.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if pol.HostMeta() != nil {
		t.Fatal("expected nil HostMeta for pen with delimiter")
	}
	if err := os.WriteFile(metaPath, []byte(`{"pen":"demo","delete_url":"http://signup.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if pol.HostMeta() != nil {
		t.Fatal("expected nil HostMeta for non-HTTPS delete_url")
	}

	if err := os.WriteFile(metaPath, []byte(`{"pen":"Demo","delete_url":"https://signup.example/path","has_subscription":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	meta := pol.HostMeta()
	if meta == nil || meta.Pen != "demo" || meta.DeleteURL != "https://signup.example" || !meta.HasSubscription {
		t.Fatalf("HostMeta = %+v", meta)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	renewTok, exp, err := pol.MintRenewToken("demo", "alice", "owner", now)
	if err != nil {
		t.Fatalf("MintRenewToken: %v", err)
	}
	if !exp.Equal(now.Add(renewTokenTTL)) {
		t.Fatalf("exp = %v, want %v", exp, now.Add(renewTokenTTL))
	}
	delTok, _, err := pol.MintDeleteToken("demo", "alice", now)
	if err != nil {
		t.Fatalf("MintDeleteToken: %v", err)
	}

	keyHex, err := os.ReadFile(pol.KeyPath())
	if err != nil {
		t.Fatalf("read renew.key: %v", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil || len(key) != 32 {
		t.Fatalf("invalid key: len=%d err=%v", len(key), err)
	}

	verify := func(tok, purpose string) bool {
		payload, sig, ok := strings.Cut(tok, ".")
		if !ok {
			return false
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(purpose))
		mac.Write([]byte(payload))
		want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		return hmac.Equal([]byte(sig), []byte(want))
	}
	if !verify(renewTok, renewTokenPurpose) || verify(renewTok, deleteTokenPurpose) {
		t.Fatal("renew token failed purpose domain separation")
	}
	if !verify(delTok, deleteTokenPurpose) || verify(delTok, renewTokenPurpose) {
		t.Fatal("delete token failed purpose domain separation")
	}
}
