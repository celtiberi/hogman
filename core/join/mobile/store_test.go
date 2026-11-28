package mobile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"tailscale.com/ipn"
)

func testKey(seed byte) []byte {
	k := make([]byte, StateKeyLen)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func TestEncryptedStateStoreLifecycleAndSecurity(t *testing.T) {
	dir := t.TempDir()
	key := testKey(1)

	st, err := NewEncryptedStateStore(dir, key)
	if err != nil {
		t.Fatalf("NewEncryptedStateStore: %v", err)
	}

	if _, err := st.ReadState("missing"); err != ipn.ErrStateNotExist {
		t.Fatalf("ReadState(missing) = %v, want ErrStateNotExist", err)
	}

	want := []byte(`{"node_key":"secret-wireguard-private-key"}`)
	if err := st.WriteState("profile-1", want); err != nil {
		t.Fatalf("WriteState: %v", err)
	}

	// Verify ciphertext on disk does not contain plaintext and has 0600 perms on Unix.
	encPath := filepath.Join(dir, encryptedStoreFilename)
	rawOnDisk, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", encPath, err)
	}
	if bytes.Contains(rawOnDisk, []byte("secret-wireguard-private-key")) {
		t.Fatalf("plaintext leaked into encrypted state file")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(encPath)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("encrypted state perms = %o, want 0600", fi.Mode().Perm())
		}
	}

	// Close must wipe the in-memory key copy and reject subsequent ops.
	st.Close()
	for i, b := range st.key {
		if b != 0 {
			t.Fatalf("st.key[%d] = %d after Close, want 0", i, b)
		}
	}
	if _, err := st.ReadState("profile-1"); err == nil {
		t.Fatalf("expected error reading closed store")
	}

	// Re-open with same key succeeds and returns exact plaintext.
	st2, err := NewEncryptedStateStore(dir, key)
	if err != nil {
		t.Fatalf("re-open with same key: %v", err)
	}
	defer st2.Close()
	got, err := st2.ReadState("profile-1")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("ReadState = (%q, %v), want %q", got, err, want)
	}

	// Re-open with wrong key must fail authentication.
	if _, err := NewEncryptedStateStore(dir, testKey(99)); err == nil {
		t.Fatalf("expected decryption failure with wrong key")
	}

	// Swapping ciphertext to a different StateKey ID must fail AAD check.
	var env encryptedEnvelope
	if err := json.Unmarshal(rawOnDisk, &env); err != nil {
		t.Fatal(err)
	}
	swappedDir := t.TempDir()
	env.Entries["profile-2"] = env.Entries["profile-1"]
	delete(env.Entries, "profile-1")
	swappedBytes, _ := json.Marshal(env)
	if err := os.WriteFile(filepath.Join(swappedDir, encryptedStoreFilename), swappedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptedStateStore(swappedDir, key); err == nil {
		t.Fatalf("expected AAD mismatch failure when ciphertext moved across StateKey IDs")
	}

	// Delete entry via WriteState(id, nil).
	if err := st2.WriteState("profile-1", nil); err != nil {
		t.Fatalf("WriteState(nil): %v", err)
	}
	if _, err := st2.ReadState("profile-1"); err != ipn.ErrStateNotExist {
		t.Fatalf("ReadState after delete = %v, want ErrStateNotExist", err)
	}
}

func TestValidateStateKeyRejectsInvalid(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"short", make([]byte, 31)},
		{"long", make([]byte, 33)},
		{"all-zero", make([]byte, 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateStateKey(tc.key); err == nil {
				t.Fatalf("validateStateKey(%s) = nil, want error", tc.name)
			}
		})
	}
}

func TestEncryptedSecretRoundTripAndAAD(t *testing.T) {
	p := filepath.Join(t.TempDir(), encryptedAuthKeyFile)
	key := testKey(7)
	aad := []byte("hogman-authkey:bobo.pens.example.com")
	secret := []byte("tskey-auth-example-one-time")

	if err := saveEncryptedSecret(p, key, aad, secret); err != nil {
		t.Fatalf("saveEncryptedSecret: %v", err)
	}
	got, err := loadEncryptedSecret(p, key, aad)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("loadEncryptedSecret = (%q, %v), want %q", got, err, secret)
	}
	if _, err := loadEncryptedSecret(p, key, []byte("hogman-authkey:other.pens.example.com")); err == nil {
		t.Fatalf("expected AAD mismatch failure")
	}
}
