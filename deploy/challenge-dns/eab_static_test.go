//go:build cdnstest

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticEABMinterValidation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	validPath := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(validPath, []byte(`{"kid":"k1","hmac_b64url":"abc123"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := loadTestEABMinter(validPath, nil)
	if err != nil {
		t.Fatalf("loadTestEABMinter(valid): %v", err)
	}
	kid, hmac, err := m.Mint(context.Background())
	if err != nil || kid != "k1" || hmac != "abc123" {
		t.Fatalf("Mint() = (%q, %q, %v), want (k1, abc123, nil)", kid, hmac, err)
	}

	unknownPath := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknownPath, []byte(`{"kid":"k1","hmac_b64url":"abc","extra":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTestEABMinter(unknownPath, nil); err == nil {
		t.Fatal("expected unknown field error")
	}

	emptyPath := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(emptyPath, []byte(`{"kid":"k1","hmac_b64url":"   "}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTestEABMinter(emptyPath, nil); err == nil {
		t.Fatal("expected missing hmac_b64url error")
	}

	bigPath := filepath.Join(dir, "big.json")
	if err := os.WriteFile(bigPath, []byte(strings.Repeat("a", maxTestEABFileBytes+10)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTestEABMinter(bigPath, nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}
