//go:build !cdnstest

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultBuildRefusesTestEABFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(validPath, []byte(`{"kid":"k1","hmac_b64url":"abc123"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTestEABMinter(validPath, nil); err == nil || !strings.Contains(err.Error(), "unsupported in this build") {
		t.Fatalf("loadTestEABMinter() = %v, want unsupported-in-this-build error", err)
	}
	api := &API{}
	err := configureFallbackEAB(context.Background(), api, "", validPath, "ops@example.com", nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported in this build") {
		t.Fatalf("configureFallbackEAB() = %v, want unsupported-in-this-build error", err)
	}
	if api.eab != nil {
		t.Fatalf("expected api.eab to remain nil, got %T", api.eab)
	}
}
