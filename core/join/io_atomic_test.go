package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteFileAtomicCreatesOverwritesAndCleansTempFiles(t *testing.T) {
	base := t.TempDir()
	secretPath := filepath.Join(base, "private-dir", "config.json")
	if err := writeFileAtomic(secretPath, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatalf("writeFileAtomic initial: %v", err)
	}
	got, err := os.ReadFile(secretPath)
	if err != nil || !bytes.Equal(got, []byte(`{"v":1}`)) {
		t.Fatalf("initial content = %q (err=%v)", string(got), err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(secretPath); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("secret file mode = %o (err=%v), want 0600", fi.Mode().Perm(), err)
		}
		if fi, err := os.Stat(filepath.Dir(secretPath)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("secret parent dir mode = %o (err=%v), want 0700", fi.Mode().Perm(), err)
		}
	}

	// Overwrite atomically with new contents and verify no leftover temp files.
	if err := writeFileAtomic(secretPath, []byte(`{"v":2}`), 0o600); err != nil {
		t.Fatalf("writeFileAtomic overwrite: %v", err)
	}
	got, err = os.ReadFile(secretPath)
	if err != nil || !bytes.Equal(got, []byte(`{"v":2}`)) {
		t.Fatalf("overwritten content = %q (err=%v)", string(got), err)
	}
	entries, err := os.ReadDir(filepath.Dir(secretPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".hogman-tmp-") {
			t.Fatalf("leftover temp file found: %s", e.Name())
		}
	}

	// Public unit file gets 0644 and 0755 parent directory.
	unitFile := filepath.Join(base, "units", "test.service")
	if err := writeFileAtomic(unitFile, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic unit: %v", err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(unitFile); err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("unit file mode = %o (err=%v), want 0644", fi.Mode().Perm(), err)
		}
	}

	// Attempting to overwrite a directory fails without leaving temp files behind.
	targetDir := filepath.Join(base, "target-is-dir")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(targetDir, []byte("x"), 0o600); err == nil {
		t.Fatal("expected error overwriting directory")
	}
	entries, err = os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".hogman-tmp-") {
			t.Fatalf("leftover temp file after rename error: %s", e.Name())
		}
	}
}
