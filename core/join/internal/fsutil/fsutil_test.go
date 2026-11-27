package fsutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteFileAtomicCreatesOverwritesAndCleansTempFiles(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	secretPath := filepath.Join(base, "private-dir", "config.json")
	if err := WriteFileAtomic(secretPath, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic initial: %v", err)
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

	if err := WriteFileAtomic(secretPath, []byte(`{"v":2}`), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic overwrite: %v", err)
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

	unitFile := filepath.Join(base, "units", "test.service")
	if err := WriteFileAtomic(unitFile, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatalf("WriteFileAtomic unit: %v", err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(unitFile); err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("unit file mode = %o (err=%v), want 0644", fi.Mode().Perm(), err)
		}
	}

	targetDir := filepath.Join(base, "target-is-dir")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(targetDir, []byte("x"), 0o600); err == nil {
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

func TestCopyExecutableAtomicSHA256AndShareLock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "src-bin")
	dst := filepath.Join(dir, "dst-bin")
	if err := os.WriteFile(src, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CopyExecutableAtomic(src, dst); err != nil {
		t.Fatalf("CopyExecutableAtomic: %v", err)
	}
	sumSrc, err := FileSHA256(src)
	if err != nil {
		t.Fatal(err)
	}
	sumDst, err := FileSHA256(dst)
	if err != nil || sumDst != sumSrc {
		t.Fatalf("FileSHA256 mismatch: src=%q dst=%q err=%v", sumSrc, sumDst, err)
	}
	if !SameFilePath(dst, filepath.Join(dir, ".", "dst-bin")) {
		t.Fatal("SameFilePath failed on equivalent clean paths")
	}

	if runtime.GOOS != "windows" {
		unlock, err := AcquireShareLock(dir)
		if err != nil {
			t.Fatalf("AcquireShareLock #1: %v", err)
		}
		if _, err := AcquireShareLock(dir); !errors.Is(err, ErrLocked) {
			t.Fatalf("AcquireShareLock #2 = %v, want ErrLocked", err)
		}
		unlock()
		unlock2, err := AcquireShareLock(dir)
		if err != nil {
			t.Fatalf("AcquireShareLock after unlock: %v", err)
		}
		unlock2()
	}
}
