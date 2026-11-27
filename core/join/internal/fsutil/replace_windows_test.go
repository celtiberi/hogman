//go:build windows

package fsutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestReplaceRunningExecutableHelper(t *testing.T) {
	readyFile := os.Getenv("HOGMAN_TEST_REPLACE_READY")
	if readyFile == "" {
		return
	}
	_ = os.WriteFile(readyFile, []byte("ready"), 0o600)
	time.Sleep(30 * time.Second)
}

func TestReplaceRunningExecutableOnWindows(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "hogman.exe")
	if err := CopyExecutableAtomic(os.Args[0], dst); err != nil {
		t.Fatalf("seed dst executable: %v", err)
	}

	readyFile := filepath.Join(dir, "ready")
	cmd := exec.Command(dst, "-test.run=^TestReplaceRunningExecutableHelper$")
	cmd.Env = append(os.Environ(), "HOGMAN_TEST_REPLACE_READY="+readyFile)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start running exe: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		// Give Windows a moment to release the renamed .old image handle before TempDir cleanup.
		for i := 0; i < 20; i++ {
			if err := os.Remove(dst + ".old"); err == nil || os.IsNotExist(err) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(readyFile); err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if _, err := os.Stat(readyFile); err != nil {
		t.Fatalf("helper exe did not become ready: %v", err)
	}

	newSrc := filepath.Join(dir, "hogman-new.exe")
	newPayload := []byte("MZ-updated-hogman-windows-binary")
	if err := os.WriteFile(newSrc, newPayload, 0o755); err != nil {
		t.Fatal(err)
	}
	wantSum, err := FileSHA256(newSrc)
	if err != nil {
		t.Fatal(err)
	}

	if err := CopyExecutableAtomic(newSrc, dst); err != nil {
		t.Fatalf("CopyExecutableAtomic on running Windows exe failed: %v", err)
	}
	gotSum, err := FileSHA256(dst)
	if err != nil || gotSum != wantSum {
		t.Fatalf("replaced exe sha256 = %q (err=%v), want %q", gotSum, err, wantSum)
	}
}
