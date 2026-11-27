//go:build windows

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	"hogman/join/internal/state"
)

func TestWinDetachedHelper(t *testing.T) {
	if os.Getenv("GO_TEST_WIN_DETACHED") == "" {
		return
	}
	fmt.Println("detached-ready")
	time.Sleep(30 * time.Second)
}

func TestSpawnDetachedProcessAliveAndStopProcessOnWindows(t *testing.T) {
	if ProcessAlive(0) || ProcessAlive(-1) {
		t.Fatal("ProcessAlive should return false for non-positive PIDs")
	}

	t.Setenv("GO_TEST_WIN_DETACHED", "1")
	logPath := filepath.Join(t.TempDir(), "detached.log")
	pid, err := SpawnDetached(logPath, os.Args[0], "-test.run=^TestWinDetachedHelper$")
	if err != nil {
		t.Fatalf("SpawnDetached: %v", err)
	}
	t.Cleanup(func() {
		StopProcess(pid, 2*time.Second)
	})

	if !ProcessAlive(pid) {
		t.Fatalf("newly spawned PID %d reported not alive", pid)
	}

	deadline := time.Now().Add(5 * time.Second)
	sawReady := false
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(logPath); err == nil && strings.Contains(string(b), "detached-ready") {
			sawReady = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sawReady {
		b, _ := os.ReadFile(logPath)
		t.Fatalf("detached helper did not log ready line; log=%q", string(b))
	}

	StopProcess(pid, 2*time.Second)
	if ProcessAlive(pid) {
		t.Fatalf("PID %d still reported alive after StopProcess", pid)
	}
}

func TestWindowsRunRegistryAutostartLifecycle(t *testing.T) {
	testKey := fmt.Sprintf(`Software\HogmanTest\Run-%d-%d`, os.Getpid(), time.Now().UnixNano())
	orig := windowsRunRegPath
	windowsRunRegPath = testKey
	t.Cleanup(func() {
		windowsRunRegPath = orig
		_ = registry.DeleteKey(registry.CURRENT_USER, testKey)
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\HogmanTest`)
	})

	zone := "alpha.pens.example.com"
	agentCfg := &state.AgentConfig{Zone: zone}
	shareCfg := &state.ShareConfig{Name: "blog", Zone: zone}
	agentDir := filepath.Join(t.TempDir(), "pen alpha")
	shareDir := filepath.Join(t.TempDir(), "share blog")
	oldBin := `C:\Users\Alice Smith\AppData\Roaming\hogman\bin\hogman-old.exe`
	newBin := `C:\Users\Alice Smith\AppData\Roaming\hogman\bin\hogman.exe`

	if ServiceConfigured(zone) {
		t.Fatal("expected ServiceConfigured=false initially")
	}
	if ShareServiceConfigured(shareCfg) {
		t.Fatal("expected ShareServiceConfigured=false initially")
	}

	if err := RewriteAgentService(oldBin, agentDir, agentCfg); err != nil {
		t.Fatalf("RewriteAgentService(old): %v", err)
	}
	if err := RewriteShareService(oldBin, shareDir, shareCfg); err != nil {
		t.Fatalf("RewriteShareService(old): %v", err)
	}
	if !ServiceConfigured(zone) {
		t.Fatal("expected ServiceConfigured=true after RewriteAgentService")
	}
	if !ShareServiceConfigured(shareCfg) {
		t.Fatal("expected ShareServiceConfigured=true after RewriteShareService")
	}

	// Simulate hogman update rewriting both entries to the new canonical binary.
	if err := RewriteAgentService(newBin, agentDir, agentCfg); err != nil {
		t.Fatalf("RewriteAgentService(new): %v", err)
	}
	if err := RewriteShareService(newBin, shareDir, shareCfg); err != nil {
		t.Fatalf("RewriteShareService(new): %v", err)
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, testKey, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("open test Run key: %v", err)
	}
	defer k.Close()

	gotAgent, _, err := k.GetStringValue(WindowsRunValueName(zone))
	if err != nil {
		t.Fatalf("read agent Run value: %v", err)
	}
	if !strings.Contains(gotAgent, newBin) || !strings.Contains(gotAgent, "__start-detached agent") || !strings.Contains(gotAgent, agentDir) {
		t.Fatalf("unexpected agent Run value: %q", gotAgent)
	}

	gotShare, _, err := k.GetStringValue(WindowsShareRunValueName(shareCfg))
	if err != nil {
		t.Fatalf("read share Run value: %v", err)
	}
	if !strings.Contains(gotShare, newBin) || !strings.Contains(gotShare, "__start-detached share") || !strings.Contains(gotShare, shareDir) {
		t.Fatalf("unexpected share Run value: %q", gotShare)
	}

	StopAgent(agentDir, agentCfg)
	StopShareService(shareCfg)
	if ServiceConfigured(zone) {
		t.Fatal("expected ServiceConfigured=false after StopAgent")
	}
	if ShareServiceConfigured(shareCfg) {
		t.Fatal("expected ShareServiceConfigured=false after StopShareService")
	}
}
