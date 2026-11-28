//go:build windows

package nativehost

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	"hogman/join/internal/fsutil"
)

func deleteRegTreeBestEffort(path string) {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		names, _ := k.ReadSubKeyNames(-1)
		_ = k.Close()
		for _, sub := range names {
			deleteRegTreeBestEffort(path + `\` + sub)
		}
	}
	_ = registry.DeleteKey(registry.CURRENT_USER, path)
}

func TestWindowsNativeManifestRegistryLifecycle(t *testing.T) {
	prefix := fmt.Sprintf(`Software\HogmanTest\NMH-%d-%d`, os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() {
		deleteRegTreeBestEffort(prefix)
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\HogmanTest`)
	})

	cfgBase := t.TempDir()
	hostPath := filepath.Join(cfgBase, "bin", "hogman-native-host.exe")
	chromeIDs := []string{DefaultChromeExtIDs[0], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	firefoxIDs := []string{DefaultFirefoxExtIDs[0], "hogman-browser-staging@pens.example.test"}

	written, err := registerNativeManifestsUnder(prefix, cfgBase, hostPath, chromeIDs, firefoxIDs)
	if err != nil {
		t.Fatalf("registerNativeManifestsUnder: %v", err)
	}
	if written != len(windowsNativeBrowsers) {
		t.Fatalf("written = %d, want %d", written, len(windowsNativeBrowsers))
	}

	wantChromeJSON := filepath.Join(cfgBase, "bin", HostName+".chrome.json")
	wantFirefoxJSON := filepath.Join(cfgBase, "bin", HostName+".firefox.json")
	for _, b := range windowsNativeBrowsers {
		keyPath := prefix + `\` + b.subkey
		k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
		if err != nil {
			t.Fatalf("expected registry key HKCU\\%s: %v", keyPath, err)
		}
		got, _, err := k.GetStringValue("")
		_ = k.Close()
		if err != nil {
			t.Fatalf("read default value of HKCU\\%s: %v", keyPath, err)
		}
		want := wantChromeJSON
		if b.kind == "firefox" {
			want = wantFirefoxJSON
		}
		if got != want {
			t.Fatalf("HKCU\\%s = %q, want %q", keyPath, got, want)
		}
	}

	var chromeDoc struct {
		Path           string   `json:"path"`
		AllowedOrigins []string `json:"allowed_origins"`
	}
	rawChrome, err := os.ReadFile(wantChromeJSON)
	if err != nil {
		t.Fatalf("read chrome manifest: %v", err)
	}
	if err := json.Unmarshal(rawChrome, &chromeDoc); err != nil {
		t.Fatalf("parse chrome manifest: %v", err)
	}
	if chromeDoc.Path != hostPath || len(chromeDoc.AllowedOrigins) != 2 {
		t.Fatalf("unexpected chrome manifest: %+v", chromeDoc)
	}

	unregisterNativeManifestsUnder(prefix, cfgBase)
	for _, b := range windowsNativeBrowsers {
		keyPath := prefix + `\` + b.subkey
		if k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE); err == nil {
			_ = k.Close()
			t.Fatalf("registry key HKCU\\%s still exists after unregister", keyPath)
		}
	}
	for _, p := range []string{wantChromeJSON, wantFirefoxJSON} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("manifest file %s still exists after unregister (err=%v)", p, err)
		}
	}
}

func TestWindowsNativeHostHelperProcess(t *testing.T) {
	if os.Getenv("HOGMAN_NATIVE_HOST_HELPER") != "1" {
		return
	}
	fmt.Println("READY")
	time.Sleep(30 * time.Second)
}

func startDummyNativeHost(t *testing.T, dst string) (*exec.Cmd, <-chan error) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(dst), err)
	}
	if err := fsutil.CopyExecutableAtomic(self, dst); err != nil {
		t.Fatalf("copy helper exe to %s: %v", dst, err)
	}
	cmd := exec.Command(dst, "-test.run=^TestWindowsNativeHostHelperProcess$")
	cmd.Env = append(os.Environ(), "HOGMAN_NATIVE_HOST_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper %s: %v", dst, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	})

	readyCh := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		readyCh <- strings.TrimSpace(line)
	}()
	select {
	case line := <-readyCh:
		if line != "READY" {
			t.Fatalf("helper %s printed %q, want READY", dst, line)
		}
	case err := <-done:
		t.Fatalf("helper %s exited before READY: %v", dst, err)
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for helper %s READY", dst)
	}
	return cmd, done
}

func TestWindowsRemoveStopsRunningNativeHost(t *testing.T) {
	prefix := fmt.Sprintf(`Software\HogmanTest\NMHRemove-%d-%d`, os.Getpid(), time.Now().UnixNano())
	origPrefix := windowsNativeRegPrefix
	windowsNativeRegPrefix = prefix
	t.Cleanup(func() {
		windowsNativeRegPrefix = origPrefix
		deleteRegTreeBestEffort(prefix)
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\HogmanTest`)
	})

	cfgBase := t.TempDir()
	otherBase := t.TempDir()
	hostPath := BinaryPath(cfgBase)
	otherHostPath := BinaryPath(otherBase)

	_, targetDone := startDummyNativeHost(t, hostPath)
	_, otherDone := startDummyNativeHost(t, otherHostPath)

	if _, err := registerNativeManifestsUnder(prefix, cfgBase, hostPath, DefaultChromeExtIDs, DefaultFirefoxExtIDs); err != nil {
		t.Fatalf("registerNativeManifestsUnder: %v", err)
	}

	// Sanity check: while running, Windows refuses direct unlink of hostPath.
	if err := os.Remove(hostPath); err == nil {
		t.Fatalf("expected os.Remove(%s) to fail while process is running", hostPath)
	}

	Remove(cfgBase)

	select {
	case <-targetDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("expected target native host %s to be stopped by Remove", hostPath)
	}

	if _, err := os.Stat(hostPath); !os.IsNotExist(err) {
		t.Fatalf("host binary %s still exists after Remove (err=%v)", hostPath, err)
	}
	if err := os.RemoveAll(cfgBase); err != nil {
		t.Fatalf("os.RemoveAll(%s) after Remove: %v", cfgBase, err)
	}

	// Unrelated hogman-native-host.exe in another directory must NOT be killed.
	select {
	case err := <-otherDone:
		t.Fatalf("unrelated native host in %s exited unexpectedly: %v", otherBase, err)
	case <-time.After(250 * time.Millisecond):
	}
}
