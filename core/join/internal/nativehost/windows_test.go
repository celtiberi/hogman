//go:build windows

package nativehost

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
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
