package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCanonicalBinaryConsolidationAndMigration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if runtime.GOOS == "windows" {
		t.Setenv("AppData", filepath.Join(home, "AppData"))
	}

	// installedBinary installs once to the canonical <configBase>/bin/ path,
	// regardless of which pen or share dir is passed.
	binA, err := installedBinary(stateDir("alpha.pens.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	binB, err := installedBinary(stateDir("beta.pens.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	wantCanon := canonicalBinaryPath(hogmanConfigBase())
	if binA != wantCanon || binB != wantCanon {
		t.Fatalf("installedBinary returned (%q, %q), want single canonical %q", binA, binB, wantCanon)
	}

	// Atomic migration: legacy per-pen binary is KEPT if restartNew fails,
	// and REMOVED only after restartNew succeeds on canonicalBin.
	penDir := stateDir("alpha.pens.example.com")
	_ = os.MkdirAll(penDir, 0o700)
	legacy := filepath.Join(penDir, installedBinaryName(runtime.GOOS))
	if err := os.WriteFile(legacy, []byte("legacy-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &penTarget{zone: "alpha.pens.example.com", dir: penDir, cfg: &agentConfig{Zone: "alpha.pens.example.com"}}

	failOps := penUpdateOps{
		isRunning:  func(string, *agentConfig) bool { return true },
		hasService: func(string) bool { return true },
		stop:       func(string, *agentConfig) {},
		restartNew: func(_ *penTarget, bin string, _ bool, _ options) error {
			if bin != wantCanon {
				t.Errorf("restartNew got bin=%q, want canonical %q", bin, wantCanon)
			}
			return errors.New("start failed")
		},
	}
	if err := migrateAndRestartPen(p, wantCanon, legacy, "/tmp/other-self", options{}, failOps); err == nil {
		t.Fatal("expected restart error")
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("legacy binary was deleted despite failed restart: %v", err)
	}

	okOps := failOps
	okOps.restartNew = func(_ *penTarget, bin string, _ bool, _ options) error {
		if bin != wantCanon {
			t.Errorf("restartNew got bin=%q, want canonical %q", bin, wantCanon)
		}
		return nil
	}
	if err := migrateAndRestartPen(p, wantCanon, legacy, "/tmp/other-self", options{}, okOps); err != nil {
		t.Fatalf("migrateAndRestartPen failed: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy binary was not removed after successful migration: %v", err)
	}
}

func TestDetectPackageManager(t *testing.T) {
	for _, tc := range []struct {
		path    string
		goos    string
		wantMgr string
		wantOK  bool
	}{
		{"/opt/homebrew/Cellar/hogman/2026.11.23/bin/hogman", "darwin", "Homebrew", true},
		{"/usr/local/Cellar/hogman/1.0/bin/hogman", "darwin", "Homebrew", true},
		{"/home/linuxbrew/.linuxbrew/Cellar/hogman/1.0/bin/hogman", "linux", "Homebrew", true},
		{"/usr/bin/hogman", "linux", "your system package manager", true},
		{`C:\Users\alice\scoop\apps\hogman\current\hogman.exe`, "windows", "Scoop", true},
		{`C:\Users\alice\AppData\Local\Microsoft\WinGet\Packages\Celtiberi.Hogman\hogman.exe`, "windows", "winget", true},
		{"/tmp/hogman", "darwin", "", false},
		{"/usr/local/bin/hogman", "linux", "", false},
	} {
		mgr, _, ok := detectPackageManager(tc.path, tc.goos)
		if ok != tc.wantOK || mgr != tc.wantMgr {
			t.Errorf("detectPackageManager(%q, %q) = (%q, %v), want (%q, %v)", tc.path, tc.goos, mgr, ok, tc.wantMgr, tc.wantOK)
		}
	}
}

func TestInstallNativeHostBinarySymlinkOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix symlink test")
	}
	dir := t.TempDir()
	canon := filepath.Join(dir, "hogman")
	if err := os.WriteFile(canon, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(dir, "hogman-native-host")
	// Even if an old regular-file copy exists, installNativeHostBinary replaces it with a symlink.
	if err := os.WriteFile(hostPath, []byte("old-copy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := installNativeHostBinary(canon, hostPath); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(hostPath)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink at %s, got mode=%v err=%v", hostPath, fi.Mode(), err)
	}
	if !sameFilePath(canon, hostPath) {
		t.Fatalf("symlink %s does not resolve to %s", hostPath, canon)
	}
}

func TestStatusShareListAndDoctorJSON(t *testing.T) {
	home := t.TempDir()
	cfgBase := filepath.Join(home, "hogman")
	sharesDir := filepath.Join(home, "hogman-shares")
	_ = os.MkdirAll(cfgBase, 0o700)
	_ = os.MkdirAll(sharesDir, 0o700)

	// 1. Empty status JSON emits [] arrays (never null) and valid JSON.
	out := buildStatusOutput(cfgBase, sharesDir)
	var buf bytes.Buffer
	if err := writeJSON(&buf, out); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("status JSON invalid: %v\n%s", err, buf.String())
	}
	if _, ok := decoded["pens"].([]any); !ok {
		t.Fatalf("pens should be JSON array, got %T", decoded["pens"])
	}
	if _, ok := decoded["shares"].([]any); !ok {
		t.Fatalf("shares should be JSON array, got %T", decoded["shares"])
	}

	// 2. Doctor flags corrupt pen configs as fail and legacy duplicates as warn.
	corruptDir := filepath.Join(cfgBase, "broken.pens.example.com")
	_ = os.MkdirAll(corruptDir, 0o700)
	_ = os.WriteFile(filepath.Join(corruptDir, "config.json"), []byte("{bad"), 0o600)

	rep := runDoctor(cfgBase, sharesDir, "/opt/homebrew/Cellar/hogman/1.0/bin/hogman")
	if rep.OK {
		t.Fatal("doctor should report OK=false with corrupt pen config")
	}
	foundCorrupt := false
	foundBrew := false
	for _, c := range rep.Checks {
		if c.Name == "pen-configs" && c.Status == "fail" {
			foundCorrupt = true
		}
		if c.Name == "binary" && strings.Contains(c.Detail, "Homebrew") {
			foundBrew = true
		}
	}
	if !foundCorrupt || !foundBrew {
		t.Fatalf("unexpected doctor checks: %+v", rep.Checks)
	}

	// 3. CLI flag routing for --json on status, share list, doctor + hogman alias.
	var gotStatusJSON, gotShareJSON, gotDoctorJSON bool
	h := cliHandlers{
		status:    func(o options) error { gotStatusJSON = o.jsonOut; return nil },
		shareList: func(_ string, asJSON bool) error { gotShareJSON = asJSON; return nil },
		doctor:    func(o options) error { gotDoctorJSON = o.jsonOut; return nil },
	}
	if rc := runCLI([]string{"status", "--json"}, h); rc != 0 || !gotStatusJSON {
		t.Fatalf("status --json: rc=%d got=%v", rc, gotStatusJSON)
	}
	if rc := runCLI([]string{"share", "list", "--json"}, h); rc != 0 || !gotShareJSON {
		t.Fatalf("share list --json: rc=%d got=%v", rc, gotShareJSON)
	}
	if rc := runCLI([]string{"doctor", "--json"}, h); rc != 0 || !gotDoctorJSON {
		t.Fatalf("doctor --json: rc=%d got=%v", rc, gotDoctorJSON)
	}
	if cliBinaryName() != "hogman" {
		t.Fatalf("cliBinaryName() = %q, want hogman", cliBinaryName())
	}
}

func TestUpgradeFromLegacyHogmanJoinLayout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if runtime.GOOS == "windows" {
		t.Setenv("AppData", filepath.Join(home, "AppData"))
	}

	cfgBase := hogmanConfigBase()
	legacyName := legacyBinaryName(runtime.GOOS)
	canonBin := canonicalBinaryPath(cfgBase)

	// 1. Seed a full legacy hogman-join device layout:
	//    - Running pen "alpha" with per-pen hogman-join binary + registered login item
	//    - Stopped pen "beta" with per-pen hogman-join binary + registered login item
	//    - Running managed share "blog.alpha" with per-share hogman-join binary + registered login item
	//    - Legacy regular-file copy at <configBase>/bin/hogman-native-host
	alphaZone := "alpha.pens.example.com"
	betaZone := "beta.pens.example.com"
	alphaDir := stateDir(alphaZone)
	betaDir := stateDir(betaZone)
	shareCfg := &shareConfig{
		Name:        "blog",
		Zone:        alphaZone,
		LoginServer: "https://alpha.gate.example.com",
		Target:      "http://127.0.0.1:3000",
	}
	blogDir := shareDir(alphaZone, "blog")
	for _, d := range []string{alphaDir, betaDir, blogDir, filepath.Dir(canonBin)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alphaCfg := &agentConfig{Zone: alphaZone, LoginServer: "https://alpha.gate.example.com"}
	betaCfg := &agentConfig{Zone: betaZone, LoginServer: "https://beta.gate.example.com"}
	if err := alphaCfg.save(alphaDir); err != nil {
		t.Fatal(err)
	}
	if err := betaCfg.save(betaDir); err != nil {
		t.Fatal(err)
	}
	if err := shareCfg.save(blogDir); err != nil {
		t.Fatal(err)
	}

	alphaLegacyBin := filepath.Join(alphaDir, legacyName)
	betaLegacyBin := filepath.Join(betaDir, legacyName)
	blogLegacyBin := filepath.Join(blogDir, legacyName)
	for _, p := range []string{alphaLegacyBin, betaLegacyBin, blogLegacyBin} {
		if err := os.WriteFile(p, []byte("old-hogman-join-binary"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	nhBin := nativeHostBinaryPath(cfgBase)
	if err := os.WriteFile(nhBin, []byte("old-native-host-copy"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Write legacy login items pointing at the per-pen/per-share hogman-join binaries.
	if runtime.GOOS != "windows" {
		if err := rewriteAgentService(alphaLegacyBin, alphaDir, alphaCfg); err != nil {
			t.Fatal(err)
		}
		if err := rewriteAgentService(betaLegacyBin, betaDir, betaCfg); err != nil {
			t.Fatal(err)
		}
		if err := rewriteShareService(blogLegacyBin, blogDir, shareCfg); err != nil {
			t.Fatal(err)
		}
	}

	serviceFiles := func() []string {
		switch runtime.GOOS {
		case "darwin":
			m, _ := filepath.Glob(filepath.Join(home, "Library", "LaunchAgents", "*hogman*"))
			return m
		case "linux":
			m, _ := filepath.Glob(filepath.Join(home, ".config", "systemd", "user", "*hogman*"))
			return m
		default:
			return nil
		}
	}
	beforeUnits := serviceFiles()
	if runtime.GOOS != "windows" && len(beforeUnits) != 3 {
		t.Fatalf("expected 3 legacy login items before upgrade, got %d: %v", len(beforeUnits), beforeUnits)
	}

	// Stage the new canonical hogman binary + native-host symlink.
	newPayload := []byte("new-hogman-canonical-binary")
	srcPath := filepath.Join(t.TempDir(), "downloaded-hogman")
	if err := os.WriteFile(srcPath, newPayload, 0o755); err != nil {
		t.Fatal(err)
	}
	wantHex, err := fileSHA256(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := stageAndVerify(srcPath, canonBin, wantHex); err != nil {
		t.Fatalf("stage canonical binary: %v", err)
	}
	if err := installNativeHostBinary(canonBin, nhBin); err != nil {
		t.Fatalf("install native host binary: %v", err)
	}

	// 2. First verify rollback on failed restart: if restartNew fails, restartOld
	//    brings alpha back up on alphaLegacyBin with zero gap and preserves it.
	var rolledBackBin string
	rollbackOps := penUpdateOps{
		isRunning:  func(string, *agentConfig) bool { return true },
		hasService: func(string) bool { return true },
		stop:       func(string, *agentConfig) {},
		restartNew: func(*penTarget, string, bool, options) error { return errors.New("boom") },
		restartOld: func(_ *penTarget, bin string, _ bool, _ options) error {
			rolledBackBin = bin
			return nil
		},
		rewriteService: rewriteAgentService,
	}
	alphaTarget := &penTarget{zone: alphaZone, dir: alphaDir, cfg: alphaCfg}
	betaTarget := &penTarget{zone: betaZone, dir: betaDir, cfg: betaCfg}
	blogTarget := &shareTargetDir{zone: alphaZone, name: "blog", dir: blogDir, cfg: shareCfg}
	if err := migrateAndRestartPen(alphaTarget, canonBin, alphaLegacyBin, "/tmp/hogman-cli", options{}, rollbackOps); err == nil {
		t.Fatal("expected error when restartNew fails")
	}
	if rolledBackBin != alphaLegacyBin {
		t.Fatalf("rollback restarted %q, want legacy %q", rolledBackBin, alphaLegacyBin)
	}
	if _, err := os.Stat(alphaLegacyBin); err != nil {
		t.Fatalf("legacy binary should be preserved after rollback: %v", err)
	}

	// 3. Now run the full upgrade migration for running alpha, stopped beta, and running blog share.
	var restartedPens []string
	penOps := penUpdateOps{
		isRunning: func(dir string, _ *agentConfig) bool { return dir == alphaDir },
		hasService: func(zone string) bool {
			if runtime.GOOS == "windows" {
				return false
			}
			return serviceConfigured(zone)
		},
		stop: func(string, *agentConfig) {},
		restartNew: func(p *penTarget, bin string, hadService bool, _ options) error {
			if bin != canonBin {
				return errors.New("expected canonical binary")
			}
			if hadService && runtime.GOOS != "windows" {
				if err := rewriteAgentService(bin, p.dir, p.cfg); err != nil {
					return err
				}
			}
			restartedPens = append(restartedPens, p.zone+":"+bin)
			return nil
		},
		restartOld:     func(*penTarget, string, bool, options) error { return nil },
		rewriteService: rewriteAgentService,
	}
	var restartedShares []string
	shOps := shareUpdateOps{
		isRunning: func(dir string) bool { return dir == blogDir },
		hasService: func(c *shareConfig) bool {
			if runtime.GOOS == "windows" {
				return true
			}
			return shareServiceConfigured(c)
		},
		stop: func(string, *shareConfig) {},
		restartNew: func(s *shareTargetDir, bin string, _ options) error {
			if bin != canonBin {
				return errors.New("expected canonical binary")
			}
			if runtime.GOOS != "windows" {
				if err := rewriteShareService(bin, s.dir, s.cfg); err != nil {
					return err
				}
			}
			restartedShares = append(restartedShares, s.cfg.fqdn()+":"+bin)
			return nil
		},
		restartOld:     func(*shareTargetDir, string, options) error { return nil },
		rewriteService: rewriteShareService,
	}

	if err := migrateAndRestartPen(alphaTarget, canonBin, alphaLegacyBin, "/tmp/hogman-cli", options{}, penOps); err != nil {
		t.Fatalf("migrate alpha: %v", err)
	}
	if err := migrateAndRestartPen(betaTarget, canonBin, betaLegacyBin, "/tmp/hogman-cli", options{}, penOps); err != nil {
		t.Fatalf("migrate beta (stopped): %v", err)
	}
	if err := migrateAndRestartShare(blogTarget, canonBin, blogLegacyBin, "/tmp/hogman-cli", options{}, shOps); err != nil {
		t.Fatalf("migrate blog share: %v", err)
	}

	// Assert running agent and share came back up under the canonical hogman binary.
	if len(restartedPens) != 1 || restartedPens[0] != alphaZone+":"+canonBin {
		t.Fatalf("restartedPens = %v, want [%s:%s]", restartedPens, alphaZone, canonBin)
	}
	if len(restartedShares) != 1 || restartedShares[0] != "blog."+alphaZone+":"+canonBin {
		t.Fatalf("restartedShares = %v, want [blog.%s:%s]", restartedShares, alphaZone, canonBin)
	}

	// Assert all legacy per-pen and per-share hogman-join binaries were removed.
	for _, p := range []string{alphaLegacyBin, betaLegacyBin, blogLegacyBin} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("legacy binary %s still exists after upgrade (err=%v)", p, err)
		}
	}

	// Assert native host is now a symlink to canonical hogman on Unix.
	if runtime.GOOS != "windows" {
		fi, err := os.Lstat(nhBin)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 || !sameFilePath(canonBin, nhBin) {
			t.Fatalf("native host %s not migrated to symlink -> %s (err=%v)", nhBin, canonBin, err)
		}

		// Assert zero orphaned login items and every login item now points to canonBin (never hogman-join).
		afterUnits := serviceFiles()
		if len(afterUnits) != len(beforeUnits) {
			t.Fatalf("login item count changed (%d -> %d): before=%v after=%v", len(beforeUnits), len(afterUnits), beforeUnits, afterUnits)
		}
		for _, u := range afterUnits {
			b, err := os.ReadFile(u)
			if err != nil {
				t.Fatalf("read login item %s: %v", u, err)
			}
			text := string(b)
			if strings.Contains(text, "hogman-join") {
				t.Errorf("login item %s still references hogman-join:\n%s", u, text)
			}
			if !strings.Contains(text, canonBin) {
				t.Errorf("login item %s does not reference canonical %s:\n%s", u, canonBin, text)
			}
		}
	}
}
