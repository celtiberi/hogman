package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
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
		{`C:\Users\alice\AppData\Local\Microsoft\WinGet\Packages\Galderwood.Hogman\hogman.exe`, "windows", "winget", true},
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

	// 2. First verify rollback on failed restart: if restartNew fails, ops.stop
	//    runs BEFORE restartOld (so a partially started new agent is stopped),
	//    alpha comes back up on alphaLegacyBin with zero gap, and alphaLegacyBin is kept.
	var rolledBackBin string
	var rollbackSeq []string
	rollbackOps := penUpdateOps{
		isRunning:  func(string, *agentConfig) bool { return true },
		hasService: func(string) bool { return true },
		stop:       func(string, *agentConfig) { rollbackSeq = append(rollbackSeq, "stop") },
		restartNew: func(*penTarget, string, bool, options) error {
			rollbackSeq = append(rollbackSeq, "restartNew")
			return errors.New("boom")
		},
		restartOld: func(_ *penTarget, bin string, _ bool, _ options) error {
			rollbackSeq = append(rollbackSeq, "restartOld")
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
	if strings.Join(rollbackSeq, ",") != "stop,restartNew,stop,restartOld" {
		t.Fatalf("rollback sequence = %v, want [stop restartNew stop restartOld]", rollbackSeq)
	}
	if _, err := os.Stat(alphaLegacyBin); err != nil {
		t.Fatalf("legacy binary should be preserved after rollback: %v", err)
	}
	if interrupted, _ := readUpdatingMarker(alphaDir); interrupted {
		t.Fatal("updating marker should be cleared after successful rollback")
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

func TestInterruptedUpdateRecoveryAndVersionGuard(t *testing.T) {
	// 1. Interrupted update recovery: if .updating ("service") was left behind
	//    after stopAgent removed the login item and the process died before
	//    restartNew, re-running migrateAndRestartPen restores the agent & service.
	dir := t.TempDir()
	cfg := &agentConfig{Zone: "interrupted.pens.example.com"}
	legacy := filepath.Join(dir, legacyBinaryName(runtime.GOOS))
	if err := os.WriteFile(legacy, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeUpdatingMarker(dir, true)

	var restarted bool
	var restoredService bool
	ops := penUpdateOps{
		isRunning:  func(string, *agentConfig) bool { return false },
		hasService: func(string) bool { return false },
		stop:       func(string, *agentConfig) {},
		restartNew: func(_ *penTarget, _ string, hadService bool, _ options) error {
			restarted = true
			restoredService = hadService
			return nil
		},
	}
	p := &penTarget{zone: cfg.Zone, dir: dir, cfg: cfg}
	if err := migrateAndRestartPen(p, "/tmp/canon/hogman", legacy, "/tmp/self", options{}, ops); err != nil {
		t.Fatalf("interrupted recovery failed: %v", err)
	}
	if !restarted || !restoredService {
		t.Fatalf("restarted=%v restoredService=%v, want true/true", restarted, restoredService)
	}
	if interrupted, _ := readUpdatingMarker(dir); interrupted {
		t.Fatal(".updating marker was not cleared after recovery")
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy binary should be removed after recovery (err=%v)", err)
	}

	// 2. Version comparison helper for canonical binary downgrade protection.
	for _, tc := range []struct {
		a, b    string
		wantCmp int
		wantOK  bool
	}{
		{"2026.11.24", "2026.11.23", 1, true},
		{"2026.11.23", "2026.11.24", -1, true},
		{"2026.11.24-d17d2f9", "2026.11.23-abc1234", 1, true},
		{"2026.11.23-abc1234", "2026.11.24-d17d2f9", -1, true},
		{"v2026.11.24-d17d2f9", "2026.11.24-d17d2f9", 0, true},
		{"2026.11.24-d17d2f9", "2026.11.24-deadbee", 0, false},
		{"2026.11.24-d17d2f9", "2026.11.24", 0, false},
		{"v0.2.0", "0.2.0", 0, true},
		{"2026.11.24-rc1", "2026.11.23", 1, true},
		{"dev", "2026.11.24", 0, false},
		{"", "2026.11.24", 0, false},
	} {
		got, ok := compareReleaseVersions(tc.a, tc.b)
		if ok != tc.wantOK || got != tc.wantCmp {
			t.Errorf("compareReleaseVersions(%q, %q) = (%d, %v), want (%d, %v)", tc.a, tc.b, got, ok, tc.wantCmp, tc.wantOK)
		}
	}
}

func TestUpdateContinuesPastUnreachablePenAndLegacySHA256MessageI10(t *testing.T) {
	// 1. Two legacy pens where the first pen's server is unreachable and the
	// second pen is healthy: pen 1 rewrites its login item without waiting for
	// restartNew, and pen 2 still migrates and restarts cleanly.
	tmp := t.TempDir()
	deadDir := filepath.Join(tmp, "aaa-dead.example.test")
	goodDir := filepath.Join(tmp, "zzz-good.example.test")
	_ = os.MkdirAll(deadDir, 0o700)
	_ = os.MkdirAll(goodDir, 0o700)
	deadLegacy := filepath.Join(deadDir, "hogman-join")
	goodLegacy := filepath.Join(goodDir, "hogman-join")
	_ = os.WriteFile(deadLegacy, []byte("old"), 0o755)
	_ = os.WriteFile(goodLegacy, []byte("old"), 0o755)

	pens := []penTarget{
		{zone: "aaa-dead.example.test", dir: deadDir, cfg: &agentConfig{Zone: "aaa-dead.example.test", LoginServer: "https://dead.example.test"}},
		{zone: "zzz-good.example.test", dir: goodDir, cfg: &agentConfig{Zone: "zzz-good.example.test", LoginServer: "https://good.example.test"}},
	}
	var stopped, startedNoWait, restarted []string
	ops := penUpdateOps{
		isRunning:  func(string, *agentConfig) bool { return true },
		hasService: func(string) bool { return true },
		probeReachable: func(p *penTarget, _ options) error {
			if p.zone == "aaa-dead.example.test" {
				return errors.New("dial tcp: connection refused")
			}
			return nil
		},
		stop: func(_ string, c *agentConfig) { stopped = append(stopped, c.Zone) },
		startNoWait: func(p *penTarget, bin string, _ bool, _ options) error {
			startedNoWait = append(startedNoWait, p.zone+":"+bin)
			return nil
		},
		restartNew: func(p *penTarget, _ string, _ bool, _ options) error {
			restarted = append(restarted, p.zone)
			return nil
		},
	}

	results := migratePensForUpdate(pens, "/tmp/canon/hogman", "/tmp/self", func(dir string) string {
		p := filepath.Join(dir, "hogman-join")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}, true, options{}, ops)

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "hogman leave aaa-dead.example.test") {
		t.Fatalf("dead pen result = %v, want unreachable error with hogman leave hint", results[0].Err)
	}
	if results[1].Err != nil {
		t.Fatalf("healthy pen should still migrate cleanly, got err=%v", results[1].Err)
	}
	if len(restarted) != 1 || restarted[0] != "zzz-good.example.test" {
		t.Fatalf("restarted = %v, want only [zzz-good.example.test]", restarted)
	}
	if len(startedNoWait) != 1 || startedNoWait[0] != "aaa-dead.example.test:/tmp/canon/hogman" {
		t.Fatalf("startedNoWait = %v, want unreachable pen started on canonical bin without waiting", startedNoWait)
	}
	if _, err := os.Stat(deadLegacy); !os.IsNotExist(err) {
		t.Fatalf("dead pen legacy copy should be removed after moving login item (err=%v)", err)
	}
	if _, err := os.Stat(goodLegacy); !os.IsNotExist(err) {
		t.Fatalf("healthy pen legacy copy should be removed after migration (err=%v)", err)
	}

	// 2. Legacy pen SHA256SUMS listing hogman-join-* gives an actionable message.
	legacySums := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  hogman-join-Linux-x86_64\n")
	if _, err := parseSHA256SUMS(legacySums, "hogman-Linux-x86_64"); err == nil ||
		!strings.Contains(err.Error(), "older release") ||
		!strings.Contains(err.Error(), "hogman update") {
		t.Fatalf("legacy SHA256SUMS err = %v, want older-release + plain hogman update hint", err)
	}

	// 3. probePenLoginServer probes /hogman/v1/network (the real public route used by fetchNetwork).
	var statusCode int = http.StatusOK
	var gotPath string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path != "/hogman/v1/network" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(`{"zone":"lab.example.test"}`))
	}))
	defer ts.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	probeTarget := &penTarget{
		zone: "lab.example.test",
		cfg:  &agentConfig{Zone: "lab.example.test", LoginServer: ts.URL, ControlCA: string(caPEM)},
	}
	if err := probePenLoginServer(probeTarget, options{}); err != nil {
		t.Fatalf("probePenLoginServer against live /hogman/v1/network failed: %v (path=%q)", err, gotPath)
	}
	if gotPath != "/hogman/v1/network" {
		t.Fatalf("probed path = %q, want /hogman/v1/network", gotPath)
	}
	statusCode = http.StatusServiceUnavailable
	if err := probePenLoginServer(probeTarget, options{}); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("probePenLoginServer on 503 = %v, want 503 error", err)
	}
}
