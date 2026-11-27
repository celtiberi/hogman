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

	"hogman/join/internal/fsutil"
	"hogman/join/internal/nativehost"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
	"hogman/join/internal/updater"
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
	binA, err := installedBinary(state.StateDir("alpha.pens.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	binB, err := installedBinary(state.StateDir("beta.pens.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	wantCanon := state.CanonicalBinaryPath(state.ConfigBase())
	if binA != wantCanon || binB != wantCanon {
		t.Fatalf("installedBinary returned (%q, %q), want single canonical %q", binA, binB, wantCanon)
	}

	// Atomic migration: legacy per-pen binary is KEPT if restartNew fails,
	// and REMOVED only after restartNew succeeds on canonicalBin.
	penDir := state.StateDir("alpha.pens.example.com")
	_ = os.MkdirAll(penDir, 0o700)
	legacy := filepath.Join(penDir, state.InstalledBinaryName(runtime.GOOS))
	if err := os.WriteFile(legacy, []byte("legacy-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &updater.PenTarget{Zone: "alpha.pens.example.com", Dir: penDir, Cfg: &state.AgentConfig{Zone: "alpha.pens.example.com"}}

	failOps := updater.PenOps{
		IsRunning:  func(string, *state.AgentConfig) bool { return true },
		HasService: func(string) bool { return true },
		Stop:       func(string, *state.AgentConfig) {},
		RestartNew: func(_ *updater.PenTarget, bin string, _ bool, _ updater.Options) error {
			if bin != wantCanon {
				t.Errorf("restartNew got bin=%q, want canonical %q", bin, wantCanon)
			}
			return errors.New("start failed")
		},
	}
	if err := updater.MigrateAndRestartPen(p, wantCanon, legacy, "/tmp/other-self", updater.Options{}, failOps, ui.Default()); err == nil {
		t.Fatal("expected restart error")
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("legacy binary was deleted despite failed restart: %v", err)
	}

	okOps := failOps
	okOps.RestartNew = func(_ *updater.PenTarget, bin string, _ bool, _ updater.Options) error {
		if bin != wantCanon {
			t.Errorf("restartNew got bin=%q, want canonical %q", bin, wantCanon)
		}
		return nil
	}
	if err := updater.MigrateAndRestartPen(p, wantCanon, legacy, "/tmp/other-self", updater.Options{}, okOps, ui.Default()); err != nil {
		t.Fatalf("MigrateAndRestartPen failed: %v", err)
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
		wantCmd string
		wantOK  bool
	}{
		{"/opt/homebrew/Cellar/hogman/2026.11.23/bin/hogman", "darwin", "Homebrew", "brew upgrade hogman", true},
		{"/usr/local/Cellar/hogman/1.0/bin/hogman", "darwin", "Homebrew", "brew upgrade hogman", true},
		{"/home/linuxbrew/.linuxbrew/Cellar/hogman/1.0/bin/hogman", "linux", "Homebrew", "brew upgrade hogman", true},
		{"/usr/bin/hogman", "linux", "your system package manager", "upgrade via your OS package manager", true},
		{`C:\Users\alice\scoop\apps\hogman\current\hogman.exe`, "windows", "Scoop", "scoop update hogman", true},
		{`C:\Users\alice\AppData\Local\Microsoft\WinGet\Packages\Example.Hogman\hogman.exe`, "windows", "winget", "winget upgrade --id Example.Hogman", true},
		{`C:\Users\alice\AppData\Local\Microsoft\WinGet\Packages\Example.Hogman_Microsoft.Winget.Source_8wekyb3d8bbwe\hogman.exe`, "windows", "winget", "winget upgrade --id Example.Hogman", true},
		{`C:\Users\alice\AppData\Local\Microsoft\WinGet\Packages\bad folder!\hogman.exe`, "windows", "winget", "winget upgrade hogman", true},
		{`C:\Users\alice\AppData\Local\Microsoft\WinGet\Packages\_onlysource\hogman.exe`, "windows", "winget", "winget upgrade hogman", true},
		{`C:\Users\alice\AppData\Local\Microsoft\WinGet\Packages\hogman.exe`, "windows", "winget", "winget upgrade hogman", true},
		{"/tmp/hogman", "darwin", "", "", false},
		{"/usr/local/bin/hogman", "linux", "", "", false},
	} {
		mgr, cmd, ok := updater.DetectPackageManager(tc.path, tc.goos)
		if ok != tc.wantOK || mgr != tc.wantMgr || cmd != tc.wantCmd {
			t.Errorf("DetectPackageManager(%q, %q) = (%q, %q, %v), want (%q, %q, %v)", tc.path, tc.goos, mgr, cmd, ok, tc.wantMgr, tc.wantCmd, tc.wantOK)
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
	// Even if an old regular-file copy exists, nativehost.InstallBinary replaces it with a symlink.
	if err := os.WriteFile(hostPath, []byte("old-copy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := nativehost.InstallBinary(canon, hostPath); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(hostPath)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink at %s, got mode=%v err=%v", hostPath, fi.Mode(), err)
	}
	if !fsutil.SameFilePath(canon, hostPath) {
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
	if err := (&ui.UI{Out: &buf}).WriteJSON(out); err != nil {
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

	// 2b. Doctor preserves all lines of a 3-line share command/runtime error.
	errShareDir := filepath.Join(sharesDir, "alpha.pens.example.com", "broken")
	_ = os.MkdirAll(errShareDir, 0o700)
	if err := (&state.ShareConfig{Name: "broken", Zone: "alpha.pens.example.com", Target: "http://127.0.0.1:3000"}).Save(errShareDir); err != nil {
		t.Fatal(err)
	}
	state.WriteShareStatus(errShareDir, "error", "line one\nline two\nline three")
	rep2 := runDoctor(cfgBase, sharesDir, "/opt/homebrew/Cellar/hogman/1.0/bin/hogman")
	found3Line := false
	for _, c := range rep2.Checks {
		if c.Name == "share:broken.alpha.pens.example.com" && c.Status == "fail" && c.Detail == "line one; line two; line three" {
			found3Line = true
		}
	}
	if !found3Line {
		t.Fatalf("doctor did not preserve all 3 lines of share error: %+v", rep2.Checks)
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

	cfgBase := state.ConfigBase()
	legacyName := state.LegacyBinaryName(runtime.GOOS)
	canonBin := state.CanonicalBinaryPath(cfgBase)

	// 1. Seed a full legacy hogman-join device layout:
	//    - Running pen "alpha" with per-pen hogman-join binary + registered login item
	//    - Stopped pen "beta" with per-pen hogman-join binary + registered login item
	//    - Running managed share "blog.alpha" with per-share hogman-join binary + registered login item
	//    - Legacy regular-file copy at <configBase>/bin/hogman-native-host
	alphaZone := "alpha.pens.example.com"
	betaZone := "beta.pens.example.com"
	alphaDir := state.StateDir(alphaZone)
	betaDir := state.StateDir(betaZone)
	shareCfg := &state.ShareConfig{
		Name:        "blog",
		Zone:        alphaZone,
		LoginServer: "https://alpha.gate.example.com",
		Target:      "http://127.0.0.1:3000",
	}
	blogDir := state.ShareDir(alphaZone, "blog")
	for _, d := range []string{alphaDir, betaDir, blogDir, filepath.Dir(canonBin)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alphaCfg := &state.AgentConfig{Zone: alphaZone, LoginServer: "https://alpha.gate.example.com"}
	betaCfg := &state.AgentConfig{Zone: betaZone, LoginServer: "https://beta.gate.example.com"}
	if err := alphaCfg.Save(alphaDir); err != nil {
		t.Fatal(err)
	}
	if err := betaCfg.Save(betaDir); err != nil {
		t.Fatal(err)
	}
	if err := shareCfg.Save(blogDir); err != nil {
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
	nhBin := nativehost.BinaryPath(cfgBase)
	if err := os.WriteFile(nhBin, []byte("old-native-host-copy"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Write legacy login items pointing at the per-pen/per-share hogman-join binaries.
	if runtime.GOOS != "windows" {
		if err := platform.RewriteAgentService(alphaLegacyBin, alphaDir, alphaCfg); err != nil {
			t.Fatal(err)
		}
		if err := platform.RewriteAgentService(betaLegacyBin, betaDir, betaCfg); err != nil {
			t.Fatal(err)
		}
		if err := platform.RewriteShareService(blogLegacyBin, blogDir, shareCfg); err != nil {
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
	wantHex, err := fsutil.FileSHA256(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := updater.StageAndVerify(srcPath, canonBin, wantHex); err != nil {
		t.Fatalf("stage canonical binary: %v", err)
	}
	if err := nativehost.InstallBinary(canonBin, nhBin); err != nil {
		t.Fatalf("install native host binary: %v", err)
	}

	// 2. First verify rollback on failed restart: if RestartNew fails, ops.Stop
	//    runs BEFORE RestartOld (so a partially started new agent is stopped),
	//    alpha comes back up on alphaLegacyBin with zero gap, and alphaLegacyBin is kept.
	var rolledBackBin string
	var rollbackSeq []string
	rollbackOps := updater.PenOps{
		IsRunning:  func(string, *state.AgentConfig) bool { return true },
		HasService: func(string) bool { return true },
		Stop:       func(string, *state.AgentConfig) { rollbackSeq = append(rollbackSeq, "stop") },
		RestartNew: func(*updater.PenTarget, string, bool, updater.Options) error {
			rollbackSeq = append(rollbackSeq, "restartNew")
			return errors.New("boom")
		},
		RestartOld: func(_ *updater.PenTarget, bin string, _ bool, _ updater.Options) error {
			rollbackSeq = append(rollbackSeq, "restartOld")
			rolledBackBin = bin
			return nil
		},
		RewriteService: platform.RewriteAgentService,
	}
	alphaTarget := &updater.PenTarget{Zone: alphaZone, Dir: alphaDir, Cfg: alphaCfg}
	betaTarget := &updater.PenTarget{Zone: betaZone, Dir: betaDir, Cfg: betaCfg}
	blogTarget := &updater.ShareTargetDir{Zone: alphaZone, Name: "blog", Dir: blogDir, Cfg: shareCfg}
	if err := updater.MigrateAndRestartPen(alphaTarget, canonBin, alphaLegacyBin, "/tmp/hogman-cli", updater.Options{}, rollbackOps, ui.Default()); err == nil {
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
	if interrupted, _ := state.ReadUpdatingMarker(alphaDir); interrupted {
		t.Fatal("updating marker should be cleared after successful rollback")
	}

	// 3. Now run the full upgrade migration for running alpha, stopped beta, and running blog share.
	var restartedPens []string
	penOps := updater.PenOps{
		IsRunning: func(dir string, _ *state.AgentConfig) bool { return dir == alphaDir },
		HasService: func(zone string) bool {
			if runtime.GOOS == "windows" {
				return false
			}
			return platform.ServiceConfigured(zone)
		},
		Stop: func(string, *state.AgentConfig) {},
		RestartNew: func(p *updater.PenTarget, bin string, hadService bool, _ updater.Options) error {
			if bin != canonBin {
				return errors.New("expected canonical binary")
			}
			if hadService && runtime.GOOS != "windows" {
				if err := platform.RewriteAgentService(bin, p.Dir, p.Cfg); err != nil {
					return err
				}
			}
			restartedPens = append(restartedPens, p.Zone+":"+bin)
			return nil
		},
		RestartOld:     func(*updater.PenTarget, string, bool, updater.Options) error { return nil },
		RewriteService: platform.RewriteAgentService,
	}
	var restartedShares []string
	shOps := updater.ShareOps{
		IsRunning: func(dir string) bool { return dir == blogDir },
		HasService: func(c *state.ShareConfig) bool {
			if runtime.GOOS == "windows" {
				return true
			}
			return platform.ShareServiceConfigured(c)
		},
		Stop: func(string, *state.ShareConfig) {},
		RestartNew: func(s *updater.ShareTargetDir, bin string, _ updater.Options) error {
			if bin != canonBin {
				return errors.New("expected canonical binary")
			}
			if runtime.GOOS != "windows" {
				if err := platform.RewriteShareService(bin, s.Dir, s.Cfg); err != nil {
					return err
				}
			}
			restartedShares = append(restartedShares, s.Cfg.FQDN()+":"+bin)
			return nil
		},
		RestartOld:     func(*updater.ShareTargetDir, string, updater.Options) error { return nil },
		RewriteService: platform.RewriteShareService,
	}

	if err := updater.MigrateAndRestartPen(alphaTarget, canonBin, alphaLegacyBin, "/tmp/hogman-cli", updater.Options{}, penOps, ui.Default()); err != nil {
		t.Fatalf("migrate alpha: %v", err)
	}
	if err := updater.MigrateAndRestartPen(betaTarget, canonBin, betaLegacyBin, "/tmp/hogman-cli", updater.Options{}, penOps, ui.Default()); err != nil {
		t.Fatalf("migrate beta (stopped): %v", err)
	}
	if err := updater.MigrateAndRestartShare(blogTarget, canonBin, blogLegacyBin, "/tmp/hogman-cli", updater.Options{}, shOps, ui.Default()); err != nil {
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
		if err != nil || fi.Mode()&os.ModeSymlink == 0 || !fsutil.SameFilePath(canonBin, nhBin) {
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
	cfg := &state.AgentConfig{Zone: "interrupted.pens.example.com"}
	legacy := filepath.Join(dir, state.LegacyBinaryName(runtime.GOOS))
	if err := os.WriteFile(legacy, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	state.WriteUpdatingMarker(dir, true)

	var restarted bool
	var restoredService bool
	ops := updater.PenOps{
		IsRunning:  func(string, *state.AgentConfig) bool { return false },
		HasService: func(string) bool { return false },
		Stop:       func(string, *state.AgentConfig) {},
		RestartNew: func(_ *updater.PenTarget, _ string, hadService bool, _ updater.Options) error {
			restarted = true
			restoredService = hadService
			return nil
		},
	}
	p := &updater.PenTarget{Zone: cfg.Zone, Dir: dir, Cfg: cfg}
	if err := updater.MigrateAndRestartPen(p, "/tmp/canon/hogman", legacy, "/tmp/self", updater.Options{}, ops, ui.Default()); err != nil {
		t.Fatalf("interrupted recovery failed: %v", err)
	}
	if !restarted || !restoredService {
		t.Fatalf("restarted=%v restoredService=%v, want true/true", restarted, restoredService)
	}
	if interrupted, _ := state.ReadUpdatingMarker(dir); interrupted {
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
		got, ok := updater.CompareReleaseVersions(tc.a, tc.b)
		if ok != tc.wantOK || got != tc.wantCmp {
			t.Errorf("CompareReleaseVersions(%q, %q) = (%d, %v), want (%d, %v)", tc.a, tc.b, got, ok, tc.wantCmp, tc.wantOK)
		}
	}
}

func TestUpdateContinuesPastUnreachablePenAndLegacySHA256Message(t *testing.T) {
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

	pens := []updater.PenTarget{
		{Zone: "aaa-dead.example.test", Dir: deadDir, Cfg: &state.AgentConfig{Zone: "aaa-dead.example.test", LoginServer: "https://dead.example.test"}},
		{Zone: "zzz-good.example.test", Dir: goodDir, Cfg: &state.AgentConfig{Zone: "zzz-good.example.test", LoginServer: "https://good.example.test"}},
	}
	var stopped, startedNoWait, restarted []string
	ops := updater.PenOps{
		IsRunning:  func(string, *state.AgentConfig) bool { return true },
		HasService: func(string) bool { return true },
		ProbeReachable: func(p *updater.PenTarget, _ updater.Options) error {
			if p.Zone == "aaa-dead.example.test" {
				return errors.New("dial tcp: connection refused")
			}
			return nil
		},
		Stop: func(_ string, c *state.AgentConfig) { stopped = append(stopped, c.Zone) },
		StartNoWait: func(p *updater.PenTarget, bin string, _ bool, _ updater.Options) error {
			startedNoWait = append(startedNoWait, p.Zone+":"+bin)
			return nil
		},
		RestartNew: func(p *updater.PenTarget, _ string, _ bool, _ updater.Options) error {
			restarted = append(restarted, p.Zone)
			return nil
		},
	}

	results := updater.MigratePens(pens, "/tmp/canon/hogman", "/tmp/self", func(dir string) string {
		p := filepath.Join(dir, "hogman-join")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}, true, updater.Options{}, ops, ui.Default())

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
	if _, err := updater.ParseSHA256SUMS(legacySums, "hogman-Linux-x86_64"); err == nil ||
		!strings.Contains(err.Error(), "older release") ||
		!strings.Contains(err.Error(), "hogman update") {
		t.Fatalf("legacy SHA256SUMS err = %v, want older-release + plain hogman update hint", err)
	}

	// 3. ProbePenLoginServer probes /hogman/v1/network (the real public route used by fetchNetwork).
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
	probeTarget := &updater.PenTarget{
		Zone: "lab.example.test",
		Cfg:  &state.AgentConfig{Zone: "lab.example.test", LoginServer: ts.URL, ControlCA: string(caPEM)},
	}
	if err := updater.ProbePenLoginServer(probeTarget, updater.Options{}); err != nil {
		t.Fatalf("ProbePenLoginServer against live /hogman/v1/network failed: %v (path=%q)", err, gotPath)
	}
	if gotPath != "/hogman/v1/network" {
		t.Fatalf("probed path = %q, want /hogman/v1/network", gotPath)
	}
	statusCode = http.StatusServiceUnavailable
	if err := updater.ProbePenLoginServer(probeTarget, updater.Options{}); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("ProbePenLoginServer on 503 = %v, want 503 error", err)
	}
}

func TestInstallNativeHostRespectsCanonicalBinaryDowngradeGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell stub binary test")
	}
	home := t.TempDir()
	configBase := filepath.Join(home, ".config", "hogman")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	canon := state.CanonicalBinaryPath(configBase)
	if err := os.MkdirAll(filepath.Dir(canon), 0o700); err != nil {
		t.Fatal(err)
	}
	newerStub := "#!/bin/sh\necho 'hogman 2099.01.01-bbbbbbb linux/amd64'\n"
	if err := os.WriteFile(canon, []byte(newerStub), 0o755); err != nil {
		t.Fatal(err)
	}
	origVer := version
	version = "2025.01.01-aaaaaaa"
	t.Cleanup(func() { version = origVer })

	if _, _, err := nativehost.Install(configBase, ensureCanonicalBinary, nil, nil, nil); err != nil {
		t.Fatalf("nativehost.Install failed: %v", err)
	}
	got, err := os.ReadFile(canon)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != newerStub {
		t.Fatalf("installNativeHost downgraded newer canonical binary! got %d bytes, want preserved stub", len(got))
	}
}
