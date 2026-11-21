package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func hexSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestPlatformBinaryName(t *testing.T) {
	cases := []struct {
		goos, goarch string
		want         string
		wantErr      bool
	}{
		{"darwin", "arm64", "hogman-join-Darwin-arm64", false},
		{"darwin", "amd64", "hogman-join-Darwin-x86_64", false},
		{"linux", "amd64", "hogman-join-Linux-x86_64", false},
		{"linux", "arm64", "hogman-join-Linux-aarch64", false},
		{"windows", "amd64", "hogman-join-windows-amd64.exe", false},
		{"freebsd", "amd64", "", true},
	}
	for _, tc := range cases {
		got, err := platformBinaryName(tc.goos, tc.goarch)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%s/%s: err=%v, wantErr=%v", tc.goos, tc.goarch, err, tc.wantErr)
		}
		if got != tc.want {
			t.Fatalf("%s/%s: got %q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestParseSHA256SUMS(t *testing.T) {
	sumA := strings.Repeat("ab", 32)
	sumB := strings.Repeat("CD", 32)

	sums := []byte(sumA + "  hogman-join-Darwin-arm64\n" +
		sumB + " *hogman-join-Linux-x86_64\r\n\n")

	gotA, err := parseSHA256SUMS(sums, "hogman-join-Darwin-arm64")
	if err != nil || gotA != sumA {
		t.Fatalf("Darwin-arm64: got (%q, %v), want %q", gotA, err, sumA)
	}
	gotB, err := parseSHA256SUMS(sums, "hogman-join-Linux-x86_64")
	if err != nil || gotB != strings.ToLower(sumB) {
		t.Fatalf("Linux-x86_64: got (%q, %v), want %q", gotB, err, strings.ToLower(sumB))
	}
	if _, err := parseSHA256SUMS(sums, "hogman-join-windows-amd64.exe"); err == nil {
		t.Fatal("expected error for missing entry")
	}
	if _, err := parseSHA256SUMS([]byte("zzzz"+sumA[4:]+"  hogman-join-Darwin-arm64\n"), "hogman-join-Darwin-arm64"); err == nil {
		t.Fatal("expected error for non-hex digest")
	}
	dup := append([]byte{}, sums...)
	dup = append(dup, []byte(sumA+"  hogman-join-Darwin-arm64\n")...)
	if _, err := parseSHA256SUMS(dup, "hogman-join-Darwin-arm64"); err == nil {
		t.Fatal("expected error for duplicate entry")
	}
}

func TestParseUpdateSourceURL(t *testing.T) {
	good := []struct {
		raw      string
		wantBase string
		wantHost string
	}{
		{"https://pen.example/join#t=abc", "https://pen.example", "pen.example"},
		{"https://pen.example/join#k=dev&for=share", "https://pen.example", "pen.example"},
		{"pen.example", "https://pen.example", "pen.example"},
		{"https://pen.example:8443/", "https://pen.example:8443", "pen.example:8443"},
	}
	for _, tc := range good {
		base, host, err := parseUpdateSourceURL(tc.raw)
		if err != nil || base != tc.wantBase || host != tc.wantHost {
			t.Fatalf("%q: got (%q, %q, %v), want (%q, %q, nil)", tc.raw, base, host, err, tc.wantBase, tc.wantHost)
		}
	}
	bad := []string{
		"",
		"http://pen.example",
		"https://user:pass@pen.example",
		"https://pen.example/other",
		"https://pen.example?q=1",
		"https://pen.example#frag",
	}
	for _, raw := range bad {
		if _, _, err := parseUpdateSourceURL(raw); err == nil {
			t.Fatalf("expected error for %q", raw)
		}
	}
}

func testServerPEM(srv *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

func TestDownloadVerifiedBinary(t *testing.T) {
	payload := []byte("verified-hogman-join-binary-bytes")
	wantHex := hexSHA256(payload)
	binName := "hogman-join-Linux-x86_64"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/join/dl/SHA256SUMS":
			_, _ = w.Write([]byte(wantHex + "  " + binName + "\n"))
		case "/join/dl/" + binName:
			_, _ = w.Write(payload)
		case "/join/dl/bad-" + binName:
			_, _ = w.Write([]byte("corrupted-bytes"))
		case "/join/dl/redir-" + binName:
			http.Redirect(w, r, "https://evil.example/payload", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	client, err := updateHTTPClient("", testServerPEM(srv), host, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	gotHex, err := fetchExpectedSHA256(client, srv.URL, binName)
	if err != nil || gotHex != wantHex {
		t.Fatalf("fetchExpectedSHA256: (%q, %v), want %q", gotHex, err, wantHex)
	}

	tmpDir := t.TempDir()
	path, err := downloadVerifiedBinary(client, srv.URL, binName, wantHex, tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("downloaded file content mismatch: %q, err=%v", got, err)
	}

	failDir := t.TempDir()
	if _, err := downloadVerifiedBinary(client, srv.URL, "bad-"+binName, wantHex, failDir); err == nil {
		t.Fatal("expected error on checksum mismatch")
	}
	if entries, _ := os.ReadDir(failDir); len(entries) != 0 {
		t.Fatalf("failed download left temp files: %v", entries)
	}

	if _, err := downloadVerifiedBinary(client, srv.URL, "redir-"+binName, wantHex, failDir); err == nil {
		t.Fatal("expected error on cross-host redirect")
	}
	if _, err := downloadVerifiedBinary(client, srv.URL, "missing-"+binName, wantHex, failDir); err == nil {
		t.Fatal("expected error on HTTP 404")
	}
}

func TestStageAndVerifyAtomicReplace(t *testing.T) {
	dir := t.TempDir()
	oldBytes := []byte("old-binary")
	newBytes := []byte("new-verified-binary")
	newHex := hexSHA256(newBytes)

	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "hogman-join")
	if err := os.WriteFile(src, newBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, oldBytes, 0o755); err != nil {
		t.Fatal(err)
	}

	// Mismatch must leave existing dst completely untouched.
	if err := stageAndVerify(src, dst, strings.Repeat("00", 32)); err == nil {
		t.Fatal("expected error when staged checksum mismatches")
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, oldBytes) {
		t.Fatalf("dst modified after failed stage: %q", got)
	}

	if err := stageAndVerify(src, dst, newHex); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(dst)
	if !bytes.Equal(got, newBytes) {
		t.Fatalf("dst content after replace: %q, want %q", got, newBytes)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm()&0o100 == 0 {
		t.Fatalf("dst mode not executable: %v, err=%v", fi.Mode().Perm(), err)
	}
}

func TestResolveUpdatePlan(t *testing.T) {
	root := t.TempDir()
	cfgBase := filepath.Join(root, "hogman")
	sharesDir := filepath.Join(root, "hogman-shares")

	// Empty state -> error without explicit source.
	if _, err := resolveUpdatePlan(nil, options{}, cfgBase, sharesDir); err == nil {
		t.Fatal("expected error with no joined pens")
	}

	writePen := func(zone, login, ca string) {
		d := filepath.Join(cfgBase, zone)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := (&agentConfig{Zone: zone, LoginServer: login, ControlCA: ca}).save(d); err != nil {
			t.Fatal(err)
		}
	}
	writeShare := func(zone, name, login string) {
		d := filepath.Join(sharesDir, zone, name)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := (&shareConfig{Zone: zone, Name: name, LoginServer: login}).save(d); err != nil {
			t.Fatal(err)
		}
	}

	writePen("alpha.hogman", "https://alpha.example", "CA-ALPHA")
	writeShare("alpha.hogman", "notes", "https://alpha.example")

	// Single pen + share sharing LoginServer resolves cleanly.
	p, err := resolveUpdatePlan(nil, options{}, cfgBase, sharesDir)
	if err != nil {
		t.Fatal(err)
	}
	if p.baseURL != "https://alpha.example" || p.controlCA != "CA-ALPHA" || len(p.pens) != 1 || len(p.shares) != 1 {
		t.Fatalf("unexpected 1-pen plan: %+v", p)
	}

	// Adding a second pen on a different server requires --pen or explicit arg.
	writePen("beta.hogman", "https://beta.example", "")
	if _, err := resolveUpdatePlan(nil, options{}, cfgBase, sharesDir); err == nil {
		t.Fatal("expected ambiguity error with two pens")
	}
	pBeta, err := resolveUpdatePlan(nil, options{pen: "beta.hogman"}, cfgBase, sharesDir)
	if err != nil || pBeta.baseURL != "https://beta.example" || len(pBeta.pens) != 1 {
		t.Fatalf("unexpected --pen beta plan: (%+v, %v)", pBeta, err)
	}

	// Explicit URL matching alpha picks up alpha's ControlCA and targets.
	pExpl, err := resolveUpdatePlan([]string{"https://alpha.example"}, options{}, cfgBase, sharesDir)
	if err != nil || pExpl.baseURL != "https://alpha.example" || pExpl.controlCA != "CA-ALPHA" || len(pExpl.pens) != 1 || len(pExpl.shares) != 1 {
		t.Fatalf("unexpected explicit plan: (%+v, %v)", pExpl, err)
	}

	// Explicit URL conflicting with --pen fails cleanly.
	if _, err := resolveUpdatePlan([]string{"https://alpha.example"}, options{pen: "beta.hogman"}, cfgBase, sharesDir); err == nil {
		t.Fatal("expected error when --pen LoginServer mismatches explicit URL")
	}

	// Share-only box with no personal pen resolves from share.json.
	onlyShares := filepath.Join(t.TempDir(), "shares")
	d := filepath.Join(onlyShares, "gamma.hogman", "blog")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&shareConfig{Zone: "gamma.hogman", Name: "blog", LoginServer: "https://gamma.example", ControlCA: "CA-GAMMA"}).save(d); err != nil {
		t.Fatal(err)
	}
	pShareOnly, err := resolveUpdatePlan(nil, options{}, filepath.Join(t.TempDir(), "none"), onlyShares)
	if err != nil || pShareOnly.baseURL != "https://gamma.example" || pShareOnly.controlCA != "CA-GAMMA" || len(pShareOnly.shares) != 1 {
		t.Fatalf("unexpected share-only plan: (%+v, %v)", pShareOnly, err)
	}
}

func TestParseCLIArgsUpdate(t *testing.T) {
	pos, o, ver, err := parseCLIArgs([]string{"update", "--dry-run", "--pen", "bobo.hogman"})
	if err != nil || ver {
		t.Fatalf("parseCLIArgs: (%v, %v)", ver, err)
	}
	if len(pos) != 1 || pos[0] != "update" || !o.dryRun || o.pen != "bobo.hogman" {
		t.Fatalf("unexpected parse: pos=%v o=%+v", pos, o)
	}

	pos, _, _, err = parseCLIArgs([]string{"update", "https://control.example"})
	if err != nil || len(pos) != 2 || pos[0] != "update" || pos[1] != "https://control.example" {
		t.Fatalf("unexpected positional parse: pos=%v err=%v", pos, err)
	}
}

func TestUpdatePenAgentRollbackAndRecovery(t *testing.T) {
	pen := &penTarget{zone: "bobo.hogman", dir: "/tmp/pen", cfg: &agentConfig{Zone: "bobo.hogman"}}
	binPath := "/tmp/pen/hogman-join"

	// 1. Stage fails while running -> old agent restarted, restartNew not called.
	var calls []string
	ops := penUpdateOps{
		isRunning:  func(string, *agentConfig) bool { return true },
		hasService: func(string) bool { return true },
		stop:       func(string, *agentConfig) { calls = append(calls, "stop") },
		stage:      func(string, string, string) error { calls = append(calls, "stage"); return errors.New("disk full") },
		restartNew: func(*penTarget, string, bool, options) error { calls = append(calls, "restartNew"); return nil },
		restartOld: func(_ *penTarget, _ string, hadService bool, _ options) error {
			if !hadService {
				t.Fatal("expected hadService=true")
			}
			calls = append(calls, "restartOld")
			return nil
		},
	}
	err := updatePenAgent(pen, binPath, "/tmp/src", strings.Repeat("aa", 32), options{}, ops)
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("expected disk full error, got %v", err)
	}
	if !slices.Equal(calls, []string{"stop", "stage", "restartOld"}) {
		t.Fatalf("unexpected call sequence on stage failure: %v", calls)
	}

	// 2. Stage fails AND restartOld fails -> error gives recovery instructions.
	calls = nil
	ops.restartOld = func(*penTarget, string, bool, options) error {
		calls = append(calls, "restartOld")
		return errors.New("launchd error")
	}
	err = updatePenAgent(pen, binPath, "/tmp/src", strings.Repeat("aa", 32), options{}, ops)
	if err == nil || !strings.Contains(err.Error(), "agent") || !strings.Contains(err.Error(), "link") {
		t.Fatalf("expected recovery hint in error, got %v", err)
	}

	// 3. Stage fails while stopped -> no stop or restart attempted.
	calls = nil
	ops.isRunning = func(string, *agentConfig) bool { return false }
	err = updatePenAgent(pen, binPath, "/tmp/src", strings.Repeat("aa", 32), options{}, ops)
	if err == nil || !slices.Equal(calls, []string{"stage"}) {
		t.Fatalf("expected only stage on stopped pen, got calls=%v err=%v", calls, err)
	}

	// 4. Happy path while running -> stop, stage, restartNew in order.
	calls = nil
	ops.isRunning = func(string, *agentConfig) bool { return true }
	ops.stage = func(string, string, string) error { calls = append(calls, "stage"); return nil }
	if err := updatePenAgent(pen, binPath, "/tmp/src", strings.Repeat("aa", 32), options{}, ops); err != nil {
		t.Fatalf("unexpected error on happy path: %v", err)
	}
	if !slices.Equal(calls, []string{"stop", "stage", "restartNew"}) {
		t.Fatalf("unexpected happy-path call sequence: %v", calls)
	}
}

func TestUpdateShareBinaryRestartAndRollback(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "hogman-join")
	s := &shareTargetDir{
		dir:  dir,
		name: "blog",
		cfg:  &shareConfig{Name: "blog", Zone: "bobo.hogman", Target: "http://127.0.0.1:3000"},
	}

	// 1. Running managed share + stage failure -> stops share, calls restartOld, returns error.
	var calls []string
	ops := shareUpdateOps{
		isRunning:  func(string) bool { return true },
		hasService: func(*shareConfig) bool { return true },
		stop:       func(string, *shareConfig) { calls = append(calls, "stop") },
		stage:      func(string, string, string) error { calls = append(calls, "stage"); return errors.New("disk full") },
		restartNew: func(*shareTargetDir, string, options) error { calls = append(calls, "restartNew"); return nil },
		restartOld: func(*shareTargetDir, string, options) error { calls = append(calls, "restartOld"); return nil },
	}
	err := updateShareBinary(s, binPath, "/tmp/src", strings.Repeat("aa", 32), options{}, ops)
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("expected disk full error, got %v", err)
	}
	if !slices.Equal(calls, []string{"stop", "stage", "restartOld"}) {
		t.Fatalf("managed stage failure sequence = %v, want [stop stage restartOld]", calls)
	}

	// 2. Running managed share + stage success -> stops share, stages new binary, calls restartNew.
	calls = nil
	ops.stage = func(string, string, string) error { calls = append(calls, "stage"); return nil }
	if err := updateShareBinary(s, binPath, "/tmp/src", strings.Repeat("aa", 32), options{}, ops); err != nil {
		t.Fatalf("unexpected error on managed happy path: %v", err)
	}
	if !slices.Equal(calls, []string{"stop", "stage", "restartNew"}) {
		t.Fatalf("managed happy-path sequence = %v, want [stop stage restartNew]", calls)
	}

	// 3. Running unmanaged (foreground/no-service) share -> stages without stopping or restarting.
	calls = nil
	ops.hasService = func(*shareConfig) bool { return false }
	if err := updateShareBinary(s, binPath, "/tmp/src", strings.Repeat("aa", 32), options{}, ops); err != nil {
		t.Fatalf("unexpected error on unmanaged running share: %v", err)
	}
	if !slices.Equal(calls, []string{"stage"}) {
		t.Fatalf("unmanaged running share sequence = %v, want [stage]", calls)
	}

	// 4. Stopped share -> stages without stopping or starting.
	calls = nil
	ops.isRunning = func(string) bool { return false }
	ops.hasService = func(*shareConfig) bool { return true }
	if err := updateShareBinary(s, binPath, "/tmp/src", strings.Repeat("aa", 32), options{}, ops); err != nil {
		t.Fatalf("unexpected error on stopped share: %v", err)
	}
	if !slices.Equal(calls, []string{"stage"}) {
		t.Fatalf("stopped share sequence = %v, want [stage]", calls)
	}
}

func TestCleanupLegacyRootsForUpdate(t *testing.T) {
	// 1. Saved RootFP cleans specific pen root, runs trailing wildcard sweep, and clears RootFP on disk.
	pubDir := t.TempDir()
	pubCfg := &agentConfig{Zone: "bobo.hogman", LoginServer: "https://hs.example.com", RootFP: "BB22"}
	if err := pubCfg.save(pubDir); err != nil {
		t.Fatal(err)
	}
	var calls []string
	plan := &updatePlan{
		baseURL: "https://bobo.gate.example.com",
		host:    "bobo.gate.example.com",
		pens:    []penTarget{{zone: pubCfg.Zone, dir: pubDir, cfg: pubCfg}},
	}
	got := cleanupLegacyRootsForUpdate(plan, false, legacyCleanupOps{
		removeRoot: func(zone, fp string) (bool, error) {
			calls = append(calls, zone+"|"+fp)
			return true, nil
		},
		saveConfig: func(dir string, c *agentConfig) error { return c.save(dir) },
	})
	if !slices.Equal(calls, []string{"bobo.hogman|BB22", "|"}) {
		t.Fatalf("cleanup calls = %v, want pen + wildcard sweep", calls)
	}
	if len(got) != 2 {
		t.Fatalf("cleanup results = %v, want 2 entries", got)
	}
	reloaded, err := loadAgentConfig(pubDir)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.RootFP != "" {
		t.Fatalf("expected saved config RootFP cleared, got %q", reloaded.RootFP)
	}

	// 2. Dry-run never invokes removeRoot and preserves RootFP.
	calls = nil
	plan.pens[0].cfg.RootFP = "DD44"
	cleanupLegacyRootsForUpdate(plan, true, legacyCleanupOps{
		removeRoot: func(zone, fp string) (bool, error) {
			calls = append(calls, zone+"|"+fp)
			return true, nil
		},
	})
	if len(calls) != 0 {
		t.Fatalf("dry-run called removeRoot: %v", calls)
	}

	// 3. Steady-state pen without RootFP scans only once via wildcard sweep.
	calls = nil
	plan.pens[0].cfg.RootFP = ""
	cleanupLegacyRootsForUpdate(plan, false, legacyCleanupOps{
		removeRoot: func(zone, fp string) (bool, error) {
			calls = append(calls, zone+"|"+fp)
			return false, nil
		},
	})
	if !slices.Equal(calls, []string{"|"}) {
		t.Fatalf("steady-state cleanup calls = %v, want single wildcard [\"|\"]", calls)
	}
}

func TestFindAndRetireLegacySameServerPens(t *testing.T) {
	base := t.TempDir()
	oldDir := filepath.Join(base, "bobo.hogman")
	newDir := filepath.Join(base, "bobo.pens.example.com")
	otherDir := filepath.Join(base, "other.hogman")
	for _, d := range []string{oldDir, newDir, otherDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := (&agentConfig{Zone: "bobo.hogman", LoginServer: "https://hs.example.com", RootFP: "FP-OLD"}).save(oldDir); err != nil {
		t.Fatal(err)
	}
	if err := (&agentConfig{Zone: "bobo.pens.example.com", LoginServer: "https://hs.example.com"}).save(newDir); err != nil {
		t.Fatal(err)
	}
	if err := (&agentConfig{Zone: "other.hogman", LoginServer: "https://other.example.com", RootFP: "FP-OTHER"}).save(otherDir); err != nil {
		t.Fatal(err)
	}

	found := findLegacySameServerPens(base, "bobo.pens.example.com", "https://hs.example.com")
	if len(found) != 1 || found[0].zone != "bobo.hogman" || found[0].dir != oldDir {
		t.Fatalf("findLegacySameServerPens = %+v, want only bobo.hogman", found)
	}

	var steps []string
	retireLegacySameServerPens(found, legacyRetireOps{
		stop: func(_ string, c *agentConfig) {
			steps = append(steps, "stop:"+c.Zone)
		},
		logout: func(dir string) {
			if dir != oldDir {
				t.Fatalf("logout dir = %q, want %q", dir, oldDir)
			}
			steps = append(steps, "logout")
		},
		removeRoot: func(zone, rootFP string) (bool, error) {
			steps = append(steps, "removeRoot:"+zone+"|"+rootFP)
			return true, nil
		},
	})
	if !slices.Equal(steps, []string{"stop:bobo.hogman", "logout", "removeRoot:bobo.hogman|FP-OLD"}) {
		t.Fatalf("retire call sequence = %v, want [stop:bobo.hogman logout removeRoot:bobo.hogman|FP-OLD]", steps)
	}
	if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
		t.Fatalf("expected old pen dir %s removed, stat err = %v", oldDir, err)
	}
	if _, err := os.Stat(newDir); err != nil {
		t.Fatalf("expected new pen dir %s kept, err = %v", newDir, err)
	}
	if _, err := os.Stat(otherDir); err != nil {
		t.Fatalf("expected unrelated pen dir %s kept, err = %v", otherDir, err)
	}
}

