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
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"hogman/join/internal/state"
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
		{"darwin", "arm64", "hogman-Darwin-arm64", false},
		{"darwin", "amd64", "hogman-Darwin-x86_64", false},
		{"linux", "amd64", "hogman-Linux-x86_64", false},
		{"linux", "arm64", "hogman-Linux-aarch64", false},
		{"windows", "amd64", "hogman-windows-amd64.exe", false},
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

	sums := []byte(sumA + "  hogman-Darwin-arm64\n" +
		sumB + " *hogman-Linux-x86_64\r\n\n")

	gotA, err := parseSHA256SUMS(sums, "hogman-Darwin-arm64")
	if err != nil || gotA != sumA {
		t.Fatalf("Darwin-arm64: got (%q, %v), want %q", gotA, err, sumA)
	}
	gotB, err := parseSHA256SUMS(sums, "hogman-Linux-x86_64")
	if err != nil || gotB != strings.ToLower(sumB) {
		t.Fatalf("Linux-x86_64: got (%q, %v), want %q", gotB, err, strings.ToLower(sumB))
	}
	if _, err := parseSHA256SUMS(sums, "hogman-windows-amd64.exe"); err == nil {
		t.Fatal("expected error for missing entry")
	}
	if _, err := parseSHA256SUMS([]byte("zzzz"+sumA[4:]+"  hogman-Darwin-arm64\n"), "hogman-Darwin-arm64"); err == nil {
		t.Fatal("expected error for non-hex digest")
	}
	dup := append([]byte{}, sums...)
	dup = append(dup, []byte(sumA+"  hogman-Darwin-arm64\n")...)
	if _, err := parseSHA256SUMS(dup, "hogman-Darwin-arm64"); err == nil {
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
	payload := []byte("verified-hogman-binary-bytes")
	wantHex := hexSHA256(payload)
	binName := "hogman-Linux-x86_64"

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

	gotHex, err := fetchExpectedSHA256URL(client, srv.URL+"/join/dl/SHA256SUMS", binName)
	if err != nil || gotHex != wantHex {
		t.Fatalf("fetchExpectedSHA256URL: (%q, %v), want %q", gotHex, err, wantHex)
	}

	tmpDir := t.TempDir()
	path, err := downloadVerifiedBinaryURL(client, srv.URL+"/join/dl/"+binName, binName, wantHex, tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("downloaded file content mismatch: %q, err=%v", got, err)
	}

	failDir := t.TempDir()
	if _, err := downloadVerifiedBinaryURL(client, srv.URL+"/join/dl/bad-"+binName, "bad-"+binName, wantHex, failDir); err == nil {
		t.Fatal("expected error on checksum mismatch")
	}
	if entries, _ := os.ReadDir(failDir); len(entries) != 0 {
		t.Fatalf("failed download left temp files: %v", entries)
	}

	if _, err := downloadVerifiedBinaryURL(client, srv.URL+"/join/dl/redir-"+binName, "redir-"+binName, wantHex, failDir); err == nil {
		t.Fatal("expected error on cross-host redirect")
	}
	if _, err := downloadVerifiedBinaryURL(client, srv.URL+"/join/dl/missing-"+binName, "missing-"+binName, wantHex, failDir); err == nil {
		t.Fatal("expected error on HTTP 404")
	}
}

func TestStageAndVerifyAtomicReplace(t *testing.T) {
	dir := t.TempDir()
	oldBytes := []byte("old-binary")
	newBytes := []byte("new-verified-binary")
	newHex := hexSHA256(newBytes)

	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "hogman")
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

	// Default with 0 pens resolves to immutable GitHub Releases (I-4).
	p0, err := resolveUpdatePlan(nil, options{}, cfgBase, sharesDir)
	if err != nil {
		t.Fatalf("0-pen default update plan failed: %v", err)
	}
	if !p0.fromRelease || p0.host != "github.com" || p0.releaseBase != defaultReleaseBase || len(p0.pens) != 0 {
		t.Fatalf("unexpected 0-pen plan: %+v", p0)
	}

	writePen := func(zone, login, ca string) {
		d := filepath.Join(cfgBase, zone)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := (&state.AgentConfig{Zone: zone, LoginServer: login, ControlCA: ca}).Save(d); err != nil {
			t.Fatal(err)
		}
	}
	writeShare := func(zone, name, login string) {
		d := filepath.Join(sharesDir, zone, name)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := (&state.ShareConfig{Zone: zone, Name: name, LoginServer: login}).Save(d); err != nil {
			t.Fatal(err)
		}
	}

	writePen("alpha.hogman", "https://alpha.example", "CA-ALPHA")
	writeShare("alpha.hogman", "notes", "https://alpha.example")
	writePen("beta.hogman", "https://beta.example", "")

	// Default with 2 pens on different servers still resolves to GitHub Releases
	// and includes ALL installed pens and shares (no --pen ambiguity).
	pAll, err := resolveUpdatePlan(nil, options{}, cfgBase, sharesDir)
	if err != nil {
		t.Fatal(err)
	}
	if !pAll.fromRelease || len(pAll.pens) != 2 || len(pAll.shares) != 1 {
		t.Fatalf("unexpected multi-pen release plan: %+v", pAll)
	}

	// --pen selects that specific pen's server instead of GitHub Releases.
	pBeta, err := resolveUpdatePlan(nil, options{pen: "beta.hogman"}, cfgBase, sharesDir)
	if err != nil || pBeta.fromRelease || pBeta.baseURL != "https://beta.example" || len(pBeta.pens) != 1 {
		t.Fatalf("unexpected --pen beta plan: (%+v, %v)", pBeta, err)
	}

	// Explicit URL matching alpha picks up alpha's ControlCA and targets.
	pExpl, err := resolveUpdatePlan([]string{"https://alpha.example"}, options{}, cfgBase, sharesDir)
	if err != nil || pExpl.fromRelease || pExpl.baseURL != "https://alpha.example" || pExpl.controlCA != "CA-ALPHA" || len(pExpl.pens) != 1 || len(pExpl.shares) != 1 {
		t.Fatalf("unexpected explicit plan: (%+v, %v)", pExpl, err)
	}

	// Explicit URL conflicting with --pen fails cleanly.
	if _, err := resolveUpdatePlan([]string{"https://alpha.example"}, options{pen: "beta.hogman"}, cfgBase, sharesDir); err == nil {
		t.Fatal("expected error when --pen LoginServer mismatches explicit URL")
	}

	// --pen on a share-only box resolves from share.json.
	onlyShares := filepath.Join(t.TempDir(), "shares")
	d := filepath.Join(onlyShares, "gamma.hogman", "blog")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&state.ShareConfig{Zone: "gamma.hogman", Name: "blog", LoginServer: "https://gamma.example", ControlCA: "CA-GAMMA"}).Save(d); err != nil {
		t.Fatal(err)
	}
	pShareOnly, err := resolveUpdatePlan(nil, options{pen: "gamma.hogman"}, filepath.Join(t.TempDir(), "none"), onlyShares)
	if err != nil || pShareOnly.fromRelease || pShareOnly.baseURL != "https://gamma.example" || pShareOnly.controlCA != "CA-GAMMA" || len(pShareOnly.shares) != 1 {
		t.Fatalf("unexpected share-only --pen plan: (%+v, %v)", pShareOnly, err)
	}
}

func TestGitHubReleaseFlowAndRedirects(t *testing.T) {
	// Version tag validation rejects traversal, whitespace, and shell metacharacters.
	for _, bad := range []string{"", " ", "../evil", "2026.11.23/foo", "v..bad", "v1.0;rm"} {
		if _, _, err := validateReleaseVersion(bad); err == nil {
			t.Fatalf("validateReleaseVersion(%q) succeeded, want error", bad)
		}
	}
	ver, tag, err := validateReleaseVersion("2026.11.23-abc1234\r\n")
	if err != nil || ver != "2026.11.23-abc1234" || tag != "v2026.11.23-abc1234" {
		t.Fatalf("validateReleaseVersion = (%q, %q, %v)", ver, tag, err)
	}

	// GitHub redirect allowlist permits official release asset hosts only.
	if !allowedUpdateRedirectHost("github.com", "objects.githubusercontent.com") {
		t.Fatal("expected objects.githubusercontent.com allowed for github.com")
	}
	if !allowedUpdateRedirectHost("github.com", "release-assets.githubusercontent.com") {
		t.Fatal("expected release-assets.githubusercontent.com allowed for github.com")
	}
	if allowedUpdateRedirectHost("github.com", "evil.example.com") {
		t.Fatal("evil.example.com must be rejected for github.com")
	}
	if allowedUpdateRedirectHost("bobo.gate.example.com", "objects.githubusercontent.com") {
		t.Fatal("objects.githubusercontent.com must not be allowed for non-GitHub hosts")
	}

	// End-to-end version-pinned download against local TLS test server.
	binName := "hogman-Darwin-arm64"
	payload := []byte("release-binary-payload-v1")
	wantHex := hexSHA256(payload)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest/download/latest":
			_, _ = w.Write([]byte("2026.11.23-abc1234\n"))
		case "/releases/download/v2026.11.23-abc1234/hogman-SHA256SUMS":
			_, _ = w.Write([]byte(wantHex + "  " + binName + "\n"))
		case "/releases/download/v2026.11.23-abc1234/" + binName:
			_, _ = w.Write(payload)
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
	relBase := srv.URL + "/releases"
	gotVer, gotTag, dlBase, err := fetchLatestReleaseTag(client, relBase)
	if err != nil || gotVer != "2026.11.23-abc1234" || gotTag != "v2026.11.23-abc1234" {
		t.Fatalf("fetchLatestReleaseTag = (%q, %q, %q, %v)", gotVer, gotTag, dlBase, err)
	}
	gotHex, err := fetchExpectedSHA256URL(client, dlBase+"/hogman-SHA256SUMS", binName)
	if err != nil || gotHex != wantHex {
		t.Fatalf("fetchExpectedSHA256URL = (%q, %v), want %q", gotHex, err, wantHex)
	}
	path, err := downloadVerifiedBinaryURL(client, dlBase+"/"+binName, binName, wantHex, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("downloaded release payload mismatch: %q, err=%v", got, err)
	}

	// Unreachable GitHub Releases fails clearly with explicit override hint (no silent fallback).
	srv.Close()
	if _, _, _, err := fetchLatestReleaseTag(client, relBase); err == nil || !strings.Contains(err.Error(), "hogman update --pen") {
		t.Fatalf("unreachable error = %v, want override hint", err)
	}
}

func TestParseCLIArgsUpdate(t *testing.T) {
	var gotArgs []string
	var gotO options
	rc := runCLI([]string{"update", "--dry-run", "--pen", "bobo.hogman"}, cliHandlers{
		update: func(args []string, o options) error {
			gotArgs, gotO = args, o
			return nil
		},
	})
	if rc != 0 || len(gotArgs) != 0 || !gotO.dryRun || gotO.pen != "bobo.hogman" {
		t.Fatalf("unexpected update parse: rc=%d args=%v o=%+v", rc, gotArgs, gotO)
	}

	rc = runCLI([]string{"update", "https://control.example"}, cliHandlers{
		update: func(args []string, o options) error {
			gotArgs, gotO = args, o
			return nil
		},
	})
	if rc != 0 || len(gotArgs) != 1 || gotArgs[0] != "https://control.example" {
		t.Fatalf("unexpected positional parse: rc=%d args=%v", rc, gotArgs)
	}
}

func TestMigrateAndRestartPenRollbackAndRecovery(t *testing.T) {
	dir := t.TempDir()
	canonBin := filepath.Join(dir, "canonical", "hogman")
	legacyBin := filepath.Join(dir, "hogman-join")
	if err := os.WriteFile(legacyBin, []byte("legacy"), 0o700); err != nil {
		t.Fatal(err)
	}
	pen := &penTarget{zone: "bobo.hogman", dir: dir, cfg: &state.AgentConfig{Zone: "bobo.hogman"}}

	// 1. restartNew fails while running -> stops partial new agent, rolls back to legacyBin, keeps legacyBin.
	var calls []string
	ops := penUpdateOps{
		isRunning:  func(string, *state.AgentConfig) bool { return true },
		hasService: func(string) bool { return true },
		stop:       func(string, *state.AgentConfig) { calls = append(calls, "stop") },
		restartNew: func(*penTarget, string, bool, options) error {
			calls = append(calls, "restartNew")
			return errors.New("agent timeout")
		},
		restartOld: func(_ *penTarget, bin string, hadService bool, _ options) error {
			if !hadService || bin != legacyBin {
				t.Fatalf("restartOld got hadService=%v bin=%q, want true %q", hadService, bin, legacyBin)
			}
			calls = append(calls, "restartOld")
			return nil
		},
	}
	err := migrateAndRestartPen(pen, canonBin, legacyBin, "/tmp/self", options{}, ops)
	if err == nil || !strings.Contains(err.Error(), "agent timeout") {
		t.Fatalf("expected restartNew error, got %v", err)
	}
	if !slices.Equal(calls, []string{"stop", "restartNew", "stop", "restartOld"}) {
		t.Fatalf("unexpected rollback sequence: %v", calls)
	}
	if _, statErr := os.Stat(legacyBin); statErr != nil {
		t.Fatalf("legacyBin removed despite rollback: %v", statErr)
	}
	if present, _ := state.ReadUpdatingMarker(dir); present {
		t.Fatal("updating marker should be cleared after successful rollback to legacyBin")
	}

	// 1b. restartNew fails AND restartOld fails -> updating marker remains on disk for recovery.
	calls = nil
	ops.restartOld = func(*penTarget, string, bool, options) error {
		calls = append(calls, "restartOld")
		return errors.New("rollback failed")
	}
	if err := migrateAndRestartPen(pen, canonBin, legacyBin, "/tmp/self", options{}, ops); err == nil {
		t.Fatal("expected error when both restartNew and restartOld fail")
	}
	if present, hadSvc := state.ReadUpdatingMarker(dir); !present || !hadSvc {
		t.Fatalf("updating marker after failed rollback = (%v, %v), want (true, true)", present, hadSvc)
	}
	state.ClearUpdatingMarker(dir)

	// 2. Stopped pen with service -> rewrites service and removes legacyBin without starting.
	calls = nil
	ops.isRunning = func(string, *state.AgentConfig) bool { return false }
	ops.rewriteService = func(bin, _ string, _ *state.AgentConfig) error {
		if bin != canonBin {
			t.Fatalf("rewriteService bin=%q, want %q", bin, canonBin)
		}
		calls = append(calls, "rewriteService")
		return nil
	}
	if err := migrateAndRestartPen(pen, canonBin, legacyBin, "/tmp/self", options{}, ops); err != nil {
		t.Fatalf("stopped pen migrate: %v", err)
	}
	if !slices.Equal(calls, []string{"rewriteService"}) {
		t.Fatalf("stopped pen sequence = %v, want [rewriteService]", calls)
	}
	if _, statErr := os.Stat(legacyBin); !os.IsNotExist(statErr) {
		t.Fatalf("legacyBin should be removed after stopped migration (err=%v)", statErr)
	}

	// 3. Running pen happy path -> stop, restartNew, clear marker.
	calls = nil
	ops.isRunning = func(string, *state.AgentConfig) bool { return true }
	ops.restartNew = func(*penTarget, string, bool, options) error { calls = append(calls, "restartNew"); return nil }
	if err := migrateAndRestartPen(pen, canonBin, "", "/tmp/self", options{}, ops); err != nil {
		t.Fatalf("happy-path migrate: %v", err)
	}
	if !slices.Equal(calls, []string{"stop", "restartNew"}) {
		t.Fatalf("happy-path sequence = %v, want [stop restartNew]", calls)
	}
	if present, _ := state.ReadUpdatingMarker(dir); present {
		t.Fatal("updating marker should be cleared after successful pen migration")
	}
}

func TestMigrateAndRestartShareRollbackAndRecovery(t *testing.T) {
	dir := t.TempDir()
	canonBin := filepath.Join(dir, "canonical", "hogman")
	legacyBin := filepath.Join(dir, "hogman-join")
	if err := os.WriteFile(legacyBin, []byte("legacy"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &shareTargetDir{
		dir:  dir,
		name: "blog",
		cfg:  &state.ShareConfig{Name: "blog", Zone: "bobo.hogman", Target: "http://127.0.0.1:3000"},
	}

	// 1. Running managed share + restartNew fails -> stops, rolls back to legacyBin, keeps legacyBin.
	var calls []string
	ops := shareUpdateOps{
		isRunning:  func(string) bool { return true },
		hasService: func(*state.ShareConfig) bool { return true },
		stop:       func(string, *state.ShareConfig) { calls = append(calls, "stop") },
		restartNew: func(*shareTargetDir, string, options) error {
			calls = append(calls, "restartNew")
			return errors.New("share failed")
		},
		restartOld: func(_ *shareTargetDir, bin string, _ options) error {
			if bin != legacyBin {
				t.Fatalf("restartOld bin=%q, want %q", bin, legacyBin)
			}
			calls = append(calls, "restartOld")
			return nil
		},
		rewriteService: func(string, string, *state.ShareConfig) error {
			calls = append(calls, "rewriteService")
			return nil
		},
	}
	err := migrateAndRestartShare(s, canonBin, legacyBin, "/tmp/self", options{}, ops)
	if err == nil || !strings.Contains(err.Error(), "share failed") {
		t.Fatalf("expected restartNew error, got %v", err)
	}
	if !slices.Equal(calls, []string{"stop", "restartNew", "stop", "restartOld"}) {
		t.Fatalf("managed rollback sequence = %v, want [stop restartNew stop restartOld]", calls)
	}
	if _, statErr := os.Stat(legacyBin); statErr != nil {
		t.Fatalf("legacyBin removed despite rollback: %v", statErr)
	}

	// 2. Running unmanaged share -> leaves running without stopping or deleting legacyBin.
	calls = nil
	ops.hasService = func(*state.ShareConfig) bool { return false }
	if err := migrateAndRestartShare(s, canonBin, legacyBin, "/tmp/self", options{}, ops); err != nil {
		t.Fatalf("unmanaged running share: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("unmanaged running share sequence = %v, want empty", calls)
	}
	if _, statErr := os.Stat(legacyBin); statErr != nil {
		t.Fatalf("legacyBin removed for unmanaged running share: %v", statErr)
	}

	// 3. Running managed share happy path -> stop, restartNew, remove legacyBin.
	calls = nil
	ops.hasService = func(*state.ShareConfig) bool { return true }
	ops.restartNew = func(*shareTargetDir, string, options) error { calls = append(calls, "restartNew"); return nil }
	if err := migrateAndRestartShare(s, canonBin, legacyBin, "/tmp/self", options{}, ops); err != nil {
		t.Fatalf("managed happy path: %v", err)
	}
	if !slices.Equal(calls, []string{"stop", "restartNew"}) {
		t.Fatalf("managed happy-path sequence = %v, want [stop restartNew]", calls)
	}
	if _, statErr := os.Stat(legacyBin); !os.IsNotExist(statErr) {
		t.Fatalf("legacyBin should be removed after managed migration (err=%v)", statErr)
	}

	// 4. Stopped managed share -> rewrites service without starting.
	calls = nil
	ops.isRunning = func(string) bool { return false }
	if err := migrateAndRestartShare(s, canonBin, "", "/tmp/self", options{}, ops); err != nil {
		t.Fatalf("stopped managed share: %v", err)
	}
	if !slices.Equal(calls, []string{"rewriteService"}) {
		t.Fatalf("stopped managed share sequence = %v, want [rewriteService]", calls)
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
	if err := (&state.AgentConfig{Zone: "bobo.hogman", LoginServer: "https://hs.example.com"}).Save(oldDir); err != nil {
		t.Fatal(err)
	}
	if err := (&state.AgentConfig{Zone: "bobo.pens.example.com", LoginServer: "https://hs.example.com"}).Save(newDir); err != nil {
		t.Fatal(err)
	}
	if err := (&state.AgentConfig{Zone: "other.hogman", LoginServer: "https://other.example.com"}).Save(otherDir); err != nil {
		t.Fatal(err)
	}

	found := findLegacySameServerPens(base, "bobo.pens.example.com", "https://hs.example.com")
	if len(found) != 1 || found[0].zone != "bobo.hogman" || found[0].dir != oldDir {
		t.Fatalf("findLegacySameServerPens = %+v, want only bobo.hogman", found)
	}

	var steps []string
	retireLegacySameServerPens(found, legacyRetireOps{
		stop: func(_ string, c *state.AgentConfig) {
			steps = append(steps, "stop:"+c.Zone)
		},
		logout: func(dir string) {
			if dir != oldDir {
				t.Fatalf("logout dir = %q, want %q", dir, oldDir)
			}
			steps = append(steps, "logout")
		},
	})
	if !slices.Equal(steps, []string{"stop:bobo.hogman", "logout"}) {
		t.Fatalf("retire call sequence = %v, want [stop:bobo.hogman logout]", steps)
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

func TestQueryBinaryVersionLineAndPensOutsidePlan(t *testing.T) {
	base := t.TempDir()
	for _, z := range []string{"alpha.pens.example.com", "beta.pens.example.com", "gamma.pens.example.com"} {
		d := filepath.Join(base, z)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := (&state.AgentConfig{Zone: z, LoginServer: "https://hs.example.com"}).Save(d); err != nil {
			t.Fatal(err)
		}
	}
	outside := pensOutsidePlan(base, []penTarget{{zone: "beta.pens.example.com"}})
	if !slices.Equal(outside, []string{"alpha.pens.example.com", "gamma.pens.example.com"}) {
		t.Fatalf("pensOutsidePlan = %v, want [alpha gamma]", outside)
	}

	if runtime.GOOS == "windows" {
		return
	}
	dir := t.TempDir()
	multi := filepath.Join(dir, "multi")
	if err := os.WriteFile(multi, []byte("#!/bin/sh\necho 'hogman 2026.11.26 darwin/arm64'\necho 'extra trailing line'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := queryBinaryVersionLine(multi); got != "hogman 2026.11.26 darwin/arm64; extra trailing line" {
		t.Fatalf("queryBinaryVersionLine(multi) = %q, want all lines joined", got)
	}
	if got := queryBinaryVersion(multi); got != "2026.11.26" {
		t.Fatalf("queryBinaryVersion(multi) = %q, want 2026.11.26", got)
	}

	slow := filepath.Join(dir, "slow")
	if err := os.WriteFile(slow, []byte("#!/bin/sh\nsleep 5\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	prev := versionQueryTimeout
	versionQueryTimeout = 100 * time.Millisecond
	t.Cleanup(func() { versionQueryTimeout = prev })
	if got := queryBinaryVersionLine(slow); got != "" {
		t.Fatalf("queryBinaryVersionLine(slow) = %q, want empty on timeout", got)
	}
}
