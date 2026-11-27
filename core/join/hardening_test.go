package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"hogman/join/internal/agent"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/penapi"
	"hogman/join/internal/platform"
	"hogman/join/internal/share"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
	"hogman/join/internal/updater"
)

func TestRedTeamLoopbackStatusTransportNoLeak(t *testing.T) {
	if !agent.LoopbackStatusTransport.DisableKeepAlives {
		t.Fatal("agent.LoopbackStatusTransport must disable keep-alives to avoid loopback FD leaks")
	}
	dir := t.TempDir()
	zone := "bobo.pens.example.com"
	token, err := state.WriteStatusToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := strings.TrimSpace(r.Header.Get("X-Hogman-Challenge"))
		if nonce != "" {
			w.Header().Set("X-Hogman-Proof", state.ComputeStatusProof(token, nonce, zone))
		}
		_ = json.NewEncoder(w).Encode(agent.Status{Zone: zone, Up: true, IPs: []string{"100.64.0.1"}})
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	cfg := &state.AgentConfig{Zone: zone, ProxyAddr: u.Host}

	// Warm up runtime goroutines, then run 40 status probes.
	if _, err := agent.StateInDir(dir, cfg); err != nil {
		t.Fatal(err)
	}
	baseG := runtime.NumGoroutine()
	for i := 0; i < 40; i++ {
		st, err := agent.StateInDir(dir, cfg)
		if err != nil || !st.Up {
			t.Fatalf("iter %d: agent.StateInDir = (%v, %v)", i, st, err)
		}
		epState, detail := agent.VerifyEndpointDetail(dir, cfg)
		if epState != agent.EndpointUp || !detail.Verified {
			t.Fatalf("iter %d: agent.VerifyEndpointDetail = (%v, %+v)", i, epState, detail)
		}
	}
	// Give short-lived closed sockets a moment to settle.
	time.Sleep(50 * time.Millisecond)
	afterG := runtime.NumGoroutine()
	if afterG-baseG > 10 {
		t.Fatalf("goroutine leak detected: before=%d after=%d", baseG, afterG)
	}
}

func TestRedTeamCLIParseSubcommandFlagValidationAndDoubleDash(t *testing.T) {
	noop := cliHandlers{
		join:         func(string, options) error { return nil },
		update:       func([]string, options) error { return nil },
		leave:        func([]string, options) error { return nil },
		leaveAll:     func([]string, options) error { return nil },
		uninstall:    func([]string, options) error { return nil },
		status:       func(options) error { return nil },
		doctor:       func(options) error { return nil },
		browserSetup: func([]string, options) error { return nil },
		shareStart:   func(string, string, string, options) error { return nil },
		shareList:    func(string, bool) error { return nil },
		shareStop:    func(string, options) error { return nil },
	}
	badCases := []struct {
		name string
		args []string
		want string
	}{
		{"leave dry-run", []string{"leave", "--dry-run", "https://bobo.gate.example.com/join#t=abc"}, "--dry-run"},
		{"leave dry-run after", []string{"leave", "https://bobo.gate.example.com/join#t=abc", "--dry-run"}, "--dry-run"},
		{"leave-all dry-run", []string{"leave-all", "--dry-run"}, "--dry-run"},
		{"uninstall dry-run", []string{"uninstall", "--dry-run", "--yes"}, "--dry-run"},
		{"share dry-run", []string{"share", "blog", "3000", "--dry-run"}, "--dry-run"},
		{"share stop dry-run", []string{"share", "stop", "blog", "--dry-run"}, "--dry-run"},
		{"browser-setup dry-run", []string{"browser-setup", "--dry-run"}, "--dry-run"},
		{"status pen", []string{"status", "--pen", "bobo.pens.example.com"}, "--pen"},
		{"update background", []string{"update", "--background"}, "--background"},
		{"unknown cmd dry-run", []string{"bogus", "--dry-run"}, "unknown command"},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			h := noop
			h.out, h.errOut = &out, &errOut
			rc := runCLI(tc.args, h)
			if rc != 2 || !strings.Contains(errOut.String(), tc.want) {
				t.Fatalf("runCLI(%v) rc=%d stderr=%q, want rc=2 containing %q", tc.args, rc, errOut.String(), tc.want)
			}
		})
	}

	// Harmless global flags (--no-open, --verbose, --yes, --control-ca) are accepted
	// everywhere so test harnesses and scripts (e.g. run.sh) keep working, and #144
	// commands accept --force.
	for _, okArgs := range [][]string{
		{"--no-open", "leave", "bobo"},
		{"--no-open", "leave", "--force", "bobo"},
		{"--no-open", "leave-all", "--force", "--yes"},
		{"--no-open", "uninstall", "--force", "--yes"},
		{"--no-open", "share", "list"},
		{"--no-open", "share", "stop", "blog", "--force"},
		{"--no-open", "update", "--dry-run"},
		{"--verbose", "status"},
	} {
		var out, errOut bytes.Buffer
		h := noop
		h.out, h.errOut = &out, &errOut
		if rc := runCLI(okArgs, h); rc != 0 {
			t.Fatalf("runCLI(%v) failed unexpectedly: rc=%d stderr=%q", okArgs, rc, errOut.String())
		}
	}

	// --help / -h returns exit 0 and writes usage to stdout.
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--help"}, "hogman"},
		{[]string{"-h"}, "hogman"},
		{[]string{"share", "--help"}, "share <name> <target>"},
		{[]string{"update", "-h"}, "GitHub Releases"},
	} {
		var out, errOut bytes.Buffer
		h := noop
		h.out, h.errOut = &out, &errOut
		if rc := runCLI(tc.args, h); rc != 0 || !strings.Contains(out.String(), tc.want) {
			t.Fatalf("runCLI(%v) rc=%d out=%q err=%q, want %q", tc.args, rc, out.String(), errOut.String(), tc.want)
		}
	}

	// `--` stops option parsing so following dash-prefixed args stay positional.
	var gotName, gotTarget string
	var gotO options
	h := noop
	h.shareStart = func(name, target, _ string, o options) error {
		gotName, gotTarget, gotO = name, target, o
		return nil
	}
	if rc := runCLI([]string{"share", "--", "--dry-run", "./dir"}, h); rc != 0 {
		t.Fatalf("runCLI with -- rc=%d", rc)
	}
	if gotO.dryRun || gotName != "--dry-run" || gotTarget != "./dir" {
		t.Fatalf("got name=%q target=%q dryRun=%v", gotName, gotTarget, gotO.dryRun)
	}

	// `--note --` consumes `--` as the flag's value, NOT as end-of-options.
	if rc := runCLI([]string{"share", "--note", "--", "blog", "3000", "--background"}, h); rc != 0 {
		t.Fatalf("runCLI(--note --) rc=%d", rc)
	}
	if gotO.note != "--" || !gotO.noteSet || !gotO.background || gotName != "blog" || gotTarget != "3000" {
		t.Fatalf("got name=%q target=%q note=%q noteSet=%v bg=%v", gotName, gotTarget, gotO.note, gotO.noteSet, gotO.background)
	}

	// Valid --force on share stop.
	var stopName string
	var stopO options
	h.shareStop = func(name string, o options) error {
		stopName, stopO = name, o
		return nil
	}
	if rc := runCLI([]string{"share", "stop", "blog", "--force", "--pen", "bobo.pens.example.com"}, h); rc != 0 || !stopO.force || stopO.pen != "bobo.pens.example.com" || stopName != "blog" {
		t.Fatalf("share stop --force: rc=%d name=%q o=%+v", rc, stopName, stopO)
	}
}

func TestRedTeamShareHandlerRejectsOpaqueURIAndHidesDotfiles(t *testing.T) {
	// 1. Opaque URI SSRF guard on URL shares.
	var hits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h, closeH, err := share.NewHandler(&state.ShareConfig{
		Name:   "app",
		Zone:   "farm.pens.example.com",
		Target: upstream.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeH()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.URL = &url.URL{Scheme: "x", Opaque: "//127.0.0.1:9999/admin"}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("opaque URI status = %d, want 400", rec.Code)
	}
	if hits != 0 {
		t.Fatalf("opaque URI reached upstream (%d hits)", hits)
	}

	// 2. Folder shares hide dotfiles (.git, .env, nested .secret) while serving normal files & .well-known.
	dir := t.TempDir()
	for rel, content := range map[string]string{
		"index.html":               "hello",
		".env":                     "SECRET=1",
		".git/config":              "[core]",
		"sub/.hidden":              "nope",
		".well-known/security.txt": "Contact: security@example.com",
	} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fh, closeFH, err := share.NewHandler(&state.ShareConfig{Name: "site", Zone: "farm.pens.example.com", Target: dir, Folder: true})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFH()

	for _, denied := range []string{"/.env", "/.git/config", "/sub/.hidden"} {
		r := httptest.NewRequest(http.MethodGet, denied, nil)
		w := httptest.NewRecorder()
		fh.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("dotfile %q status = %d, want 404", denied, w.Code)
		}
	}
	for _, allowed := range []string{"/", "/.well-known/security.txt"} {
		r := httptest.NewRequest(http.MethodGet, allowed, nil)
		w := httptest.NewRecorder()
		fh.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("allowed path %q status = %d, want 200", allowed, w.Code)
		}
	}

	// Directory listing (no index.html in sub/) must hide .hidden while showing visible.txt.
	if err := os.WriteFile(filepath.Join(dir, "sub", "visible.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	listReq := httptest.NewRequest(http.MethodGet, "/sub/", nil)
	listRec := httptest.NewRecorder()
	fh.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("dir listing status = %d, want 200", listRec.Code)
	}
	body := listRec.Body.String()
	if strings.Contains(body, ".hidden") {
		t.Fatalf("dir listing leaked dotfile: %s", body)
	}
	if !strings.Contains(body, "visible.txt") {
		t.Fatalf("dir listing missing visible.txt: %s", body)
	}
}

func TestRedTeamJoinRollbackAndReenrollPreserveInvite(t *testing.T) {
	// 1. Unspent authkey on disk: existingPenNeedsReenroll is false (retry existing key),
	//    and shouldRollbackFreshJoin is false on Ctrl-C / timeout so invite is never burned.
	dir := t.TempDir()
	cfg := &state.AgentConfig{Zone: "bobo.pens.example.com", LoginServer: "https://bobo.gate.example.com", ProxyAddr: "127.0.0.1:18123"}
	_ = cfg.Save(dir)
	_ = os.WriteFile(filepath.Join(dir, "authkey"), []byte("unspent-key"), 0o600)

	if existingPenNeedsReenroll(dir, cfg) {
		t.Fatal("existingPenNeedsReenroll should be false when an unspent authkey exists on disk")
	}
	if shouldRollbackFreshJoin(true, dir, errorf("cancelled before the pen connection came up")) {
		t.Fatal("shouldRollbackFreshJoin must not wipe an unspent authkey on Ctrl-C or timeout")
	}
	if !shouldRollbackFreshJoin(true, dir, &agent.JoinError{Msg: "rejected"}) {
		t.Fatal("shouldRollbackFreshJoin should roll back on definite agent.JoinError")
	}
	// Once authkey is spent (removed), the device has enrolled on the server:
	// follow-up check failures must NOT log it out and leave an orphan device (I-21).
	_ = os.Remove(filepath.Join(dir, "authkey"))
	if shouldRollbackFreshJoin(true, dir, errorf("portal failed")) {
		t.Fatal("shouldRollbackFreshJoin must not log out an already-enrolled device on follow-up failure")
	}

	// 2. reenrollExistingPen must NOT stop agent or wipe node/ when redeem fails.
	nodeMarker := filepath.Join(dir, "node", "state.json")
	_ = os.MkdirAll(filepath.Dir(nodeMarker), 0o700)
	_ = os.WriteFile(nodeMarker, []byte("keep"), 0o600)
	stopped := false
	n := &penapi.NetworkInfo{Zone: cfg.Zone, LoginServer: cfg.LoginServer, DNSServer: "100.64.0.1"}
	_, _, err := reenrollExistingPen(dir, cfg, n, "laptop", options{},
		func() (string, string, error) { return "", "", errorf("invite claimed") },
		func(string, *state.AgentConfig) { stopped = true },
	)
	if err == nil {
		t.Fatal("expected redeem error")
	}
	if stopped {
		t.Fatal("reenrollExistingPen stopped agent before redeem succeeded")
	}
	if _, statErr := os.Stat(nodeMarker); statErr != nil {
		t.Fatalf("reenrollExistingPen wiped node/ despite failed redeem: %v", statErr)
	}

	// 3. When redeem succeeds, reenrollExistingPen stops old agent, clears node/, writes new authkey.
	newCfg, handle, err := reenrollExistingPen(dir, cfg, n, "laptop", options{},
		func() (string, string, error) { return "fresh-key", "alice", nil },
		func(string, *state.AgentConfig) { stopped = true },
	)
	if err != nil || !stopped || handle != "alice" || newCfg.ProxyAddr != cfg.ProxyAddr {
		t.Fatalf("reenrollExistingPen success: cfg=%+v handle=%q stopped=%v err=%v", newCfg, handle, stopped, err)
	}
	if _, statErr := os.Stat(nodeMarker); !os.IsNotExist(statErr) {
		t.Fatal("reenrollExistingPen did not clear stale node/ after successful redeem")
	}
	keyBytes, err := os.ReadFile(filepath.Join(dir, "authkey"))
	if err != nil || string(keyBytes) != "fresh-key" {
		t.Fatalf("authkey after reenroll = %q (err=%v), want fresh-key", keyBytes, err)
	}
}

func TestRedTeamInstalledBinaryDirect(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AppData", filepath.Join(home, "AppData", "Roaming"))
	dir := t.TempDir()
	got, err := installedBinary(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, home) {
		t.Fatalf("installedBinary wrote outside isolated test home: %s (home=%s)", got, home)
	}
	fi, err := os.Stat(got)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("installedBinary produced invalid file %s (err=%v)", got, err)
	}
}

func TestRedTeamCopyExecutableAtomicAndSymlinkSafe(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "orig")
	want := []byte("#!/bin/sh\necho ok\n")
	if err := os.WriteFile(src, want, 0o755); err != nil {
		t.Fatal(err)
	}
	symLink := filepath.Join(dir, "link")
	if err := os.Symlink(src, symLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if !fsutil.SameFilePath(src, symLink) {
		t.Fatal("SameFilePath should recognize symlink to same file")
	}
	dst := filepath.Join(dir, "copy")
	if err := fsutil.CopyExecutableAtomic(symLink, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != string(want) {
		t.Fatalf("copied binary = %q (err=%v), want %q", got, err, want)
	}
}

func TestRedTeamParseLinkAndUpdateSourceNormalization(t *testing.T) {
	l, err := link.Parse("  'https://BOBO.GATE.EXAMPLE.COM/join#t=abc'  ")
	if err != nil {
		t.Fatal(err)
	}
	if l.Host != "bobo.gate.example.com" || l.InviteToken != "abc" {
		t.Fatalf("link.Parse normalized = %+v", l)
	}
	base, host, err := updater.ParseSourceURL(`"HTTPS://BOBO.GATE.EXAMPLE.COM"`)
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://bobo.gate.example.com" || host != "bobo.gate.example.com" {
		t.Fatalf("ParseSourceURL = (%q, %q)", base, host)
	}
	c, err := updater.HTTPClient("", "", "bobo.gate.example.com", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://BOBO.GATE.EXAMPLE.COM/join/dl/SHA256SUMS", nil)
	if err := c.CheckRedirect(req, []*http.Request{req}); err != nil {
		t.Fatalf("case-insensitive same-host redirect rejected: %v", err)
	}
}

func TestRedTeamAskPreservesBufferedStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, _ = w.WriteString("alice\nbob\n")
	_ = w.Close()

	u := &ui.UI{In: r, Err: &bytes.Buffer{}}
	if got := u.Ask(""); got != "alice" {
		t.Fatalf("first ask = %q, want alice", got)
	}
	if got := u.Ask(""); got != "bob" {
		t.Fatalf("second ask = %q, want bob", got)
	}
}

func TestRedTeamNonPositivePIDGuards(t *testing.T) {
	if platform.ProcessAlive(0) || platform.ProcessAlive(-1) {
		t.Fatal("platform.ProcessAlive must return false for pid <= 0")
	}
	dir := t.TempDir()
	for _, raw := range []string{"0", "-1", "not-a-pid"} {
		if err := os.WriteFile(filepath.Join(dir, "share.pid"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if pid := share.PID(dir); pid != 0 {
			t.Fatalf("share.PID(%q) = %d, want 0", raw, pid)
		}
		pidPath := filepath.Join(dir, "agent.pid")
		if err := os.WriteFile(pidPath, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		platform.StopDetached(dir)
		if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
			t.Fatalf("platform.StopDetached(%q) did not remove stale agent.pid", raw)
		}
	}
}

func TestRedTeamTailscaleStatusNonJSONNoPanic(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script test")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "tailscale")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho 'tailscaled is not running'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ts := platform.NewTailscale(script)
	if _, err := ts.Status(); err == nil {
		t.Fatal("expected error for non-JSON tailscale status output")
	}
}

func TestRedTeamHostnameAndPenTargetValidation(t *testing.T) {
	if got, err := link.SanitizeHostname("My MacBook Pro.local"); err != nil || got != "my-macbook-pro" {
		t.Fatalf("SanitizeHostname = (%q, %v), want my-macbook-pro", got, err)
	}
	if got, err := link.SanitizeHostname("!!!"); err != nil || got != "" {
		t.Fatalf("SanitizeHostname(!!!) = (%q, %v), want empty, nil", got, err)
	}
	if got, err := link.SanitizeHostname(strings.Repeat("a", 63)); err != nil || len(got) != 63 {
		t.Fatalf("SanitizeHostname(63 chars) = (%q, %v), want 63-char name", got, err)
	}
	if got, err := link.SanitizeHostname(strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "--hostname") {
		t.Fatalf("SanitizeHostname(64 chars) = (%q, %v), want error mentioning --hostname", got, err)
	}

	base := t.TempDir()
	// Valid pen dir
	validDir := filepath.Join(base, "bobo.pens.example.com")
	_ = os.MkdirAll(validDir, 0o700)
	_ = (&state.AgentConfig{Zone: "bobo.pens.example.com", LoginServer: "https://bobo.gate.example.com", ProxyAddr: "127.0.0.1:18000"}).Save(validDir)

	// Mismatched Zone vs dir name
	badDir := filepath.Join(base, "other.pens.example.com")
	_ = os.MkdirAll(badDir, 0o700)
	_ = (&state.AgentConfig{Zone: "evil.pens.example.com", LoginServer: "https://evil.gate.example.com", ProxyAddr: "127.0.0.1:18001"}).Save(badDir)

	// Corrupt JSON
	corruptDir := filepath.Join(base, "broken.pens.example.com")
	_ = os.MkdirAll(corruptDir, 0o700)
	_ = os.WriteFile(filepath.Join(corruptDir, "config.json"), []byte("{not json"), 0o600)

	pens := updater.LoadPenTargets(base)
	if len(pens) != 1 || pens[0].Zone != "bobo.pens.example.com" {
		t.Fatalf("LoadPenTargets = %+v, want only bobo.pens.example.com", pens)
	}
	bad := state.CorruptPenConfigs(base)
	if len(bad) != 2 {
		t.Fatalf("CorruptPenConfigs = %v, want 2 bad entries", bad)
	}
}

func TestRedTeamShareTargetReservedNamesAndSystemdSingleLine(t *testing.T) {
	for _, bad := range []string{
		"http://user:pass@localhost:8080",
		"http://:8080",
		"http://localhost:99999",
		"http://localhost:0",
	} {
		if _, _, err := share.ParseTarget(bad); err == nil {
			t.Fatalf("share.ParseTarget(%q) succeeded, want error", bad)
		}
	}
	if target, folder, err := share.ParseTarget("http://127.0.0.1:8080/"); err != nil || folder || target != "http://127.0.0.1:8080" {
		t.Fatalf("share.ParseTarget valid = (%q, %v, %v)", target, folder, err)
	}

	for _, res := range []string{"home", "www", "admin", "nodes", "ns", "ns1", "ns42", "sub.home", "x.admin"} {
		if !share.IsReservedName(res) {
			t.Fatalf("share.IsReservedName(%q) = false, want true", res)
		}
	}
	for _, okName := range []string{"blog", "my-notes", "app.blog", "nsa"} {
		if share.IsReservedName(okName) {
			t.Fatalf("share.IsReservedName(%q) = true, want false", okName)
		}
	}

	unit := platform.RenderSystemdUnit("line1\nExecStart=/bin/evil\rline2", "/bin/hogman", "/tmp/dir")
	if strings.Contains(unit, "\nExecStart=/bin/evil") || !strings.Contains(unit, "Description=Hogman pen connection (line1ExecStart=/bin/evilline2)\n") {
		t.Fatalf("RenderSystemdUnit retained injected newline:\n%s", unit)
	}
}
