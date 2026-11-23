package main

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShareTarget(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		in, want string
		folder   bool
		ok       bool
	}{
		{"3000", "http://127.0.0.1:3000", false, true},
		{"0", "", false, false},
		{"70000", "", false, false},
		{"http://localhost:8080/", "http://localhost:8080", false, true},
		{dir, dir, true, true},
		{dir + "/nope", "", false, false},
	}
	for _, c := range cases {
		got, folder, err := shareTarget(c.in)
		if (err == nil) != c.ok || got != c.want || folder != c.folder {
			t.Errorf("shareTarget(%q) = %q, %v, %v; want %q, %v, ok=%v", c.in, got, folder, err, c.want, c.folder, c.ok)
		}
	}
	f := dir + "/file"
	_ = os.WriteFile(f, []byte("x"), 0o600)
	if _, _, err := shareTarget(f); err == nil {
		t.Errorf("a file should not be shareable as a folder")
	}
}

func TestShareNames(t *testing.T) {
	for _, n := range []string{"blog", "my-notes", "a.blog", "x1"} {
		if !shareNameRE.MatchString(n) {
			t.Errorf("%q should be a valid share name", n)
		}
	}
	for _, n := range []string{"", "-x", "Blog", "a_b", "x.", "a b"} {
		if shareNameRE.MatchString(n) {
			t.Errorf("%q should not be a valid share name", n)
		}
	}
}

func TestShareFolderStaysInside(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	_ = os.WriteFile(secret, []byte("do not serve"), 0o600)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("hello"), 0o600)
	if err := os.Symlink(secret, filepath.Join(dir, "leak")); err != nil {
		t.Skip("no symlinks here:", err)
	}
	h, done, err := shareHandler(&shareConfig{Name: "x", Zone: "z.hogman", Target: dir, Folder: true})
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code, rec.Body.String()
	}
	if code, body := get("/"); code != 200 || !strings.Contains(body, "hello") {
		t.Fatalf("index: %d %q", code, body)
	}
	if code, body := get("/leak"); code == 200 || strings.Contains(body, "do not serve") {
		t.Fatalf("a symlink out of the folder was followed: %d %q", code, body)
	}
}

func TestShareNoteResolutionAndFlags(t *testing.T) {
	// Fresh share without --note has empty note.
	if got := resolveShareNote(nil, "", false); got != "" {
		t.Fatalf("fresh omit = %q want empty", got)
	}
	if got := resolveShareNote(nil, "  hello  ", true); got != "hello" {
		t.Fatalf("fresh --note = %q want hello", got)
	}
	// Bare restart preserves saved note; --note updates; --note "" clears.
	prev := &shareConfig{Note: "saved description"}
	if got := resolveShareNote(prev, "", false); got != "saved description" {
		t.Fatalf("restart without --note = %q want saved description", got)
	}
	if got := resolveShareNote(prev, "new note", true); got != "new note" {
		t.Fatalf("restart with --note = %q want new note", got)
	}
	if got := resolveShareNote(prev, "", true); got != "" {
		t.Fatalf("restart with --note '' = %q want empty", got)
	}

	// Flag parser tracks --note presence regardless of argument order.
	cases := []struct {
		args    []string
		wantPos []string
		note    string
		noteSet bool
		bg      bool
	}{
		{[]string{"share", "notes", "./dir"}, []string{"share", "notes", "./dir"}, "", false, false},
		{[]string{"share", "notes", "./dir", "--note", "Summer trip", "--background"}, []string{"share", "notes", "./dir"}, "Summer trip", true, true},
		{[]string{"share", "--note", "", "notes", "./dir"}, []string{"share", "notes", "./dir"}, "", true, false},
	}
	for _, tc := range cases {
		pos, o, ver, err := parseCLIArgs(tc.args)
		if err != nil || ver {
			t.Fatalf("parseCLIArgs(%v): ver=%v err=%v", tc.args, ver, err)
		}
		if strings.Join(pos, ",") != strings.Join(tc.wantPos, ",") || o.note != tc.note || o.noteSet != tc.noteSet || o.background != tc.bg {
			t.Fatalf("parseCLIArgs(%v) = pos:%v note:%q noteSet:%v bg:%v", tc.args, pos, o.note, o.noteSet, o.background)
		}
	}
}

func TestShareServiceTemplates(t *testing.T) {
	c := &shareConfig{Name: "blog", Zone: "bobo.hogman"}
	if got, pen := shareLaunchLabel(c), launchLabel(c.Zone); got == pen || got != "network.hogman.share.blog.bobo.hogman" {
		t.Fatalf("shareLaunchLabel = %q, pen label = %q", got, pen)
	}
	if got, pen := shareUnitName(c), unitName(c.Zone); got == pen || got != "hogman-share-blog.bobo.hogman.service" {
		t.Fatalf("shareUnitName = %q, pen unit = %q", got, pen)
	}

	bin := "/tmp/a & b/hogman-join"
	dir := "/tmp/dir <1> & 2/shares/blog"
	plist, err := renderShareLaunchPlist(c, bin, dir)
	if err != nil {
		t.Fatal(err)
	}
	var parsed any
	if err := xml.Unmarshal([]byte(plist), &parsed); err != nil {
		t.Fatalf("rendered share plist is not valid XML: %v\n%s", err, plist)
	}
	for _, want := range []string{
		"network.hogman.share.blog.bobo.hogman",
		"__share-run",
		"/tmp/a &amp; b/hogman-join",
		"/tmp/dir &lt;1&gt; &amp; 2/shares/blog",
		"/tmp/dir &lt;1&gt; &amp; 2/shares/blog/share.log",
		"<key>RunAtLoad</key><true/>",
		"<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>",
		"<key>ThrottleInterval</key><integer>30</integer>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("share plist missing %q:\n%s", want, plist)
		}
	}
	if strings.Contains(plist, "<key>KeepAlive</key><true/>") {
		t.Fatalf("share plist must not keep restarting on exit 0:\n%s", plist)
	}

	unit := renderShareSystemdUnit(c, `/tmp/bin "q"`, `/tmp/dir "x"\y`)
	for _, want := range []string{
		"Description=Hogman share (blog.bobo.hogman)",
		"StartLimitIntervalSec=300",
		"StartLimitBurst=5",
		`ExecStart="/tmp/bin \"q\"" __share-run "/tmp/dir \"x\"\\y"`,
		"Restart=on-failure",
		"RestartSec=30",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("share systemd unit missing %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "Restart=always") {
		t.Fatalf("share systemd unit must not use Restart=always:\n%s", unit)
	}
}

func TestSharePermanentErrorClassification(t *testing.T) {
	if got := shareExitCode(nil); got != 0 {
		t.Fatalf("shareExitCode(nil) = %d, want 0", got)
	}
	if got := shareExitCode(errors.New("transient dial error")); got != 1 {
		t.Fatalf("shareExitCode(transient) = %d, want 1", got)
	}
	perm := permanentShare(errorf("could not claim blog.bobo.hogman"))
	if !isPermanentShareError(perm) {
		t.Fatal("expected isPermanentShareError(perm) = true")
	}
	if got := shareExitCode(perm); got != 0 {
		t.Fatalf("shareExitCode(perm) = %d, want 0", got)
	}

	statusCases := []struct {
		code int
		want bool
	}{
		{0, false},
		{http.StatusBadRequest, true},
		{http.StatusForbidden, true},
		{http.StatusNotFound, true},
		{http.StatusConflict, true},
		{http.StatusRequestTimeout, false},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
		{http.StatusBadGateway, false},
		{http.StatusServiceUnavailable, false},
	}
	for _, tc := range statusCases {
		if got := isPermanentNameStatus(tc.code); got != tc.want {
			t.Fatalf("isPermanentNameStatus(%d) = %v, want %v", tc.code, got, tc.want)
		}
	}

	nodeCases := []struct {
		name       string
		hasAuthKey bool
		state      string
		err        error
		want       bool
	}{
		{"nil error", false, "NeedsLogin", nil, false},
		{"removed device needs login without key", false, "NeedsLogin", errors.New("context deadline exceeded"), true},
		{"fast-fail errDeviceRemoved", false, "", errDeviceRemoved, true},
		{"initial join with key briefly needs login", true, "NeedsLogin", errors.New("context deadline exceeded"), false},
		{"offline at boot while starting", false, "Starting", errors.New("context deadline exceeded"), false},
		{"invalid authkey message", true, "", errors.New("tsnet.Up: backend: invalid authkey"), true},
		{"transient network timeout", true, "", errors.New("dial tcp: i/o timeout"), false},
	}
	for _, tc := range nodeCases {
		if got := isPermanentNodeError(tc.hasAuthKey, tc.state, tc.err); got != tc.want {
			t.Fatalf("isPermanentNodeError(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestShareListState(t *testing.T) {
	cases := []struct {
		running, managed bool
		want             string
	}{
		{true, true, "running in the background, starts at login"},
		{true, false, "running in the background"},
		{false, true, "stopped (starts at login)"},
		{false, false, "not running"},
	}
	for _, tc := range cases {
		if got := shareListState(tc.running, tc.managed); got != tc.want {
			t.Fatalf("shareListState(%v, %v) = %q, want %q", tc.running, tc.managed, got, tc.want)
		}
	}
}

func TestWaitShareBackgroundCleansUpOnErrorAndTimeout(t *testing.T) {
	c := &shareConfig{Name: "blog", Zone: "bobo.hogman", Target: "http://127.0.0.1:3000"}

	// 1. Healthy "up" status -> returns nil without calling stopFn.
	upDir := t.TempDir()
	writeShareStatus(upDir, "up", "")
	stopped := false
	if err := waitShareBackground(upDir, c, true, 0, 100*time.Millisecond, func() { stopped = true }); err != nil {
		t.Fatalf("expected nil on up status, got %v", err)
	}
	if stopped {
		t.Fatal("stopFn should not be called when share comes up cleanly")
	}

	// 2. "error" status -> returns error AND calls stopFn to unload/cleanup service.
	errDir := t.TempDir()
	writeShareStatus(errDir, "error", "could not claim blog.bobo.hogman")
	stopped = false
	err := waitShareBackground(errDir, c, true, 0, 100*time.Millisecond, func() { stopped = true })
	if err == nil || !strings.Contains(err.Error(), "could not claim") {
		t.Fatalf("expected claim error, got %v", err)
	}
	if !stopped {
		t.Fatal("stopFn must be called when background share reports error")
	}

	// 3. Timed out while "starting" -> returns timeout error AND calls stopFn.
	slowDir := t.TempDir()
	writeShareStatus(slowDir, "starting", "")
	stopped = false
	err = waitShareBackground(slowDir, c, true, 0, 50*time.Millisecond, func() { stopped = true })
	if err == nil || !strings.Contains(err.Error(), "did not come up in time") {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if !stopped {
		t.Fatal("stopFn must be called when background share times out")
	}
}
