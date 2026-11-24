package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
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
		{[]string{"share", "notes", "./dir"}, []string{"notes", "./dir"}, "", false, false},
		{[]string{"share", "notes", "./dir", "--note", "Summer trip", "--background"}, []string{"notes", "./dir"}, "Summer trip", true, true},
		{[]string{"share", "--note", "", "notes", "./dir"}, []string{"notes", "./dir"}, "", true, false},
	}
	for _, tc := range cases {
		var gotName, gotTarget string
		var gotO options
		rc := runCLI(tc.args, cliHandlers{
			shareStart: func(name, target, _ string, o options) error {
				gotName, gotTarget, gotO = name, target, o
				return nil
			},
		})
		if rc != 0 {
			t.Fatalf("runCLI(%v) rc=%d", tc.args, rc)
		}
		if gotName != tc.wantPos[0] || gotTarget != tc.wantPos[1] || gotO.note != tc.note || gotO.noteSet != tc.noteSet || gotO.background != tc.bg {
			t.Fatalf("runCLI(%v) = (%q,%q) note:%q noteSet:%v bg:%v", tc.args, gotName, gotTarget, gotO.note, gotO.noteSet, gotO.background)
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

	bin := "/tmp/a & b/hogman"
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
		"/tmp/a &amp; b/hogman",
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

func TestFormatFreshShareCertErrorRateLimit(t *testing.T) {
	// Wrapped *meshAPIError 429 with Retry-After -> shows verbatim message + human hint.
	wrappedHourly := fmt.Errorf("certmagic: %w", dnsStepError{
		err: &meshAPIError{
			Status:     http.StatusTooManyRequests,
			Msg:        "too many new certificate names for this pen in the last hour",
			RetryAfter: 45 * time.Minute,
		},
	})
	got := formatFreshShareCertError("photos.bobo.pens.hogman.network", "photos", wrappedHourly).Error()
	if !strings.Contains(got, "too many new certificate names for this pen in the last hour") {
		t.Fatalf("missing verbatim message: %s", got)
	}
	if !strings.Contains(got, "try again in about 45 minutes") {
		t.Fatalf("missing retry hint: %s", got)
	}
	if !strings.Contains(got, "the name photos is free again") {
		t.Fatalf("missing rollback note: %s", got)
	}

	// Global hourly cap with short Retry-After.
	wrappedGlobal := &meshAPIError{
		Status:     http.StatusTooManyRequests,
		Msg:        "the network is busy; too many new certificate names in the last hour",
		RetryAfter: 30 * time.Second,
	}
	got = formatFreshShareCertError("photos.bobo.pens.hogman.network", "photos", wrappedGlobal).Error()
	if !strings.Contains(got, "try again in about 1 minute") {
		t.Fatalf("short retry hint wrong: %s", got)
	}

	// Weekly cap (~6 days).
	wrappedWeekly := &meshAPIError{
		Status:     http.StatusTooManyRequests,
		Msg:        "this pen's weekly limit on new certificate names is reached",
		RetryAfter: 6 * 24 * time.Hour,
	}
	got = formatFreshShareCertError("photos.bobo.pens.hogman.network", "photos", wrappedWeekly).Error()
	if !strings.Contains(got, "try again in about 6 days") {
		t.Fatalf("weekly retry hint wrong: %s", got)
	}

	// Non-429 error keeps original format.
	got = formatFreshShareCertError("photos.bobo.pens.hogman.network", "photos", errors.New("dns timeout")).Error()
	if !strings.Contains(got, "Fix the problem above") {
		t.Fatalf("non-429 error changed unexpectedly: %s", got)
	}
}

func TestShareTargetLocalAndLANPolicy(t *testing.T) {
	allowed := []string{
		"3000",
		"http://localhost:8080/",
		"https://localhost:8443/app",
		"http://127.0.0.1:8080",
		"http://[::1]:8080/",
		"http://192.168.1.40",
		"http://10.0.0.5:8080",
		"http://172.16.4.10:9000",
		"http://[fd12:3456:789a::1]:8080",
		"http://169.254.10.20:8080",
		"http://cooler-1.local:8080",
	}
	for _, in := range allowed {
		if _, folder, err := shareTarget(in); err != nil || folder {
			t.Errorf("shareTarget(%q) = folder=%v, err=%v; want allowed URL target", in, folder, err)
		}
	}

	rejected := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.170.2/v2/credentials",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://93.184.216.34/",
		"https://1.1.1.1/",
		"http://[2606:2800:220:1:248:1893:25c8:1946]/",
		"http://0.0.0.0:8080",
		"http://[::]:8080",
		"http://[::1%25en0]:8080",
	}
	for _, in := range rejected {
		if got, _, err := shareTarget(in); err == nil {
			t.Errorf("shareTarget(%q) succeeded (%q); want rejection", in, got)
		}
	}

	// LAN target must also be accepted by shareHandler (D-27 Work LAN bridging).
	if _, _, err := shareHandler(&shareConfig{Name: "cooler-1", Zone: "z.hogman", Target: "http://192.168.1.40"}); err != nil {
		t.Errorf("shareHandler rejected valid LAN target: %v", err)
	}
	// Public and metadata IPs persisted in share.json must be rejected by shareHandler.
	for _, bad := range []string{"http://93.184.216.34:80", "http://169.254.169.254", "http://metadata.google.internal"} {
		if _, _, err := shareHandler(&shareConfig{Name: "x", Zone: "z.hogman", Target: bad}); err == nil {
			t.Errorf("shareHandler(Target=%q) succeeded; want error", bad)
		}
	}
}

func TestLocalOrLANDialContext(t *testing.T) {
	// 1. Metadata IP literal is denied without dialing.
	dialed := ""
	dialFn := localOrLANDialContext(
		func(context.Context, string) ([]net.IPAddr, error) {
			t.Fatal("lookup should not run for IP literal")
			return nil, nil
		},
		func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return nil, errors.New("unexpected dial")
		},
	)
	if _, err := dialFn(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Fatal("expected metadata IP dial to fail")
	}
	if _, err := dialFn(context.Background(), "tcp", "93.184.216.34:443"); err == nil {
		t.Fatal("expected public IP dial to fail")
	}
	if dialed != "" {
		t.Fatalf("dial should not have been called for blocked IPs, got %q", dialed)
	}

	// 2. Hostname that resolves to a public IP (e.g. facebook.com / example.com) is denied.
	dialFn = localOrLANDialContext(
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		},
		func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return nil, errors.New("unexpected dial")
		},
	)
	if _, err := dialFn(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("expected hostname resolving to public IP to fail")
	}

	// 3. Hostname that resolves to a cloud metadata IP is denied.
	dialFn = localOrLANDialContext(
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
		},
		func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return nil, errors.New("unexpected dial")
		},
	)
	if _, err := dialFn(context.Background(), "tcp", "cooler.local:80"); err == nil {
		t.Fatal("expected hostname resolving to metadata IP to fail")
	}
	if dialed != "" {
		t.Fatalf("dial should not have been called for blocked resolutions, got %q", dialed)
	}

	// 4. LAN IP literal (RFC 1918) is allowed and dialed directly.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	dialFn = localOrLANDialContext(
		func(context.Context, string) ([]net.IPAddr, error) {
			t.Fatal("lookup should not run for IP literal")
			return nil, nil
		},
		func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return c1, nil
		},
	)
	conn, err := dialFn(context.Background(), "tcp", "192.168.1.40:80")
	if err != nil {
		t.Fatalf("expected RFC 1918 LAN dial to succeed, got %v", err)
	}
	if conn != c1 || dialed != "192.168.1.40:80" {
		t.Fatalf("dialed=%q want 192.168.1.40:80", dialed)
	}

	// 5. Hostname resolving to loopback or LAN IP is allowed and dialed by literal IP.
	dialed = ""
	dialFn = localOrLANDialContext(
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.0.1.25")}}, nil
		},
		func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return c1, nil
		},
	)
	if _, err := dialFn(context.Background(), "tcp", "cooler-1.local:8080"); err != nil || dialed != "10.0.1.25:8080" {
		t.Fatalf("LAN hostname dial = (%q, %v), want 10.0.1.25:8080", dialed, err)
	}
}

func TestShareCertLogNotice(t *testing.T) {
	got := formatShareCertLogNotice("blog.alpha.pens.example.com")
	if !strings.Contains(got, "blog.alpha.pens.example.com") || !strings.Contains(got, "certificate logs") || strings.Contains(got, "Certificate Transparency") {
		t.Fatalf("unexpected share cert log notice: %q", got)
	}
	if !strings.Contains(shareUsage, "certificate logs") {
		t.Fatalf("shareUsage missing certificate logs warning")
	}
}
