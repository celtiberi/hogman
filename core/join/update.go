package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"hogman/join/internal/agent"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/nativehost"
	"hogman/join/internal/penapi"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
)

const updateUsage = `hogman update: update hogman from GitHub Releases (or a pen's server)

usage:
  hogman update ['<link|host>']

By default, resolves the latest immutable release on GitHub
(celtiberi/hogman), verifies the matching binary against
hogman-SHA256SUMS over HTTPS, updates this computer's joined pen agents
(restarting them if running), and updates cached share and browser-host
binaries. Works even when this computer is not on any pen yet.

Pass a pen's host/link or --pen ZONE to update from a pen's server instead
(for firewalled networks or private test pens).

options:
  --pen ZONE        update from one specific pen's server instead of GitHub Releases
  --dry-run         check checksums and show what would change without modifying files
  --no-service      keep restarted agents in the background rather than a login item
  --control-ca FILE extra certificate to trust for a custom server
`

const (
	defaultReleaseBase = "https://github.com/celtiberi/hogman/releases"
	maxLatestTagBytes  = 16 << 10  // 16 KiB
	maxSHA256SUMSBytes = 64 << 10  // 64 KiB
	maxBinaryBytes     = 256 << 20 // 256 MiB
)

var releaseVersionRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]*$`)

func effectiveReleaseBase() (baseURL, host string, err error) {
	raw := strings.TrimSpace(os.Getenv("HOGMAN_RELEASE_BASE"))
	if raw == "" {
		raw = defaultReleaseBase
	}
	raw = strings.TrimRight(raw, "/")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", "", errorf("invalid release base URL %q (must be https:// without credentials)", raw)
	}
	return u.String(), strings.ToLower(u.Host), nil
}

func validateReleaseVersion(raw string) (ver, tag string, err error) {
	v := strings.TrimSpace(strings.TrimRight(raw, "\r\n"))
	v = strings.TrimPrefix(v, "v")
	if v == "" || !releaseVersionRE.MatchString(v) || strings.Contains(v, "..") {
		return "", "", errorf("unexpected release version %q", raw)
	}
	return v, "v" + v, nil
}

func allowedUpdateRedirectHost(expectedHost, gotHost string) bool {
	if strings.EqualFold(gotHost, expectedHost) {
		return true
	}
	if strings.EqualFold(expectedHost, "github.com") {
		return strings.EqualFold(gotHost, "objects.githubusercontent.com") ||
			strings.EqualFold(gotHost, "release-assets.githubusercontent.com")
	}
	return false
}

func platformBinaryName(goos, goarch string) (string, error) {
	switch goos + "/" + goarch {
	case "darwin/arm64":
		return "hogman-Darwin-arm64", nil
	case "darwin/amd64":
		return "hogman-Darwin-x86_64", nil
	case "linux/amd64":
		return "hogman-Linux-x86_64", nil
	case "linux/arm64":
		return "hogman-Linux-aarch64", nil
	case "windows/amd64":
		return "hogman-windows-amd64.exe", nil
	default:
		return "", errorf("automatic updates are not built for %s/%s", goos, goarch)
	}
}

func parseUpdateSourceURL(raw string) (baseURL, host string, err error) {
	raw = link.TrimMatchingQuotes(raw)
	if raw == "" {
		return "", "", errorf("empty update source")
	}
	if parsed, err := link.Parse(raw); err == nil {
		return "https://" + parsed.Host, parsed.Host, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", errorf("not a valid server address or link: %v", err)
	}
	if u.User != nil {
		return "", "", errorf("the server address must not contain credentials")
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", "", errorf("the server address must use https:// (got %q)", raw)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errorf("expected https://<host> or a full /join link, got %q", raw)
	}
	host = strings.ToLower(u.Host)
	return "https://" + host, host, nil
}

func parseSHA256SUMS(data []byte, wantFile string) (string, error) {
	var found string
	sawLegacyName := false
	lines := strings.Split(string(data), "\n")
	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(line) < 66 {
			continue
		}
		digest := line[:64]
		sep := line[64:66]
		if sep != "  " && sep != " *" {
			continue
		}
		name := line[66:]
		if filepath.Base(name) != name || name == "." || name == ".." {
			continue
		}
		b, err := hex.DecodeString(digest)
		if err != nil || len(b) != sha256.Size {
			continue
		}
		if strings.HasPrefix(name, "hogman-join-") {
			sawLegacyName = true
		}
		if name == wantFile {
			if found != "" {
				return "", errorf("SHA256SUMS lists %s more than once", wantFile)
			}
			found = strings.ToLower(hex.EncodeToString(b))
		}
	}
	if found == "" {
		if sawLegacyName && strings.HasPrefix(wantFile, "hogman-") {
			return "", errorf("this pen's server is on an older release (SHA256SUMS lists hogman-join-* instead of %s).\n"+
				"  Run 'hogman update' (without --pen) to update from GitHub Releases.", wantFile)
		}
		return "", errorf("SHA256SUMS has no checksum entry for %s", wantFile)
	}
	return found, nil
}

func updateHTTPClient(caFile, caPEM, expectedHost string, timeout time.Duration) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		c, err := penapi.ControlClient(caFile)
		if err != nil {
			return nil, err
		}
		tr = c.Transport.(*http.Transport)
	} else if caPEM != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errorf("saved control CA certificate is unreadable")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if !strings.EqualFold(req.URL.Scheme, "https") || !allowedUpdateRedirectHost(expectedHost, req.URL.Host) {
				return fmt.Errorf("refusing redirect to %s", req.URL.Redacted())
			}
			return nil
		},
	}, nil
}

func fetchLatestReleaseTag(client *http.Client, releaseBase string) (ver, tag, dlBase string, err error) {
	urlStr := strings.TrimRight(releaseBase, "/") + "/latest/download/latest"
	resp, err := client.Get(urlStr)
	if err != nil {
		return "", "", "", errorf("cannot reach GitHub Releases at %s: %v\n"+
			"  To update from a pen's server instead: hogman update --pen <zone> or hogman update 'https://<pen-host>'", urlStr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", "", errorf("GitHub Releases returned HTTP %d for %s\n"+
			"  To update from a pen's server instead: hogman update --pen <zone> or hogman update 'https://<pen-host>'", resp.StatusCode, urlStr)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxLatestTagBytes+1))
	if err != nil {
		return "", "", "", errorf("failed reading latest release version: %v", err)
	}
	if len(data) > maxLatestTagBytes {
		return "", "", "", errorf("latest release pointer exceeds size limit")
	}
	ver, tag, err = validateReleaseVersion(string(data))
	if err != nil {
		return "", "", "", err
	}
	return ver, tag, strings.TrimRight(releaseBase, "/") + "/download/" + tag, nil
}

func fetchExpectedSHA256URL(client *http.Client, urlStr, binName string) (string, error) {
	resp, err := client.Get(urlStr)
	if err != nil {
		return "", errorf("cannot reach %s: %v", urlStr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errorf("server returned HTTP %d for %s", resp.StatusCode, urlStr)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSHA256SUMSBytes+1))
	if err != nil {
		return "", errorf("failed reading SHA256SUMS: %v", err)
	}
	if len(data) > maxSHA256SUMSBytes {
		return "", errorf("SHA256SUMS exceeds size limit")
	}
	return parseSHA256SUMS(data, binName)
}

func digestEqualHex(a, b string) bool {
	ab, errA := hex.DecodeString(a)
	bb, errB := hex.DecodeString(b)
	return errA == nil && errB == nil && len(ab) == sha256.Size && len(bb) == sha256.Size && subtle.ConstantTimeCompare(ab, bb) == 1
}

func downloadVerifiedBinaryURL(client *http.Client, urlStr, binName, wantHex, tmpDir string) (string, error) {
	resp, err := client.Get(urlStr)
	if err != nil {
		return "", errorf("failed downloading %s: %v", urlStr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errorf("server returned HTTP %d for %s", resp.StatusCode, urlStr)
	}
	f, err := os.CreateTemp(tmpDir, "download-*")
	if err != nil {
		return "", err
	}
	tmpPath := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxBinaryBytes+1))
	if err != nil {
		return "", errorf("failed downloading %s: %v", binName, err)
	}
	if n == 0 {
		return "", errorf("downloaded %s was empty", binName)
	}
	if n > maxBinaryBytes {
		return "", errorf("downloaded %s exceeds %d MiB size limit", binName, maxBinaryBytes>>20)
	}
	gotHex := strings.ToLower(hex.EncodeToString(h.Sum(nil)))
	if !digestEqualHex(gotHex, wantHex) {
		return "", errorf("downloaded %s failed SHA-256 verification: expected %s, got %s", binName, wantHex, gotHex)
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	keep = true
	return tmpPath, nil
}

func stageAndVerify(srcPath, dstPath, wantHex string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dstDir := filepath.Dir(dstPath)
	tmp, err := os.CreateTemp(dstDir, ".hogman-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), src)
	if err != nil {
		return err
	}
	if n == 0 {
		return errorf("refusing to install empty binary at %s", dstPath)
	}
	gotHex := strings.ToLower(hex.EncodeToString(h.Sum(nil)))
	if !digestEqualHex(gotHex, wantHex) {
		return errorf("staged binary for %s failed SHA-256 check (%s != %s)", dstPath, gotHex, wantHex)
	}
	if err := tmp.Chmod(0o755); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := fsutil.ReplaceExecutable(tmpPath, dstPath); err != nil {
		return err
	}
	keep = true
	return nil
}

func checkDirWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".hogman-perm-check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

type penTarget struct {
	zone string
	dir  string
	cfg  *state.AgentConfig
}

type shareTargetDir struct {
	zone string
	name string
	dir  string
	cfg  *state.ShareConfig
}

type updatePlan struct {
	fromRelease bool
	releaseBase string
	baseURL     string
	host        string
	controlCA   string
	pens        []penTarget
	shares      []shareTargetDir
}

func loadPenTargets(configBase string) []penTarget {
	scanned := state.ScanInstalledPens(configBase)
	var pens []penTarget
	for _, p := range scanned.Pens {
		if p.Config.LoginServer != "" {
			pens = append(pens, penTarget{zone: p.Zone, dir: p.Dir, cfg: p.Config})
		}
	}
	return pens
}

func loadLocalTargets(configBase, sharesDir string) ([]penTarget, []shareTargetDir) {
	pens := loadPenTargets(configBase)
	var shares []shareTargetDir
	if pattern, err := filepath.Glob(filepath.Join(sharesDir, "*", "*", "share.json")); err == nil {
		sort.Strings(pattern)
		for _, f := range pattern {
			dir := filepath.Dir(f)
			if c, err := state.LoadShare(dir); err == nil && c.LoginServer != "" &&
				c.Zone != "" && c.Name != "" &&
				c.Zone == filepath.Base(filepath.Dir(dir)) && c.Name == filepath.Base(dir) {
				shares = append(shares, shareTargetDir{zone: c.Zone, name: c.Name, dir: dir, cfg: c})
			}
		}
	}
	return pens, shares
}

func resolveUpdatePlan(args []string, o options, configBase, sharesDir string) (*updatePlan, error) {
	allPens, allSharesList := loadLocalTargets(configBase, sharesDir)
	penFilter := ""
	if strings.TrimSpace(o.pen) != "" {
		var err error
		penFilter, err = link.ValidatePenQuery(o.pen)
		if err != nil {
			return nil, err
		}
	}

	// Default (no explicit server/link and no --pen): update from immutable
	// GitHub Releases (works with 0, 1, or N pens and updates every local copy).
	if len(args) == 0 && penFilter == "" {
		relBase, relHost, err := effectiveReleaseBase()
		if err != nil {
			return nil, err
		}
		return &updatePlan{
			fromRelease: true,
			releaseBase: relBase,
			host:        relHost,
			pens:        allPens,
			shares:      allSharesList,
		}, nil
	}

	if len(args) == 1 {
		baseURL, host, err := parseUpdateSourceURL(args[0])
		if err != nil {
			return nil, err
		}
		plan := &updatePlan{baseURL: baseURL, host: host}
		var matchedZones []string
		seenZone := map[string]bool{}
		for _, p := range allPens {
			if penFilter != "" && !link.PenMatchesQuery(p.zone, p.cfg.LoginServer, penFilter) {
				continue
			}
			if !seenZone[p.zone] {
				seenZone[p.zone] = true
				matchedZones = append(matchedZones, p.zone)
			}
			if penFilter != "" && p.cfg.LoginServer != baseURL {
				return nil, errorf("%s uses %s, not %s", p.zone, p.cfg.LoginServer, baseURL)
			}
			if p.cfg.LoginServer == baseURL {
				plan.pens = append(plan.pens, p)
				if plan.controlCA == "" && p.cfg.ControlCA != "" {
					plan.controlCA = p.cfg.ControlCA
				}
			}
		}
		for _, s := range allSharesList {
			if penFilter != "" && !link.PenMatchesQuery(s.zone, s.cfg.LoginServer, penFilter) {
				continue
			}
			if !seenZone[s.zone] {
				seenZone[s.zone] = true
				matchedZones = append(matchedZones, s.zone)
			}
			if penFilter != "" && s.cfg.LoginServer != baseURL {
				return nil, errorf("%s uses %s, not %s", s.zone, s.cfg.LoginServer, baseURL)
			}
			if s.cfg.LoginServer == baseURL {
				plan.shares = append(plan.shares, s)
				if plan.controlCA == "" && s.cfg.ControlCA != "" {
					plan.controlCA = s.cfg.ControlCA
				}
			}
		}
		if penFilter != "" && len(matchedZones) == 0 {
			return nil, errorf("this computer is not on %s", penFilter)
		}
		if penFilter != "" && len(matchedZones) > 1 {
			sort.Strings(matchedZones)
			return nil, errorf("%q matches more than one pen (%s); pass the full zone name with --pen", penFilter, strings.Join(matchedZones, ", "))
		}
		return plan, nil
	}

	type source struct {
		baseURL   string
		controlCA string
	}
	sources := map[string]source{}
	zonesSeen := map[string]struct{}{}
	var matchedPens []penTarget
	var matchedShares []shareTargetDir

	for _, p := range allPens {
		if penFilter != "" && !link.PenMatchesQuery(p.zone, p.cfg.LoginServer, penFilter) {
			continue
		}
		matchedPens = append(matchedPens, p)
		zonesSeen[p.zone] = struct{}{}
		cur := sources[p.cfg.LoginServer]
		cur.baseURL = p.cfg.LoginServer
		if cur.controlCA == "" && p.cfg.ControlCA != "" {
			cur.controlCA = p.cfg.ControlCA
		}
		sources[p.cfg.LoginServer] = cur
	}
	for _, s := range allSharesList {
		if penFilter != "" && !link.PenMatchesQuery(s.zone, s.cfg.LoginServer, penFilter) {
			continue
		}
		matchedShares = append(matchedShares, s)
		zonesSeen[s.zone] = struct{}{}
		cur := sources[s.cfg.LoginServer]
		cur.baseURL = s.cfg.LoginServer
		if cur.controlCA == "" && s.cfg.ControlCA != "" {
			cur.controlCA = s.cfg.ControlCA
		}
		sources[s.cfg.LoginServer] = cur
	}

	if len(sources) == 0 {
		if penFilter != "" {
			return nil, errorf("this computer is not on %s", penFilter)
		}
		return nil, errorf("this computer is not on any pen yet. Pass a link or host: hogman update 'https://<host>'")
	}
	if len(zonesSeen) > 1 && penFilter != "" {
		zones := make([]string, 0, len(zonesSeen))
		for z := range zonesSeen {
			zones = append(zones, z)
		}
		sort.Strings(zones)
		return nil, errorf("%q matches more than one pen (%s); pass the full zone name with --pen", penFilter, strings.Join(zones, ", "))
	}
	if len(sources) > 1 {
		zones := make([]string, 0, len(zonesSeen))
		for z := range zonesSeen {
			zones = append(zones, z)
		}
		sort.Strings(zones)
		return nil, errorf("this computer is on more than one pen (%s); pick one with --pen ZONE or pass a server address", strings.Join(zones, ", "))
	}

	var only source
	for _, s := range sources {
		only = s
	}
	baseURL, host, err := parseUpdateSourceURL(only.baseURL)
	if err != nil {
		return nil, errorf("saved server address %q is invalid: %v", only.baseURL, err)
	}
	return &updatePlan{
		baseURL:   baseURL,
		host:      host,
		controlCA: only.controlCA,
		pens:      matchedPens,
		shares:    matchedShares,
	}, nil
}

// agentRunning reports whether this pen's agent process is alive: either its
// local /status endpoint answers for this zone (whether online, still
// connecting, or holding a startup error) or its recorded agent.pid is alive.
func agentRunning(dir string, c *state.AgentConfig) bool {
	if _, err := agent.State(c); err == nil {
		return true
	}
	b, err := os.ReadFile(filepath.Join(dir, "agent.pid"))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && pid > 0 && platform.ProcessAlive(pid)
}

type penUpdateOps struct {
	isRunning      func(dir string, c *state.AgentConfig) bool
	runningStale   func(p *penTarget) bool
	hasService     func(zone string) bool
	probeReachable func(p *penTarget, o options) error
	stop           func(dir string, c *state.AgentConfig)
	startNoWait    func(p *penTarget, binPath string, hadService bool, o options) error
	restartNew     func(p *penTarget, binPath string, hadService bool, o options) error
	restartOld     func(p *penTarget, binPath string, hadService bool, o options) error
	rewriteService func(binPath, dir string, c *state.AgentConfig) error
}

// agentRunningStaleBinary reports whether p's running agent is executing a
// different binary than wantHex (including older agents that don't report
// bin_sha256 yet), so `hogman update` self-heals stale agents even when the
// on-disk binaries are already up to date (I-20).
func agentRunningStaleBinary(p *penTarget, wantHex string) bool {
	if p == nil || p.cfg == nil || wantHex == "" {
		return false
	}
	st, err := agent.State(p.cfg)
	if err != nil {
		return false
	}
	return !digestEqualHex(st.BinSHA256, wantHex)
}

func defaultPenUpdateOps() penUpdateOps {
	return penUpdateOps{
		isRunning:      agentRunning,
		hasService:     platform.ServiceConfigured,
		probeReachable: probePenLoginServer,
		stop:           platform.StopAgent,
		startNoWait: func(p *penTarget, binPath string, hadService bool, o options) error {
			return platform.StartExistingBinary(binPath, p.dir, p.cfg, o.noService || !hadService, note)
		},
		restartNew:     restartPenAgent,
		restartOld:     restartOldPenAgent,
		rewriteService: platform.RewriteAgentService,
	}
}

// probePenLoginServer does a quick (4s) pre-flight check against the pen's
// public control host so `hogman update` doesn't stall for 60s waiting on
// tsnet.Up for a pen that has been deleted, stopped, or put to sleep (I-10).
func probePenLoginServer(p *penTarget, o options) error {
	if p == nil || p.cfg == nil || strings.TrimSpace(p.cfg.LoginServer) == "" {
		return errors.New("missing server address")
	}
	baseURL, host, err := parseUpdateSourceURL(p.cfg.LoginServer)
	if err != nil {
		return err
	}
	c, err := updateHTTPClient(o.controlCA, p.cfg.ControlCA, host, 4*time.Second)
	if err != nil {
		return err
	}
	resp, err := c.Get(baseURL + "/hogman/v1/network")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return fmt.Errorf("pen server returned HTTP 503 (sleeping or stopped)")
	}
	return fmt.Errorf("pen server returned HTTP %d", resp.StatusCode)
}

func restartPenAgent(p *penTarget, binPath string, hadService bool, o options) error {
	noService := o.noService || !hadService
	logPath := filepath.Join(p.dir, "agent.log")
	if err := platform.StartExistingBinary(binPath, p.dir, p.cfg, noService, note); err != nil {
		return errorf("updated %s, but its new agent could not start: %v.\n"+
			"  Log: %s\n"+
			"  To get back on: run 'hogman update' again, or re-run hogman with your link.",
			p.zone, err, logPath)
	}
	if _, err := agent.WaitUp(p.cfg, 60*time.Second); err != nil {
		return errorf("updated %s, but its new agent did not come online: %v.\n"+
			"  Log: %s\n"+
			"  To get back on: fix what the log shows and run 'hogman agent %s', or re-run hogman with your link.",
			p.zone, err, logPath, p.dir)
	}
	note("%s agent restarted", p.zone)
	return nil
}

func restartOldPenAgent(p *penTarget, binPath string, hadService bool, o options) error {
	noService := o.noService || !hadService
	if err := platform.StartExistingBinary(binPath, p.dir, p.cfg, noService, note); err != nil {
		return err
	}
	_, err := agent.WaitUp(p.cfg, 30*time.Second)
	return err
}

type shareUpdateOps struct {
	isRunning      func(dir string) bool
	hasService     func(c *state.ShareConfig) bool
	stop           func(dir string, c *state.ShareConfig)
	restartNew     func(s *shareTargetDir, binPath string, o options) error
	restartOld     func(s *shareTargetDir, binPath string, o options) error
	rewriteService func(binPath, dir string, c *state.ShareConfig) error
}

func defaultShareUpdateOps() shareUpdateOps {
	return shareUpdateOps{
		isRunning:  func(dir string) bool { return sharePID(dir) != 0 },
		hasService: platform.ShareServiceConfigured,
		stop:       stopShare,
		restartNew: func(s *shareTargetDir, binPath string, o options) error {
			return restartShareService(s, binPath, o, true)
		},
		restartOld: func(s *shareTargetDir, binPath string, o options) error {
			return restartShareService(s, binPath, o, false)
		},
		rewriteService: platform.RewriteShareService,
	}
}

func restartShareService(s *shareTargetDir, binPath string, o options, updated bool) error {
	_ = os.Remove(filepath.Join(s.dir, "status.json"))
	_ = os.Remove(filepath.Join(s.dir, "share.pid"))
	managed, pid, err := platform.StartShareServiceWithBinary(binPath, s.dir, s.cfg, o.noService, note)
	if err != nil {
		return err
	}
	// Never pass stopShare as stopFn during update: a slow reconnect or transient
	// network hiccup must not unregister a previously working share's login service.
	if err := waitShareBackground(s.dir, s.cfg, managed, pid, 90*time.Second, nil); err != nil {
		return err
	}
	if updated {
		note("%s share restarted", s.cfg.FQDN())
	} else {
		note("restarted the previous %s share so it stays online", s.cfg.FQDN())
	}
	return nil
}

var wingetPackageIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)

// wingetPackageIDFromPath extracts the WinGet package ID from an install path
// under ...\Microsoft\WinGet\Packages\<Id>\... or
// ...\Microsoft\WinGet\Packages\<Id>_<SourceId>\..., returning "" when no
// valid package folder ID can be parsed.
func wingetPackageIDFromPath(slashPath string) string {
	segs := strings.Split(slashPath, "/")
	for i := 0; i+4 < len(segs); i++ {
		if strings.EqualFold(segs[i], "microsoft") &&
			strings.EqualFold(segs[i+1], "winget") &&
			strings.EqualFold(segs[i+2], "packages") {
			id, _, _ := strings.Cut(segs[i+3], "_")
			if wingetPackageIDRe.MatchString(id) {
				return id
			}
			return ""
		}
	}
	return ""
}

// detectPackageManager reports whether exePath appears to be installed and
// managed by a system or user package manager (Homebrew, Scoop, WinGet, or OS
// packages under /usr/bin) so `update` refuses to overwrite it in place.
func detectPackageManager(exePath, goos string) (name, upgradeCmd string, ok bool) {
	p := filepath.ToSlash(strings.ReplaceAll(exePath, "\\", "/"))
	lp := strings.ToLower(p)
	if goos == "darwin" || goos == "linux" {
		if strings.HasPrefix(p, "/opt/homebrew/Cellar/") ||
			strings.HasPrefix(p, "/usr/local/Cellar/") ||
			strings.Contains(p, "/.linuxbrew/Cellar/") {
			return "Homebrew", "brew upgrade hogman", true
		}
		if p == "/usr/bin/hogman" || p == "/usr/bin/hogman-join" {
			return "your system package manager", "upgrade via your OS package manager", true
		}
	}
	if goos == "windows" {
		if strings.Contains(lp, "/scoop/apps/") {
			return "Scoop", "scoop update hogman", true
		}
		if strings.Contains(lp, "/microsoft/winget/packages/") {
			if id := wingetPackageIDFromPath(p); id != "" {
				return "winget", "winget upgrade --id " + id, true
			}
			return "winget", "winget upgrade hogman", true
		}
	}
	return "", "", false
}

var versionQueryTimeout = 5 * time.Second

// queryBinaryVersionLine runs `<bin> --version` with a short timeout and
// returns its output as a sanitized single line (joining any extra lines with
// "; " rather than dropping them).
func queryBinaryVersionLine(binPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), versionQueryTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, "--version").Output()
	if err != nil {
		return ""
	}
	return link.SingleLine(string(out))
}

// queryBinaryVersion extracts the version token from `<bin> --version`
// (e.g. "2026.11.24" from "hogman 2026.11.24 darwin/arm64").
func queryBinaryVersion(binPath string) string {
	fields := strings.Fields(queryBinaryVersionLine(binPath))
	if len(fields) >= 2 {
		return strings.TrimPrefix(fields[1], "v")
	}
	return ""
}

func pensOutsidePlan(configBase string, inPlan []penTarget) []string {
	planned := make(map[string]bool, len(inPlan))
	for _, p := range inPlan {
		planned[p.zone] = true
	}
	var others []string
	for _, p := range loadPenTargets(configBase) {
		if !planned[p.zone] {
			others = append(others, p.zone)
		}
	}
	return others
}

// compareReleaseVersions compares two dot-separated numeric release versions
// (such as "2026.11.24-d17d2f9" or "0.2.1"). Returns (-1/0/+1, true) when both
// strings parse as numeric release versions and can be ordered unambiguously,
// or (0, false) for "dev"/non-numeric builds or two builds sharing the same
// date/numeric prefix with different suffixes (e.g. different commit SHAs on
// the same day, where order cannot be inferred from the string alone).
func compareReleaseVersions(a, b string) (int, bool) {
	parse := func(raw string) ([]int, string, bool) {
		s := strings.TrimPrefix(strings.TrimSpace(raw), "v")
		if s == "" {
			return nil, "", false
		}
		// Split optional suffix after '-' or '+'.
		suffix := ""
		if i := strings.IndexAny(s, "-+"); i >= 0 {
			suffix = s[i:]
			s = s[:i]
		}
		parts := strings.Split(s, ".")
		if len(parts) < 2 {
			return nil, "", false
		}
		nums := make([]int, len(parts))
		for i, p := range parts {
			if p == "" {
				return nil, "", false
			}
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 {
				return nil, "", false
			}
			nums[i] = n
		}
		return nums, suffix, true
	}
	pa, sufA, okA := parse(a)
	pb, sufB, okB := parse(b)
	if !okA || !okB {
		return 0, false
	}
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va < vb {
			return -1, true
		}
		if va > vb {
			return 1, true
		}
	}
	if sufA != sufB {
		return 0, false
	}
	return 0, true
}

// migrateAndRestartPen atomically transitions a pen's agent service to
// canonicalBin (rewriting its LaunchAgent/systemd unit and waiting for it to
// come online) and removes any legacy per-pen duplicate copy only after success.
// If the pen's server is unreachable (deleted/stopped/sleeping), it moves the
// login item to canonicalBin without waiting a minute for tsnet.Up and returns
// an actionable error telling the user how to remove a dead pen (I-10).
func migrateAndRestartPen(p *penTarget, canonicalBin, legacyBin, selfPath string, o options, ops penUpdateOps) error {
	running := ops.isRunning(p.dir, p.cfg)
	hadService := ops.hasService(p.cfg.Zone)
	interrupted, prevService := state.ReadUpdatingMarker(p.dir)
	if interrupted {
		running = true
		if prevService {
			hadService = true
		}
	}
	removeLegacy := func() {
		if legacyBin != "" && !fsutil.SameFilePath(legacyBin, selfPath) && !fsutil.SameFilePath(legacyBin, canonicalBin) {
			if _, err := os.Stat(legacyBin); err == nil {
				if err := os.Remove(legacyBin); err == nil {
					note("consolidated %s -> %s", legacyBin, canonicalBin)
				}
			}
		}
	}
	if running {
		if ops.probeReachable != nil {
			if perr := ops.probeReachable(p, o); perr != nil {
				// B1: "unreachable for 4s" may be a restarting server, sleeping pen,
				// or flaky Wi-Fi — start the new canonical agent normally so it
				// reconnects on its own, and skip only the 60s online wait.
				ops.stop(p.dir, p.cfg)
				state.ClearUpdatingMarker(p.dir)
				if ops.startNoWait != nil {
					if serr := ops.startNoWait(p, canonicalBin, hadService, o); serr != nil {
						return errorf("%s is unreachable (%v), and starting its new agent failed: %v.\n"+
							"  If this pen no longer exists, remove it with: hogman leave %s", p.zone, perr, serr, p.zone)
					}
					note("started %s on %s without waiting for it to come online (server unreachable)", p.zone, canonicalBin)
				} else if hadService && ops.rewriteService != nil {
					if rerr := ops.rewriteService(canonicalBin, p.dir, p.cfg); rerr != nil {
						return errorf("%s is unreachable (%v), and updating its login item failed: %v.\n"+
							"  If this pen no longer exists, remove it with: hogman leave %s", p.zone, perr, rerr, p.zone)
					}
				}
				removeLegacy()
				return errorf("%s is unreachable (%v); started %s without waiting for it to come online.\n"+
					"  If this pen no longer exists, remove it with: hogman leave %s", p.zone, perr, canonicalBin, p.zone)
			}
		}
		step("Restarting %s agent", p.zone)
		state.WriteUpdatingMarker(p.dir, hadService)
		ops.stop(p.dir, p.cfg)
		if err := ops.restartNew(p, canonicalBin, hadService, o); err != nil {
			// Stop any partially started new agent before rolling back so
			// systemd enable --now isn't a no-op and detached mode never leaves two agents.
			ops.stop(p.dir, p.cfg)
			if legacyBin != "" && ops.restartOld != nil {
				if _, serr := os.Stat(legacyBin); serr == nil {
					if rerr := ops.restartOld(p, legacyBin, hadService, o); rerr == nil {
						state.ClearUpdatingMarker(p.dir)
						note("restarted the previous %s agent so you stay connected", p.zone)
					}
				}
			}
			return errorf("%v\n  If this pen no longer exists, remove it with: hogman leave %s", err, p.zone)
		}
		state.ClearUpdatingMarker(p.dir)
	} else if hadService && ops.rewriteService != nil {
		if err := ops.rewriteService(canonicalBin, p.dir, p.cfg); err != nil {
			return errorf("could not update login item for %s: %v", p.zone, err)
		}
	}
	removeLegacy()
	return nil
}

type penMigrationResult struct {
	Zone string
	Err  error
}

// migratePensForUpdate migrates every pen in the plan, never stopping on the
// first pen that fails to come up so healthy pens still move to the new binary
// (I-10).
func migratePensForUpdate(pens []penTarget, serviceBin, selfPath string, legacyCopyIn func(string) string, forceAll bool, o options, ops penUpdateOps) []penMigrationResult {
	results := make([]penMigrationResult, 0, len(pens))
	for i := range pens {
		p := &pens[i]
		legacy := ""
		if legacyCopyIn != nil {
			legacy = legacyCopyIn(p.dir)
		}
		interrupted, _ := state.ReadUpdatingMarker(p.dir)
		stale := ops.runningStale != nil && ops.runningStale(p)
		if !forceAll && legacy == "" && !interrupted && !stale {
			continue
		}
		err := migrateAndRestartPen(p, serviceBin, legacy, selfPath, o, ops)
		if err != nil {
			note("✗ %s: %v", p.zone, err)
		} else {
			note("✓ %s migrated to %s", p.zone, serviceBin)
		}
		results = append(results, penMigrationResult{Zone: p.zone, Err: err})
	}
	return results
}

// migrateAndRestartShare atomically transitions a managed share to canonicalBin
// and removes any legacy per-share duplicate copy only after it is healthy.
func migrateAndRestartShare(s *shareTargetDir, canonicalBin, legacyBin, selfPath string, o options, ops shareUpdateOps) error {
	running := ops.isRunning(s.dir)
	managed := ops.hasService(s.cfg)
	interrupted, prevManaged := state.ReadUpdatingMarker(s.dir)
	if interrupted && prevManaged {
		running = true
		managed = true
	}
	if running && managed {
		step("Restarting %s share", s.cfg.FQDN())
		state.WriteUpdatingMarker(s.dir, true)
		ops.stop(s.dir, s.cfg)
		if err := ops.restartNew(s, canonicalBin, o); err != nil {
			ops.stop(s.dir, s.cfg)
			if legacyBin != "" && ops.restartOld != nil {
				if _, serr := os.Stat(legacyBin); serr == nil {
					if rerr := ops.restartOld(s, legacyBin, o); rerr == nil {
						state.ClearUpdatingMarker(s.dir)
					}
				}
			}
			return errorf("updated share binary, but restarting %s failed (%v).\n"+
				"  To bring it back up: hogman share %s %s",
				s.cfg.FQDN(), err, s.cfg.Name, s.cfg.Target)
		}
		state.ClearUpdatingMarker(s.dir)
	} else if running {
		note("share %s is still running the previous process; restart it when ready", s.cfg.URL())
		return nil
	} else if managed && ops.rewriteService != nil {
		if err := ops.rewriteService(canonicalBin, s.dir, s.cfg); err != nil {
			return errorf("could not update login item for share %s: %v", s.cfg.FQDN(), err)
		}
	}
	if legacyBin != "" && !fsutil.SameFilePath(legacyBin, selfPath) && !fsutil.SameFilePath(legacyBin, canonicalBin) {
		if _, err := os.Stat(legacyBin); err == nil {
			if err := os.Remove(legacyBin); err == nil {
				note("consolidated %s -> %s", legacyBin, canonicalBin)
			}
		}
	}
	return nil
}

func updateCmd(args []string, o options) error {
	if len(args) > 1 {
		return errorf("usage: hogman update [--pen ZONE] [--dry-run] ['<link|host>']")
	}
	binName, err := platformBinaryName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	selfPath, err := fsutil.ResolvedExePath()
	if err != nil {
		return err
	}

	configBase := state.ConfigBase()
	plan, err := resolveUpdatePlan(args, o, configBase, state.SharesBase())
	if err != nil {
		return err
	}

	metaClient, err := updateHTTPClient(o.controlCA, plan.controlCA, plan.host, 30*time.Second)
	if err != nil {
		return err
	}
	var sumsURL, binURL string
	if plan.fromRelease {
		step("Checking GitHub Releases for updates (%s)", binName)
		ver, tag, dlBase, err := fetchLatestReleaseTag(metaClient, plan.releaseBase)
		if err != nil {
			return err
		}
		note("latest release: %s (%s)", ver, tag)
		sumsURL = dlBase + "/hogman-SHA256SUMS"
		binURL = dlBase + "/" + binName
	} else {
		step("Checking %s for updates (%s)", plan.host, binName)
		sumsURL = plan.baseURL + "/join/dl/SHA256SUMS"
		binURL = plan.baseURL + "/join/dl/" + binName
	}
	wantHex, err := fetchExpectedSHA256URL(metaClient, sumsURL, binName)
	if err != nil {
		return err
	}
	note("expected SHA-256: %s", wantHex)

	selfHash, _ := fsutil.FileSHA256(selfPath)
	selfNeedsUpdate := !digestEqualHex(selfHash, wantHex)

	pkgMgr, pkgUpgradeCmd, pkgManaged := detectPackageManager(selfPath, runtime.GOOS)
	if selfNeedsUpdate && pkgManaged && !o.dryRun {
		return errorf("%s is managed by %s — upgrade with: %s\n"+
			"  (after upgrading, run '%s update' if any background agents need syncing)",
			selfPath, pkgMgr, pkgUpgradeCmd, cliBinaryName())
	}

	instName := state.InstalledBinaryName(runtime.GOOS)
	oldInstName := state.LegacyBinaryName(runtime.GOOS)
	canonicalBin := state.CanonicalBinaryPath(configBase)
	canonicalNeeded := len(plan.pens) > 0 || len(plan.shares) > 0
	if _, err := os.Stat(canonicalBin); err == nil {
		canonicalNeeded = true
	}
	nhBin := nativehost.BinaryPath(configBase)
	if _, err := os.Lstat(nhBin); err == nil {
		canonicalNeeded = true
	}
	canonicalNeedsUpdate := false
	if canonicalNeeded && !fsutil.SameFilePath(selfPath, canonicalBin) {
		h, _ := fsutil.FileSHA256(canonicalBin)
		canonicalNeedsUpdate = !digestEqualHex(h, wantHex)
	}

	nhNeedsUpdate := false
	if !fsutil.SameFilePath(selfPath, nhBin) {
		if fi, err := os.Lstat(nhBin); err == nil {
			if runtime.GOOS != "windows" {
				// On Unix, convert any old regular-file copy to a symlink to canonicalBin.
				nhNeedsUpdate = fi.Mode()&os.ModeSymlink == 0 || !fsutil.SameFilePath(canonicalBin, nhBin)
			} else {
				h, _ := fsutil.FileSHA256(nhBin)
				nhNeedsUpdate = !digestEqualHex(h, wantHex)
			}
		}
	}

	legacyCopyIn := func(dir string) string {
		for _, name := range []string{instName, oldInstName} {
			p := filepath.Join(dir, name)
			if fsutil.SameFilePath(p, selfPath) || fsutil.SameFilePath(p, canonicalBin) {
				continue
			}
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return ""
	}
	hasLegacyCopy := func(dir string) bool { return legacyCopyIn(dir) != "" }

	oldBinCanonical := filepath.Join(configBase, "bin", oldInstName)
	hasOldBinCanonical := false
	if !fsutil.SameFilePath(oldBinCanonical, selfPath) && !fsutil.SameFilePath(oldBinCanonical, canonicalBin) {
		if _, err := os.Stat(oldBinCanonical); err == nil {
			hasOldBinCanonical = true
		}
	}

	anyLegacy := hasOldBinCanonical
	anyInterrupted := false
	anyStaleAgent := false
	for i := range plan.pens {
		if hasLegacyCopy(plan.pens[i].dir) {
			anyLegacy = true
		}
		if interrupted, _ := state.ReadUpdatingMarker(plan.pens[i].dir); interrupted {
			anyInterrupted = true
		}
		if agentRunningStaleBinary(&plan.pens[i], wantHex) {
			anyStaleAgent = true
		}
	}
	for i := range plan.shares {
		if hasLegacyCopy(plan.shares[i].dir) {
			anyLegacy = true
		}
		if interrupted, _ := state.ReadUpdatingMarker(plan.shares[i].dir); interrupted {
			anyInterrupted = true
		}
	}

	anyUpdate := selfNeedsUpdate || canonicalNeedsUpdate || nhNeedsUpdate || anyLegacy || anyInterrupted || anyStaleAgent
	if !anyUpdate {
		say("\n✓ %s is already up to date (%s).", cliBinaryName(), wantHex)
		if !o.dryRun {
			warnMissingSystemProxyServices(state.LoadInstalledPenConfigs(configBase))
		}
		return nil
	}

	if o.dryRun {
		step("Dry run: nothing changed. Would update to %s:", wantHex)
		if selfNeedsUpdate {
			if pkgManaged {
				note("%s is managed by %s (upgrade with: %s)", selfPath, pkgMgr, pkgUpgradeCmd)
			} else {
				note("%s (current %s)", selfPath, formatDigest(selfHash))
			}
		}
		if canonicalNeedsUpdate {
			note("%s", canonicalBin)
		}
		if nhNeedsUpdate {
			note("%s", nhBin)
		}
		for i := range plan.pens {
			if legacy := legacyCopyIn(plan.pens[i].dir); legacy != "" {
				note("consolidate %s -> %s", legacy, canonicalBin)
			} else if agentRunningStaleBinary(&plan.pens[i], wantHex) {
				note("restart stale %s agent onto %s", plan.pens[i].zone, canonicalBin)
			}
		}
		for i := range plan.shares {
			if legacy := legacyCopyIn(plan.shares[i].dir); legacy != "" {
				note("consolidate %s -> %s", legacy, canonicalBin)
			}
		}
		if hasOldBinCanonical {
			note("consolidate %s -> %s", oldBinCanonical, canonicalBin)
		}
		return nil
	}

	if selfNeedsUpdate {
		if err := checkDirWritable(filepath.Dir(selfPath)); err != nil {
			return errorf("cannot update %s (%v). Move hogman to a writable folder or re-run with write permission", selfPath, err)
		}
	}
	if canonicalNeedsUpdate {
		if err := os.MkdirAll(filepath.Dir(canonicalBin), 0o700); err != nil {
			return errorf("cannot prepare %s: %v", filepath.Dir(canonicalBin), err)
		}
		if err := checkDirWritable(filepath.Dir(canonicalBin)); err != nil {
			return errorf("cannot update %s (%v)", canonicalBin, err)
		}
	}
	if nhNeedsUpdate {
		if err := checkDirWritable(filepath.Dir(nhBin)); err != nil {
			return errorf("cannot update %s (%v)", nhBin, err)
		}
	}

	verifiedSrc := selfPath
	if selfNeedsUpdate {
		tmpDir, err := os.MkdirTemp("", "hogman-update-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpDir)
		dlClient, err := updateHTTPClient(o.controlCA, plan.controlCA, plan.host, 5*time.Minute)
		if err != nil {
			return err
		}
		step("Downloading and verifying %s", binName)
		verifiedSrc, err = downloadVerifiedBinaryURL(dlClient, binURL, binName, wantHex, tmpDir)
		if err != nil {
			return err
		}
		note("checksum verified (%s)", wantHex)
		if err := stageAndVerify(verifiedSrc, selfPath, wantHex); err != nil {
			return errorf("could not replace %s: %v", selfPath, err)
		}
		note("updated %s", selfPath)
	}

	if canonicalNeedsUpdate {
		// Prevent `hogman update --pen X` from silently downgrading the shared
		// canonical binary used by other pens on this computer.
		if !plan.fromRelease {
			if otherPens := pensOutsidePlan(configBase, plan.pens); len(otherPens) > 0 {
				curVer := queryBinaryVersion(canonicalBin)
				newVer := queryBinaryVersion(verifiedSrc)
				if cmp, ok := compareReleaseVersions(newVer, curVer); ok && cmp < 0 {
					return errorf("refusing to downgrade shared binary %s (%s -> %s) from %s while other pens (%s) share it.\n"+
						"  Run 'hogman update' (without --pen) to update all pens from GitHub Releases.",
						canonicalBin, curVer, newVer, plan.host, strings.Join(otherPens, ", "))
				}
			}
		}
		if err := stageAndVerify(verifiedSrc, canonicalBin, wantHex); err != nil {
			return errorf("could not update %s: %v", canonicalBin, err)
		}
		note("updated %s", canonicalBin)
	}
	if nhNeedsUpdate {
		srcForNH := canonicalBin
		if !canonicalNeeded {
			srcForNH = verifiedSrc
		}
		if err := nativehost.InstallBinary(srcForNH, nhBin); err != nil {
			note("could not update %s: %v", nhBin, err)
		} else {
			note("updated %s", nhBin)
		}
	}

	// Atomically migrate and restart running pen agents and managed shares onto
	// canonicalBin, deleting legacy per-pen/share copies only after health checks pass.
	serviceBin := canonicalBin
	if fsutil.SameFilePath(selfPath, canonicalBin) || !canonicalNeeded {
		serviceBin = selfPath
	}
	ops := defaultPenUpdateOps()
	ops.runningStale = func(p *penTarget) bool { return agentRunningStaleBinary(p, wantHex) }
	shareOps := defaultShareUpdateOps()
	forceAll := selfNeedsUpdate || canonicalNeedsUpdate || hasOldBinCanonical
	penResults := migratePensForUpdate(plan.pens, serviceBin, selfPath, legacyCopyIn, forceAll, o, ops)
	var failedZones []string
	var failedShares []string
	for _, res := range penResults {
		if res.Err != nil {
			failedZones = append(failedZones, res.Zone)
		}
	}
	for i := range plan.shares {
		s := &plan.shares[i]
		legacy := legacyCopyIn(s.dir)
		interrupted, _ := state.ReadUpdatingMarker(s.dir)
		if !forceAll && legacy == "" && !interrupted {
			continue
		}
		if err := migrateAndRestartShare(s, serviceBin, legacy, selfPath, o, shareOps); err != nil {
			note("✗ share %s: %v", s.cfg.FQDN(), err)
			failedShares = append(failedShares, s.cfg.FQDN())
		} else {
			note("✓ share %s migrated to %s", s.cfg.FQDN(), serviceBin)
		}
	}
	if hasOldBinCanonical && len(failedZones) == 0 && len(failedShares) == 0 {
		if err := os.Remove(oldBinCanonical); err == nil {
			note("consolidated %s -> %s", oldBinCanonical, canonicalBin)
		}
	}

	// Warn if other installed pens were not part of this update plan (e.g. --pen
	// or an explicit host matching only one of several pens).
	if skipped := pensOutsidePlan(configBase, plan.pens); len(skipped) > 0 {
		note("shared binary %s updated from %s; other pens (%s) will use it on next restart (run 'hogman update' to update and restart all pens from GitHub Releases)",
			canonicalBin, plan.host, strings.Join(skipped, ", "))
	}

	if len(failedZones) > 0 || len(failedShares) > 0 {
		var parts []string
		if len(failedZones) > 0 {
			parts = append(parts, fmt.Sprintf("pen(s): %s (if gone, run 'hogman leave <pen>')", strings.Join(failedZones, ", ")))
		}
		if len(failedShares) > 0 {
			parts = append(parts, fmt.Sprintf("share(s): %s", strings.Join(failedShares, ", ")))
		}
		return errorf("updated binary (%s), but %s did not come back online", wantHex, strings.Join(parts, "; "))
	}

	if verLine := queryBinaryVersionLine(selfPath); verLine != "" {
		say("\n✓ Updated %s (SHA-256 %s).", verLine, wantHex)
	} else {
		say("\n✓ Updated hogman (SHA-256 %s).", wantHex)
	}
	warnMissingSystemProxyServices(state.LoadInstalledPenConfigs(configBase))
	return nil
}

func warnMissingSystemProxyServices(configs []*state.AgentConfig) {
	if len(configs) == 0 {
		return
	}
	sys := platform.DetectSystemProxyState(configs)
	if len(sys.MissingProxyServices) == 0 {
		return
	}
	if host := agent.PickPACHost(configs); host != nil {
		svcList := platform.FormatServiceList(sys.MissingProxyServices)
		say("\n! Automatic proxy configuration is not set on: %s", svcList)
		say("  In System Settings → Network → %s → Details… → Proxies, turn on \"Automatic proxy configuration\" and paste:", svcList)
		say("    %s", host.PACURL())
	}
}

func formatDigest(h string) string {
	if h == "" {
		return "missing"
	}
	return h
}
