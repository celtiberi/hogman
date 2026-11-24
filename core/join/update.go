package main

import (
	"bytes"
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

func installedBinaryName(goos string) string {
	if goos == "windows" {
		return "hogman.exe"
	}
	return "hogman"
}

func legacyBinaryName(goos string) string {
	if goos == "windows" {
		return "hogman-join.exe"
	}
	return "hogman-join"
}

func parseUpdateSourceURL(raw string) (baseURL, host string, err error) {
	raw = trimMatchingQuotes(raw)
	if raw == "" {
		return "", "", errorf("empty update source")
	}
	if link, err := ParseLink(raw); err == nil {
		return "https://" + link.Host, link.Host, nil
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
		if name == wantFile {
			if found != "" {
				return "", errorf("SHA256SUMS lists %s more than once", wantFile)
			}
			found = strings.ToLower(hex.EncodeToString(b))
		}
	}
	if found == "" {
		return "", errorf("SHA256SUMS has no checksum entry for %s", wantFile)
	}
	return found, nil
}

func updateHTTPClient(caFile, caPEM, expectedHost string, timeout time.Duration) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		c, err := controlClient(caFile)
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

func fetchExpectedSHA256(client *http.Client, baseURL, binName string) (string, error) {
	return fetchExpectedSHA256URL(client, baseURL+"/join/dl/SHA256SUMS", binName)
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

func downloadVerifiedBinary(client *http.Client, baseURL, binName, wantHex, tmpDir string) (string, error) {
	return downloadVerifiedBinaryURL(client, baseURL+"/join/dl/"+binName, binName, wantHex, tmpDir)
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
		return "", errorf("downloaded %s failed SHA-256 verification: expected %s, got %s", binName, wantHex[:12], gotHex[:12])
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	keep = true
	return tmpPath, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return strings.ToLower(hex.EncodeToString(h.Sum(nil))), nil
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
		return errorf("staged binary for %s failed SHA-256 check (%s != %s)", dstPath, gotHex[:12], wantHex[:12])
	}
	if err := tmp.Chmod(0o755); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceExecutable(tmpPath, dstPath); err != nil {
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
	cfg  *agentConfig
}

type shareTargetDir struct {
	zone string
	name string
	dir  string
	cfg  *shareConfig
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
	var pens []penTarget
	if pattern, err := filepath.Glob(filepath.Join(configBase, "*", "config.json")); err == nil {
		sort.Strings(pattern)
		for _, f := range pattern {
			dir := filepath.Dir(f)
			if c, err := loadAgentConfig(dir); err == nil && c.LoginServer != "" &&
				c.Zone != "" && c.Zone == filepath.Base(dir) && validPACZone(c.Zone) {
				pens = append(pens, penTarget{zone: c.Zone, dir: dir, cfg: c})
			}
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
			if c, err := loadShare(dir); err == nil && c.LoginServer != "" &&
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
		penFilter, err = validatePenQuery(o.pen)
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
			if penFilter != "" && !penMatchesQuery(p.zone, p.cfg.LoginServer, penFilter) {
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
			if penFilter != "" && !penMatchesQuery(s.zone, s.cfg.LoginServer, penFilter) {
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
		if penFilter != "" && !penMatchesQuery(p.zone, p.cfg.LoginServer, penFilter) {
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
		if penFilter != "" && !penMatchesQuery(s.zone, s.cfg.LoginServer, penFilter) {
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

func resolvedExePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if realPath, err := filepath.EvalSymlinks(exe); err == nil {
		return filepath.Clean(realPath), nil
	}
	return filepath.Clean(exe), nil
}

func sameFilePath(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}

// agentRunning reports whether this pen's agent process is alive: either its
// local /status endpoint answers for this zone (whether online, still
// connecting, or holding a startup error) or its recorded agent.pid is alive.
func agentRunning(dir string, c *agentConfig) bool {
	if _, err := agentState(c); err == nil {
		return true
	}
	b, err := os.ReadFile(filepath.Join(dir, "agent.pid"))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && pid > 0 && processAlive(pid)
}

type penUpdateOps struct {
	isRunning      func(dir string, c *agentConfig) bool
	hasService     func(zone string) bool
	stop           func(dir string, c *agentConfig)
	stage          func(srcPath, dstPath, wantHex string) error
	restartNew     func(p *penTarget, binPath string, hadService bool, o options) error
	restartOld     func(p *penTarget, binPath string, hadService bool, o options) error
	rewriteService func(binPath, dir string, c *agentConfig) error
}

func defaultPenUpdateOps() penUpdateOps {
	return penUpdateOps{
		isRunning:      agentRunning,
		hasService:     serviceConfigured,
		stop:           stopAgent,
		stage:          stageAndVerify,
		restartNew:     restartPenAgent,
		restartOld:     restartOldPenAgent,
		rewriteService: rewriteAgentService,
	}
}

func restartPenAgent(p *penTarget, binPath string, hadService bool, o options) error {
	noService := o.noService || !hadService
	logPath := filepath.Join(p.dir, "agent.log")
	if err := startExistingBinary(binPath, p.dir, p.cfg, noService); err != nil {
		return errorf("updated %s, but its new agent could not start: %v.\n"+
			"  Log: %s\n"+
			"  To get back on: run 'hogman update' again, or re-run hogman with your link.",
			p.zone, err, logPath)
	}
	if _, err := waitAgentUp(p.cfg, 60*time.Second); err != nil {
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
	if err := startExistingBinary(binPath, p.dir, p.cfg, noService); err != nil {
		return err
	}
	_, err := waitAgentUp(p.cfg, 30*time.Second)
	return err
}

func updatePenAgent(p *penTarget, binPath, verifiedSrc, wantHex string, o options, ops penUpdateOps) error {
	running := ops.isRunning(p.dir, p.cfg)
	hadService := ops.hasService(p.cfg.Zone)
	if running {
		step("Restarting %s agent", p.zone)
		ops.stop(p.dir, p.cfg)
	}
	if err := ops.stage(verifiedSrc, binPath, wantHex); err != nil {
		if running {
			if rerr := ops.restartOld(p, binPath, hadService, o); rerr != nil {
				return errorf("could not update %s agent binary (%v), and restarting the previous agent also failed (%v).\n"+
					"  To get back on: run '%s agent %s', or re-run hogman with your link.",
					p.zone, err, rerr, binPath, p.dir)
			}
			note("restarted the previous %s agent so you stay connected", p.zone)
		}
		return errorf("could not update %s agent binary: %v", p.zone, err)
	}
	note("updated %s", binPath)
	if running {
		return ops.restartNew(p, binPath, hadService, o)
	}
	return nil
}

type shareUpdateOps struct {
	isRunning      func(dir string) bool
	hasService     func(c *shareConfig) bool
	stop           func(dir string, c *shareConfig)
	stage          func(srcPath, dstPath, wantHex string) error
	restartNew     func(s *shareTargetDir, binPath string, o options) error
	restartOld     func(s *shareTargetDir, binPath string, o options) error
	rewriteService func(binPath, dir string, c *shareConfig) error
}

func defaultShareUpdateOps() shareUpdateOps {
	return shareUpdateOps{
		isRunning:  func(dir string) bool { return sharePID(dir) != 0 },
		hasService: shareServiceConfigured,
		stop:       stopShare,
		stage:      stageAndVerify,
		restartNew: func(s *shareTargetDir, binPath string, o options) error {
			return restartShareService(s, binPath, o, true)
		},
		restartOld: func(s *shareTargetDir, binPath string, o options) error {
			return restartShareService(s, binPath, o, false)
		},
		rewriteService: rewriteShareService,
	}
}

func restartShareService(s *shareTargetDir, binPath string, o options, updated bool) error {
	_ = os.Remove(filepath.Join(s.dir, "status.json"))
	_ = os.Remove(filepath.Join(s.dir, "share.pid"))
	managed, pid, err := startShareServiceWithBinary(binPath, s.dir, s.cfg, o.noService)
	if err != nil {
		return err
	}
	// Never pass stopShare as stopFn during update: a slow reconnect or transient
	// network hiccup must not unregister a previously working share's login service.
	if err := waitShareBackground(s.dir, s.cfg, managed, pid, 90*time.Second, nil); err != nil {
		return err
	}
	if updated {
		note("%s share restarted", s.cfg.fqdn())
	} else {
		note("restarted the previous %s share so it stays online", s.cfg.fqdn())
	}
	return nil
}

func updateShareBinary(s *shareTargetDir, binPath, verifiedSrc, wantHex string, o options, ops shareUpdateOps) error {
	running := ops.isRunning(s.dir)
	managed := ops.hasService(s.cfg)
	if running && managed {
		step("Restarting %s share", s.cfg.fqdn())
		ops.stop(s.dir, s.cfg)
		if err := ops.stage(verifiedSrc, binPath, wantHex); err != nil {
			if rerr := ops.restartOld(s, binPath, o); rerr != nil {
				return errorf("could not update %s share binary (%v), and restarting the previous share also failed (%v).\n"+
					"  To bring it back up: hogman share %s %s --background",
					s.cfg.fqdn(), err, rerr, s.cfg.Name, s.cfg.Target)
			}
			return errorf("could not update %s share binary: %v", s.cfg.fqdn(), err)
		}
		note("updated %s", binPath)
		if err := ops.restartNew(s, binPath, o); err != nil {
			return errorf("updated %s share binary, but restarting it failed (%v).\n"+
				"  To bring it back up: hogman share %s %s --background",
				s.cfg.fqdn(), err, s.cfg.Name, s.cfg.Target)
		}
		return nil
	}
	if err := ops.stage(verifiedSrc, binPath, wantHex); err != nil {
		return errorf("could not update share %s binary: %v", s.name, err)
	}
	note("updated %s", binPath)
	if running {
		note("share %s is still running the previous process in the foreground/background; restart it when ready", s.cfg.url())
	}
	return nil
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
			return "winget", "winget upgrade Galderwood.Hogman", true
		}
	}
	return "", "", false
}

const updatingMarkerName = ".updating"

// queryBinaryVersion runs `<bin> --version` with a short timeout and extracts
// its version token (e.g. "2026.11.24" from "hogman 2026.11.24 darwin/arm64").
func queryBinaryVersion(binPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, "--version").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) >= 2 {
		return strings.TrimPrefix(fields[1], "v")
	}
	return ""
}

// compareReleaseVersions compares two dot-separated numeric release versions
// (such as "2026.11.24" or "0.2.1"). Returns (-1/0/+1, true) when both strings
// parse as numeric release versions, or (0, false) for "dev"/non-numeric builds.
func compareReleaseVersions(a, b string) (int, bool) {
	parse := func(raw string) ([]int, bool) {
		s := strings.TrimPrefix(strings.TrimSpace(raw), "v")
		if s == "" {
			return nil, false
		}
		// Strip optional pre-release/build suffix after '-' or '+'.
		if i := strings.IndexAny(s, "-+"); i >= 0 {
			s = s[:i]
		}
		parts := strings.Split(s, ".")
		if len(parts) < 2 {
			return nil, false
		}
		nums := make([]int, len(parts))
		for i, p := range parts {
			if p == "" {
				return nil, false
			}
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 {
				return nil, false
			}
			nums[i] = n
		}
		return nums, true
	}
	pa, okA := parse(a)
	pb, okB := parse(b)
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
	return 0, true
}

func readUpdatingMarker(dir string) (present bool, hadService bool) {
	b, err := os.ReadFile(filepath.Join(dir, updatingMarkerName))
	if err != nil {
		return false, false
	}
	return true, strings.TrimSpace(string(b)) == "service"
}

func writeUpdatingMarker(dir string, hadService bool) {
	val := "detached\n"
	if hadService {
		val = "service\n"
	}
	tmp, err := os.CreateTemp(dir, ".updating-*")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	if _, err := tmp.WriteString(val); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return
	}
	_ = tmp.Chmod(0o600)
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, updatingMarkerName)); err != nil {
		_ = os.Remove(tmpPath)
	}
}

func clearUpdatingMarker(dir string) {
	_ = os.Remove(filepath.Join(dir, updatingMarkerName))
}

// migrateAndRestartPen atomically transitions a pen's agent service to
// canonicalBin (rewriting its LaunchAgent/systemd unit and waiting for it to
// come online) and removes any legacy per-pen duplicate copy only after success.
func migrateAndRestartPen(p *penTarget, canonicalBin, legacyBin, selfPath string, o options, ops penUpdateOps) error {
	running := ops.isRunning(p.dir, p.cfg)
	hadService := ops.hasService(p.cfg.Zone)
	interrupted, prevService := readUpdatingMarker(p.dir)
	if interrupted {
		running = true
		if prevService {
			hadService = true
		}
	}
	if running {
		step("Restarting %s agent", p.zone)
		writeUpdatingMarker(p.dir, hadService)
		ops.stop(p.dir, p.cfg)
		if err := ops.restartNew(p, canonicalBin, hadService, o); err != nil {
			// Stop any partially started new agent before rolling back so
			// systemd enable --now isn't a no-op and detached mode never leaves two agents.
			ops.stop(p.dir, p.cfg)
			if legacyBin != "" && ops.restartOld != nil {
				if _, serr := os.Stat(legacyBin); serr == nil {
					if rerr := ops.restartOld(p, legacyBin, hadService, o); rerr == nil {
						clearUpdatingMarker(p.dir)
						note("restarted the previous %s agent so you stay connected", p.zone)
					}
				}
			}
			return err
		}
		clearUpdatingMarker(p.dir)
	} else if hadService && ops.rewriteService != nil {
		if err := ops.rewriteService(canonicalBin, p.dir, p.cfg); err != nil {
			return errorf("could not update login item for %s: %v", p.zone, err)
		}
	}
	if legacyBin != "" && !sameFilePath(legacyBin, selfPath) && !sameFilePath(legacyBin, canonicalBin) {
		if _, err := os.Stat(legacyBin); err == nil {
			if err := os.Remove(legacyBin); err == nil {
				note("consolidated %s -> %s", legacyBin, canonicalBin)
			}
		}
	}
	return nil
}

// migrateAndRestartShare atomically transitions a managed share to canonicalBin
// and removes any legacy per-share duplicate copy only after it is healthy.
func migrateAndRestartShare(s *shareTargetDir, canonicalBin, legacyBin, selfPath string, o options, ops shareUpdateOps) error {
	running := ops.isRunning(s.dir)
	managed := ops.hasService(s.cfg)
	interrupted, prevManaged := readUpdatingMarker(s.dir)
	if interrupted && prevManaged {
		running = true
		managed = true
	}
	if running && managed {
		step("Restarting %s share", s.cfg.fqdn())
		writeUpdatingMarker(s.dir, true)
		ops.stop(s.dir, s.cfg)
		if err := ops.restartNew(s, canonicalBin, o); err != nil {
			ops.stop(s.dir, s.cfg)
			if legacyBin != "" && ops.restartOld != nil {
				if _, serr := os.Stat(legacyBin); serr == nil {
					if rerr := ops.restartOld(s, legacyBin, o); rerr == nil {
						clearUpdatingMarker(s.dir)
					}
				}
			}
			return errorf("updated share binary, but restarting %s failed (%v).\n"+
				"  To bring it back up: hogman share %s %s --background",
				s.cfg.fqdn(), err, s.cfg.Name, s.cfg.Target)
		}
		clearUpdatingMarker(s.dir)
	} else if running {
		note("share %s is still running the previous process; restart it when ready", s.cfg.url())
		return nil
	} else if managed && ops.rewriteService != nil {
		if err := ops.rewriteService(canonicalBin, s.dir, s.cfg); err != nil {
			return errorf("could not update login item for share %s: %v", s.cfg.fqdn(), err)
		}
	}
	if legacyBin != "" && !sameFilePath(legacyBin, selfPath) && !sameFilePath(legacyBin, canonicalBin) {
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
	selfPath, err := resolvedExePath()
	if err != nil {
		return err
	}

	configBase := filepath.Dir(stateDir("x"))
	plan, err := resolveUpdatePlan(args, o, configBase, sharesBase())
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

	selfHash, _ := fileSHA256(selfPath)
	selfNeedsUpdate := !digestEqualHex(selfHash, wantHex)

	pkgMgr, pkgUpgradeCmd, pkgManaged := detectPackageManager(selfPath, runtime.GOOS)
	if selfNeedsUpdate && pkgManaged && !o.dryRun {
		return errorf("%s is managed by %s — upgrade with: %s\n"+
			"  (after upgrading, run '%s update' if any background agents need syncing)",
			selfPath, pkgMgr, pkgUpgradeCmd, cliBinaryName())
	}

	instName := installedBinaryName(runtime.GOOS)
	oldInstName := legacyBinaryName(runtime.GOOS)
	canonicalBin := canonicalBinaryPath(configBase)
	canonicalNeeded := len(plan.pens) > 0 || len(plan.shares) > 0
	if _, err := os.Stat(canonicalBin); err == nil {
		canonicalNeeded = true
	}
	nhBin := nativeHostBinaryPath(configBase)
	if _, err := os.Lstat(nhBin); err == nil {
		canonicalNeeded = true
	}
	canonicalNeedsUpdate := false
	if canonicalNeeded && !sameFilePath(selfPath, canonicalBin) {
		h, _ := fileSHA256(canonicalBin)
		canonicalNeedsUpdate = !digestEqualHex(h, wantHex)
	}

	nhNeedsUpdate := false
	if !sameFilePath(selfPath, nhBin) {
		if fi, err := os.Lstat(nhBin); err == nil {
			if runtime.GOOS != "windows" {
				// On Unix, convert any old regular-file copy to a symlink to canonicalBin.
				nhNeedsUpdate = fi.Mode()&os.ModeSymlink == 0 || !sameFilePath(canonicalBin, nhBin)
			} else {
				h, _ := fileSHA256(nhBin)
				nhNeedsUpdate = !digestEqualHex(h, wantHex)
			}
		}
	}

	legacyCopyIn := func(dir string) string {
		for _, name := range []string{instName, oldInstName} {
			p := filepath.Join(dir, name)
			if sameFilePath(p, selfPath) || sameFilePath(p, canonicalBin) {
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
	if !sameFilePath(oldBinCanonical, selfPath) && !sameFilePath(oldBinCanonical, canonicalBin) {
		if _, err := os.Stat(oldBinCanonical); err == nil {
			hasOldBinCanonical = true
		}
	}

	anyLegacy := hasOldBinCanonical
	anyInterrupted := false
	for i := range plan.pens {
		if hasLegacyCopy(plan.pens[i].dir) {
			anyLegacy = true
		}
		if interrupted, _ := readUpdatingMarker(plan.pens[i].dir); interrupted {
			anyInterrupted = true
		}
	}
	for i := range plan.shares {
		if hasLegacyCopy(plan.shares[i].dir) {
			anyLegacy = true
		}
		if interrupted, _ := readUpdatingMarker(plan.shares[i].dir); interrupted {
			anyInterrupted = true
		}
	}

	anyUpdate := selfNeedsUpdate || canonicalNeedsUpdate || nhNeedsUpdate || anyLegacy || anyInterrupted
	cleanupOps := defaultLegacyCleanupOps()
	if !anyUpdate {
		if !o.dryRun {
			cleanupLegacyRootsForUpdate(plan, false, cleanupOps)
		}
		say("\n✓ %s is already up to date (%s).", cliBinaryName(), wantHex[:12])
		return nil
	}

	if o.dryRun {
		step("Dry run: nothing changed. Would update to %s:", wantHex[:12])
		if selfNeedsUpdate {
			if pkgManaged {
				note("%s is managed by %s (upgrade with: %s)", selfPath, pkgMgr, pkgUpgradeCmd)
			} else {
				note("%s (current %s)", selfPath, shortDigest(selfHash))
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
		cleanupLegacyRootsForUpdate(plan, true, cleanupOps)
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
		note("checksum verified (%s)", wantHex[:12])
		if err := stageAndVerify(verifiedSrc, selfPath, wantHex); err != nil {
			return errorf("could not replace %s: %v", selfPath, err)
		}
		note("updated %s", selfPath)
	}

	if canonicalNeedsUpdate {
		// Prevent `hogman update --pen X` from silently downgrading the shared
		// canonical binary used by other pens on this computer.
		if !plan.fromRelease {
			inPlanCheck := map[string]bool{}
			for _, p := range plan.pens {
				inPlanCheck[p.zone] = true
			}
			var otherPens []string
			for _, p := range loadPenTargets(configBase) {
				if !inPlanCheck[p.zone] {
					otherPens = append(otherPens, p.zone)
				}
			}
			if len(otherPens) > 0 {
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
		if err := installNativeHostBinary(srcForNH, nhBin); err != nil {
			note("could not update %s: %v", nhBin, err)
		} else {
			note("updated %s", nhBin)
		}
	}

	// Atomically migrate and restart running pen agents and managed shares onto
	// canonicalBin, deleting legacy per-pen/share copies only after health checks pass.
	serviceBin := canonicalBin
	if sameFilePath(selfPath, canonicalBin) || !canonicalNeeded {
		serviceBin = selfPath
	}
	ops := defaultPenUpdateOps()
	shareOps := defaultShareUpdateOps()
	for i := range plan.pens {
		p := &plan.pens[i]
		legacy := legacyCopyIn(p.dir)
		interrupted, _ := readUpdatingMarker(p.dir)
		if !selfNeedsUpdate && !canonicalNeedsUpdate && legacy == "" && !hasOldBinCanonical && !interrupted {
			continue
		}
		if err := migrateAndRestartPen(p, serviceBin, legacy, selfPath, o, ops); err != nil {
			return err
		}
	}
	for i := range plan.shares {
		s := &plan.shares[i]
		legacy := legacyCopyIn(s.dir)
		interrupted, _ := readUpdatingMarker(s.dir)
		if !selfNeedsUpdate && !canonicalNeedsUpdate && legacy == "" && !hasOldBinCanonical && !interrupted {
			continue
		}
		if err := migrateAndRestartShare(s, serviceBin, legacy, selfPath, o, shareOps); err != nil {
			return err
		}
	}
	if hasOldBinCanonical {
		if err := os.Remove(oldBinCanonical); err == nil {
			note("consolidated %s -> %s", oldBinCanonical, canonicalBin)
		}
	}

	cleanupLegacyRootsForUpdate(plan, false, cleanupOps)

	// Warn if other installed pens were not part of this update plan (e.g. --pen
	// or an explicit host matching only one of several pens).
	inPlan := map[string]bool{}
	for _, p := range plan.pens {
		inPlan[p.zone] = true
	}
	var skipped []string
	for _, p := range loadPenTargets(configBase) {
		if !inPlan[p.zone] {
			skipped = append(skipped, p.zone)
		}
	}
	if len(skipped) > 0 {
		note("shared binary %s updated from %s; other pens (%s) will use it on next restart (run 'hogman update' to update and restart all pens from GitHub Releases)",
			canonicalBin, plan.host, strings.Join(skipped, ", "))
	}

	verLine := ""
	if out, err := exec.Command(selfPath, "--version").Output(); err == nil {
		verLine = strings.TrimSpace(string(bytes.TrimSpace(out)))
	}
	if verLine != "" {
		say("\n✓ Updated %s (SHA-256 %s).", verLine, wantHex[:12])
	} else {
		say("\n✓ Updated hogman (SHA-256 %s).", wantHex[:12])
	}
	return nil
}

type legacyCleanupOps struct {
	removeRoot func(zone, rootFP string) (bool, error)
	saveConfig func(dir string, c *agentConfig) error
}

func defaultLegacyCleanupOps() legacyCleanupOps {
	return legacyCleanupOps{
		removeRoot: removeLegacyHogmanRoot,
		saveConfig: func(dir string, c *agentConfig) error {
			return c.save(dir)
		},
	}
}

func cleanupLegacyRootsForUpdate(plan *updatePlan, dryRun bool, ops legacyCleanupOps) []string {
	if plan == nil {
		return nil
	}
	var cleaned []string
	for _, p := range plan.pens {
		if p.cfg == nil || p.cfg.RootFP == "" {
			continue
		}
		if dryRun {
			note("would remove old %s certificate from trust store", p.zone)
			cleaned = append(cleaned, p.zone)
			continue
		}
		if ops.removeRoot == nil {
			continue
		}
		removed, err := ops.removeRoot(p.zone, p.cfg.RootFP)
		if err != nil {
			note("could not remove old %s certificate: %v", p.zone, err)
			continue
		}
		if removed {
			note("removed old %s network certificate from this computer's trust store", p.zone)
			cleaned = append(cleaned, p.zone)
		}
		p.cfg.RootFP = ""
		if ops.saveConfig != nil {
			if ser := ops.saveConfig(p.dir, p.cfg); ser != nil {
				note("could not update %s settings after certificate cleanup: %v", p.zone, ser)
			}
		}
	}

	if dryRun {
		note("would check for and remove any leftover old network root certificates")
	} else if ops.removeRoot != nil {
		removed, err := ops.removeRoot("", "")
		if err != nil {
			note("could not remove leftover old network certificate(s): %v", err)
		} else if removed {
			note("removed leftover old network certificate(s) from this computer's trust store")
			cleaned = append(cleaned, "*")
		}
	}
	return cleaned
}

func shortDigest(h string) string {
	if len(h) >= 12 {
		return h[:12]
	}
	if h == "" {
		return "missing"
	}
	return h
}
