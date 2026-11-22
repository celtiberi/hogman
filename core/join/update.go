package main

import (
	"bytes"
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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const updateUsage = `hogman-join update: update hogman-join from a pen's server

usage:
  hogman-join update ['<link|host>']

Downloads the matching binary from https://<host>/join/dl/, checks it against
SHA256SUMS from the same server over HTTPS (catching broken downloads, not a
tampered server), updates this computer's joined pen agent (restarting it if
running), and updates cached share binaries from that server.

options:
  --pen ZONE        which pen to update from, if this computer is on more than one
  --dry-run         check SHA256SUMS and show what would change without modifying files
  --no-service      keep restarted agent in the background rather than a login item
  --control-ca FILE extra certificate to trust for the public control server
`

const (
	maxSHA256SUMSBytes = 64 << 10   // 64 KiB
	maxBinaryBytes     = 256 << 20  // 256 MiB
)

func platformBinaryName(goos, goarch string) (string, error) {
	switch goos + "/" + goarch {
	case "darwin/arm64":
		return "hogman-join-Darwin-arm64", nil
	case "darwin/amd64":
		return "hogman-join-Darwin-x86_64", nil
	case "linux/amd64":
		return "hogman-join-Linux-x86_64", nil
	case "linux/arm64":
		return "hogman-join-Linux-aarch64", nil
	case "windows/amd64":
		return "hogman-join-windows-amd64.exe", nil
	default:
		return "", errorf("automatic updates are not built for %s/%s", goos, goarch)
	}
}

func installedBinaryName(goos string) string {
	if goos == "windows" {
		return "hogman-join.exe"
	}
	return "hogman-join"
}

func parseUpdateSourceURL(raw string) (baseURL, host string, err error) {
	raw = strings.TrimSpace(raw)
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
	return "https://" + u.Host, u.Host, nil
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
			if req.URL.Scheme != "https" || req.URL.Host != expectedHost {
				return fmt.Errorf("refusing redirect to %s", req.URL.Redacted())
			}
			return nil
		},
	}, nil
}

func fetchExpectedSHA256(client *http.Client, baseURL, binName string) (string, error) {
	urlStr := baseURL + "/join/dl/SHA256SUMS"
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
	urlStr := baseURL + "/join/dl/" + binName
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
	tmp, err := os.CreateTemp(dstDir, ".hogman-join-*")
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
	baseURL   string
	host      string
	controlCA string
	pens      []penTarget
	shares    []shareTargetDir
}

func loadPenTargets(configBase string) []penTarget {
	var pens []penTarget
	if pattern, err := filepath.Glob(filepath.Join(configBase, "*", "config.json")); err == nil {
		sort.Strings(pattern)
		for _, f := range pattern {
			dir := filepath.Dir(f)
			if c, err := loadAgentConfig(dir); err == nil && c.LoginServer != "" {
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
			if c, err := loadShare(dir); err == nil && c.LoginServer != "" {
				shares = append(shares, shareTargetDir{zone: c.Zone, name: c.Name, dir: dir, cfg: c})
			}
		}
	}
	return pens, shares
}

func resolveUpdatePlan(args []string, o options, configBase, sharesDir string) (*updatePlan, error) {
	allPens, allSharesList := loadLocalTargets(configBase, sharesDir)
	penFilter := strings.ToLower(strings.TrimSpace(o.pen))

	if len(args) == 1 {
		baseURL, host, err := parseUpdateSourceURL(args[0])
		if err != nil {
			return nil, err
		}
		plan := &updatePlan{baseURL: baseURL, host: host}
		var penMatched, shareMatched bool
		for _, p := range allPens {
			if penFilter != "" && p.zone != penFilter {
				continue
			}
			penMatched = true
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
			if penFilter != "" && s.zone != penFilter {
				continue
			}
			shareMatched = true
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
		if penFilter != "" && !penMatched && !shareMatched {
			return nil, errorf("this computer is not on %s", penFilter)
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
		if penFilter != "" && p.zone != penFilter {
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
		if penFilter != "" && s.zone != penFilter {
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
		return nil, errorf("this computer is not on any pen yet. Pass a link or host: hogman-join update 'https://<host>'")
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
	return err == nil && processAlive(pid)
}

type penUpdateOps struct {
	isRunning  func(dir string, c *agentConfig) bool
	hasService func(zone string) bool
	stop       func(dir string, c *agentConfig)
	stage      func(srcPath, dstPath, wantHex string) error
	restartNew func(p *penTarget, binPath string, hadService bool, o options) error
	restartOld func(p *penTarget, binPath string, hadService bool, o options) error
}

func defaultPenUpdateOps() penUpdateOps {
	return penUpdateOps{
		isRunning:  agentRunning,
		hasService: serviceConfigured,
		stop:       stopAgent,
		stage:      stageAndVerify,
		restartNew: restartPenAgent,
		restartOld: restartOldPenAgent,
	}
}

func restartPenAgent(p *penTarget, _ string, hadService bool, o options) error {
	restartOpts := o
	restartOpts.noService = o.noService || !hadService
	logPath := filepath.Join(p.dir, "agent.log")
	if err := startAgent(p.dir, p.cfg, restartOpts); err != nil {
		return errorf("updated %s, but its new agent could not start: %v.\n"+
			"  Log: %s\n"+
			"  To get back on: run 'hogman-join update' again, or re-run hogman-join with your link.",
			p.zone, err, logPath)
	}
	if _, err := waitAgentUp(p.cfg, 60*time.Second); err != nil {
		return errorf("updated %s, but its new agent did not come online: %v.\n"+
			"  Log: %s\n"+
			"  To get back on: fix what the log shows and run 'hogman-join agent %s', or re-run hogman-join with your link.",
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
					"  To get back on: run '%s agent %s', or re-run hogman-join with your link.",
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
	isRunning  func(dir string) bool
	hasService func(c *shareConfig) bool
	stop       func(dir string, c *shareConfig)
	stage      func(srcPath, dstPath, wantHex string) error
	restartNew func(s *shareTargetDir, binPath string, o options) error
	restartOld func(s *shareTargetDir, binPath string, o options) error
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
	}
}

func restartShareService(s *shareTargetDir, binPath string, o options, updated bool) error {
	_ = os.Remove(filepath.Join(s.dir, "status.json"))
	_ = os.Remove(filepath.Join(s.dir, "share.pid"))
	managed, pid, err := startShareServiceWithBinary(binPath, s.dir, s.cfg, o.noService)
	if err != nil {
		return err
	}
	if err := waitShareBackground(s.dir, s.cfg, managed, pid, 45*time.Second, func() {
		stopShare(s.dir, s.cfg)
	}); err != nil {
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
					"  To bring it back up: hogman-join share %s %s --background",
					s.cfg.fqdn(), err, rerr, s.cfg.Name, s.cfg.Target)
			}
			return errorf("could not update %s share binary: %v", s.cfg.fqdn(), err)
		}
		note("updated %s", binPath)
		if err := ops.restartNew(s, binPath, o); err != nil {
			return errorf("updated %s share binary, but restarting it failed (%v).\n"+
				"  To bring it back up: hogman-join share %s %s --background",
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

func updateCmd(args []string, o options) error {
	if len(args) > 1 {
		return errorf("usage: hogman-join update [--pen ZONE] [--dry-run] ['<link|host>']")
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
	step("Checking %s for updates (%s)", plan.host, binName)
	wantHex, err := fetchExpectedSHA256(metaClient, plan.baseURL, binName)
	if err != nil {
		return err
	}
	note("expected SHA-256: %s", wantHex)

	selfHash, _ := fileSHA256(selfPath)
	selfNeedsUpdate := !digestEqualHex(selfHash, wantHex)

	instName := installedBinaryName(runtime.GOOS)
	type copyStatus struct {
		path       string
		needsCopy  bool
		pen        *penTarget
		share      *shareTargetDir
		nativeHost bool
	}
	var updates []copyStatus

	for i := range plan.pens {
		p := &plan.pens[i]
		pBin := filepath.Join(p.dir, instName)
		if sameFilePath(selfPath, pBin) {
			continue
		}
		h, _ := fileSHA256(pBin)
		updates = append(updates, copyStatus{path: pBin, needsCopy: !digestEqualHex(h, wantHex), pen: p})
	}
	for i := range plan.shares {
		s := &plan.shares[i]
		sBin := filepath.Join(s.dir, instName)
		if sameFilePath(selfPath, sBin) {
			continue
		}
		if _, err := os.Stat(sBin); err != nil {
			continue
		}
		h, _ := fileSHA256(sBin)
		updates = append(updates, copyStatus{path: sBin, needsCopy: !digestEqualHex(h, wantHex), share: s})
	}
	if nhBin := nativeHostBinaryPath(hogmanConfigBase()); !sameFilePath(selfPath, nhBin) {
		if _, err := os.Stat(nhBin); err == nil {
			h, _ := fileSHA256(nhBin)
			updates = append(updates, copyStatus{path: nhBin, needsCopy: !digestEqualHex(h, wantHex), nativeHost: true})
		}
	}

	anyUpdate := selfNeedsUpdate
	for _, u := range updates {
		if u.needsCopy {
			anyUpdate = true
			break
		}
	}
	cleanupOps := defaultLegacyCleanupOps()
	if !anyUpdate {
		if !o.dryRun {
			cleanupLegacyRootsForUpdate(plan, false, cleanupOps)
		}
		say("\n✓ hogman-join is already up to date (%s).", wantHex[:12])
		return nil
	}

	if o.dryRun {
		step("Dry run: nothing changed. Would update to %s:", wantHex[:12])
		if selfNeedsUpdate {
			note("%s (current %s)", selfPath, shortDigest(selfHash))
		}
		for _, u := range updates {
			if u.needsCopy {
				note("%s", u.path)
			}
		}
		cleanupLegacyRootsForUpdate(plan, true, cleanupOps)
		return nil
	}

	if selfNeedsUpdate {
		if err := checkDirWritable(filepath.Dir(selfPath)); err != nil {
			return errorf("cannot update %s (%v). Move hogman-join to a writable folder or re-run with write permission", selfPath, err)
		}
	}
	for _, u := range updates {
		if u.needsCopy {
			if err := checkDirWritable(filepath.Dir(u.path)); err != nil {
				return errorf("cannot update %s (%v)", u.path, err)
			}
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
		verifiedSrc, err = downloadVerifiedBinary(dlClient, plan.baseURL, binName, wantHex, tmpDir)
		if err != nil {
			return err
		}
		note("checksum verified (%s)", wantHex[:12])
		if err := stageAndVerify(verifiedSrc, selfPath, wantHex); err != nil {
			return errorf("could not replace %s: %v", selfPath, err)
		}
		note("updated %s", selfPath)
	}

	ops := defaultPenUpdateOps()
	shareOps := defaultShareUpdateOps()
	for _, u := range updates {
		if !u.needsCopy {
			continue
		}
		if u.pen != nil {
			if err := updatePenAgent(u.pen, u.path, verifiedSrc, wantHex, o, ops); err != nil {
				return err
			}
			continue
		}
		if u.share != nil {
			if err := updateShareBinary(u.share, u.path, verifiedSrc, wantHex, o, shareOps); err != nil {
				return err
			}
			continue
		}
		if u.nativeHost {
			if err := stageAndVerify(verifiedSrc, u.path, wantHex); err != nil {
				return errorf("could not update %s: %v", u.path, err)
			}
			note("updated %s", u.path)
		}
	}

	// If selfPath itself IS a pen agent or managed share binary and was replaced, restart it too.
	if selfNeedsUpdate {
		for i := range plan.pens {
			p := &plan.pens[i]
			pBin := filepath.Join(p.dir, instName)
			if !sameFilePath(selfPath, pBin) {
				continue
			}
			if ops.isRunning(p.dir, p.cfg) {
				hadService := ops.hasService(p.cfg.Zone)
				step("Restarting %s agent", p.zone)
				ops.stop(p.dir, p.cfg)
				if err := ops.restartNew(p, pBin, hadService, o); err != nil {
					return err
				}
			}
		}
		for i := range plan.shares {
			s := &plan.shares[i]
			sBin := filepath.Join(s.dir, instName)
			if !sameFilePath(selfPath, sBin) {
				continue
			}
			if shareOps.isRunning(s.dir) && shareOps.hasService(s.cfg) {
				step("Restarting %s share", s.cfg.fqdn())
				shareOps.stop(s.dir, s.cfg)
				if err := shareOps.restartNew(s, sBin, o); err != nil {
					return err
				}
			}
		}
	}

	cleanupLegacyRootsForUpdate(plan, false, cleanupOps)

	verLine := ""
	if out, err := exec.Command(selfPath, "--version").Output(); err == nil {
		verLine = strings.TrimSpace(string(bytes.TrimSpace(out)))
	}
	if verLine != "" {
		say("\n✓ Updated %s (SHA-256 %s).", verLine, wantHex[:12])
	} else {
		say("\n✓ Updated hogman-join (SHA-256 %s).", wantHex[:12])
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
