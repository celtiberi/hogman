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

Downloads the matching binary from https://<host>/join/dl/, verifies its
SHA-256 digest against SHA256SUMS before replacing anything on disk, updates
this computer's joined pen agent (restarting it if running) and any cached
share binaries from that server.

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

func loadLocalTargets(configBase, sharesDir string) ([]penTarget, []shareTargetDir) {
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

func agentRunning(dir string, c *agentConfig) bool {
	if st, err := agentState(c); err == nil && (st.Up || st.Error == "") {
		return true
	}
	b, err := os.ReadFile(filepath.Join(dir, "agent.pid"))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && processAlive(pid)
}

func restartPenAgent(p *penTarget, hadService bool, o options) error {
	restartOpts := o
	restartOpts.noService = o.noService || !hadService
	if err := startAgent(p.dir, p.cfg, restartOpts); err != nil {
		return errorf("updated %s, but could not restart its agent: %v", p.zone, err)
	}
	if _, err := waitAgentUp(p.cfg, 60*time.Second); err != nil {
		return err
	}
	note("%s agent restarted", p.zone)
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
		path      string
		needsCopy bool
		pen       *penTarget
		share     *shareTargetDir
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

	anyUpdate := selfNeedsUpdate
	for _, u := range updates {
		if u.needsCopy {
			anyUpdate = true
			break
		}
	}
	if !anyUpdate {
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

	for _, u := range updates {
		if !u.needsCopy {
			continue
		}
		if u.pen != nil {
			p := u.pen
			running := agentRunning(p.dir, p.cfg)
			hadService := serviceConfigured(p.cfg.Zone)
			if running {
				step("Restarting %s agent", p.zone)
				stopAgent(p.dir, p.cfg)
			}
			if err := stageAndVerify(verifiedSrc, u.path, wantHex); err != nil {
				return errorf("could not update %s agent binary: %v", p.zone, err)
			}
			note("updated %s", u.path)
			if running {
				if err := restartPenAgent(p, hadService, o); err != nil {
					return err
				}
			}
			continue
		}
		if u.share != nil {
			s := u.share
			if err := stageAndVerify(verifiedSrc, u.path, wantHex); err != nil {
				return errorf("could not update share %s binary: %v", s.name, err)
			}
			note("updated %s", u.path)
			if sharePID(s.dir) != 0 {
				note("share %s is still running the previous process; restart when ready: hogman-join share stop %s", s.cfg.url(), s.name)
			}
		}
	}

	// If selfPath itself IS a pen agent binary, restart that pen's running agent too.
	for i := range plan.pens {
		p := &plan.pens[i]
		pBin := filepath.Join(p.dir, instName)
		if !sameFilePath(selfPath, pBin) {
			continue
		}
		if agentRunning(p.dir, p.cfg) {
			hadService := serviceConfigured(p.cfg.Zone)
			step("Restarting %s agent", p.zone)
			stopAgent(p.dir, p.cfg)
			if err := restartPenAgent(p, hadService, o); err != nil {
				return err
			}
		}
	}

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

func shortDigest(h string) string {
	if len(h) >= 12 {
		return h[:12]
	}
	if h == "" {
		return "missing"
	}
	return h
}
