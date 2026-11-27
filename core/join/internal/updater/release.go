package updater

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
	"strconv"
	"strings"
	"time"

	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/penapi"
	"hogman/join/internal/state"
)

const (
	DefaultReleaseBase = "https://github.com/celtiberi/hogman/releases"
	maxLatestTagBytes  = 16 << 10  // 16 KiB
	maxSHA256SUMSBytes = 64 << 10  // 64 KiB
	maxBinaryBytes     = 256 << 20 // 256 MiB
)

var (
	releaseVersionRE    = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]*$`)
	wingetPackageIDRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)
	VersionQueryTimeout = 5 * time.Second
)

func EffectiveReleaseBase() (baseURL, host string, err error) {
	raw := strings.TrimSpace(os.Getenv("HOGMAN_RELEASE_BASE"))
	if raw == "" {
		raw = DefaultReleaseBase
	}
	raw = strings.TrimRight(raw, "/")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", "", link.Errorf("invalid release base URL %q (must be https:// without credentials)", raw)
	}
	return u.String(), strings.ToLower(u.Host), nil
}

func ValidateReleaseVersion(raw string) (ver, tag string, err error) {
	v := strings.TrimSpace(strings.TrimRight(raw, "\r\n"))
	v = strings.TrimPrefix(v, "v")
	if v == "" || !releaseVersionRE.MatchString(v) || strings.Contains(v, "..") {
		return "", "", link.Errorf("unexpected release version %q", raw)
	}
	return v, "v" + v, nil
}

func AllowedRedirectHost(expectedHost, gotHost string) bool {
	if strings.EqualFold(gotHost, expectedHost) {
		return true
	}
	if strings.EqualFold(expectedHost, "github.com") {
		return strings.EqualFold(gotHost, "objects.githubusercontent.com") ||
			strings.EqualFold(gotHost, "release-assets.githubusercontent.com")
	}
	return false
}

func PlatformBinaryName(goos, goarch string) (string, error) {
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
		return "", link.Errorf("automatic updates are not built for %s/%s", goos, goarch)
	}
}

func ParseSourceURL(raw string) (baseURL, host string, err error) {
	raw = link.TrimMatchingQuotes(raw)
	if raw == "" {
		return "", "", link.Errorf("empty update source")
	}
	if parsed, err := link.Parse(raw); err == nil {
		return "https://" + parsed.Host, parsed.Host, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", link.Errorf("not a valid server address or link: %v", err)
	}
	if u.User != nil {
		return "", "", link.Errorf("the server address must not contain credentials")
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", "", link.Errorf("the server address must use https:// (got %q)", raw)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", "", link.Errorf("expected https://<host> or a full /join link, got %q", raw)
	}
	host = strings.ToLower(u.Host)
	return "https://" + host, host, nil
}

func ParseSHA256SUMS(data []byte, wantFile string) (string, error) {
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
				return "", link.Errorf("SHA256SUMS lists %s more than once", wantFile)
			}
			found = strings.ToLower(hex.EncodeToString(b))
		}
	}
	if found == "" {
		if sawLegacyName && strings.HasPrefix(wantFile, "hogman-") {
			return "", link.Errorf("this pen's server is on an older release (SHA256SUMS lists hogman-join-* instead of %s).\n"+
				"  Run 'hogman update' (without --pen) to update from GitHub Releases.", wantFile)
		}
		return "", link.Errorf("SHA256SUMS has no checksum entry for %s", wantFile)
	}
	return found, nil
}

func HTTPClient(caFile, caPEM, expectedHost string, timeout time.Duration) (*http.Client, error) {
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
			return nil, link.Errorf("saved control CA certificate is unreadable")
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
			if !strings.EqualFold(req.URL.Scheme, "https") || !AllowedRedirectHost(expectedHost, req.URL.Host) {
				return fmt.Errorf("refusing redirect to %s", req.URL.Redacted())
			}
			return nil
		},
	}, nil
}

func FetchLatestReleaseTag(client *http.Client, releaseBase string) (ver, tag, dlBase string, err error) {
	urlStr := strings.TrimRight(releaseBase, "/") + "/latest/download/latest"
	resp, err := client.Get(urlStr)
	if err != nil {
		return "", "", "", link.Errorf("cannot reach GitHub Releases at %s: %v\n"+
			"  To update from a pen's server instead: hogman update --pen <zone> or hogman update 'https://<pen-host>'", urlStr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", "", link.Errorf("GitHub Releases returned HTTP %d for %s\n"+
			"  To update from a pen's server instead: hogman update --pen <zone> or hogman update 'https://<pen-host>'", resp.StatusCode, urlStr)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxLatestTagBytes+1))
	if err != nil {
		return "", "", "", link.Errorf("failed reading latest release version: %v", err)
	}
	if len(data) > maxLatestTagBytes {
		return "", "", "", link.Errorf("latest release pointer exceeds size limit")
	}
	ver, tag, err = ValidateReleaseVersion(string(data))
	if err != nil {
		return "", "", "", err
	}
	return ver, tag, strings.TrimRight(releaseBase, "/") + "/download/" + tag, nil
}

func FetchExpectedSHA256URL(client *http.Client, urlStr, binName string) (string, error) {
	resp, err := client.Get(urlStr)
	if err != nil {
		return "", link.Errorf("cannot reach %s: %v", urlStr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", link.Errorf("server returned HTTP %d for %s", resp.StatusCode, urlStr)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSHA256SUMSBytes+1))
	if err != nil {
		return "", link.Errorf("failed reading SHA256SUMS: %v", err)
	}
	if len(data) > maxSHA256SUMSBytes {
		return "", link.Errorf("SHA256SUMS exceeds size limit")
	}
	return ParseSHA256SUMS(data, binName)
}

func DigestEqualHex(a, b string) bool {
	ab, errA := hex.DecodeString(a)
	bb, errB := hex.DecodeString(b)
	return errA == nil && errB == nil && len(ab) == sha256.Size && len(bb) == sha256.Size && subtle.ConstantTimeCompare(ab, bb) == 1
}

func DownloadVerifiedBinaryURL(client *http.Client, urlStr, binName, wantHex, tmpDir string) (string, error) {
	resp, err := client.Get(urlStr)
	if err != nil {
		return "", link.Errorf("failed downloading %s: %v", urlStr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", link.Errorf("server returned HTTP %d for %s", resp.StatusCode, urlStr)
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
		return "", link.Errorf("failed downloading %s: %v", binName, err)
	}
	if n == 0 {
		return "", link.Errorf("downloaded %s was empty", binName)
	}
	if n > maxBinaryBytes {
		return "", link.Errorf("downloaded %s exceeds %d MiB size limit", binName, maxBinaryBytes>>20)
	}
	gotHex := strings.ToLower(hex.EncodeToString(h.Sum(nil)))
	if !DigestEqualHex(gotHex, wantHex) {
		return "", link.Errorf("downloaded %s failed SHA-256 verification: expected %s, got %s", binName, wantHex, gotHex)
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	keep = true
	return tmpPath, nil
}

func StageAndVerify(srcPath, dstPath, wantHex string) error {
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
		return link.Errorf("refusing to install empty binary at %s", dstPath)
	}
	gotHex := strings.ToLower(hex.EncodeToString(h.Sum(nil)))
	if !DigestEqualHex(gotHex, wantHex) {
		return link.Errorf("staged binary for %s failed SHA-256 check (%s != %s)", dstPath, gotHex, wantHex)
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

func CheckDirWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".hogman-perm-check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

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

// DetectPackageManager reports whether exePath appears to be installed and
// managed by a system or user package manager (Homebrew, Scoop, WinGet, or OS
// packages under /usr/bin) so `update` refuses to overwrite it in place.
func DetectPackageManager(exePath, goos string) (name, upgradeCmd string, ok bool) {
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

// QueryBinaryVersionLine runs `<bin> --version` with a short timeout and
// returns its output as a sanitized single line (joining any extra lines with
// "; " rather than dropping them).
func QueryBinaryVersionLine(binPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), VersionQueryTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, "--version").Output()
	if err != nil {
		return ""
	}
	return link.SingleLine(string(out))
}

// QueryBinaryVersion extracts the version token from `<bin> --version`
// (e.g. "2026.11.24" from "hogman 2026.11.24 darwin/arm64").
func QueryBinaryVersion(binPath string) string {
	fields := strings.Fields(QueryBinaryVersionLine(binPath))
	if len(fields) >= 2 {
		return strings.TrimPrefix(fields[1], "v")
	}
	return ""
}

// CompareReleaseVersions compares two dot-separated numeric release versions
// (such as "2026.11.24-d17d2f9" or "0.2.1"). Returns (-1/0/+1, true) when both
// strings parse as numeric release versions and can be ordered unambiguously.
func CompareReleaseVersions(a, b string) (int, bool) {
	parse := func(raw string) ([]int, string, bool) {
		s := strings.TrimPrefix(strings.TrimSpace(raw), "v")
		if s == "" {
			return nil, "", false
		}
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

// EnsureCanonicalBinary ensures the single canonical managed binary under
// <configBase>/bin/hogman is up to date atomically, while refusing to let an
// older CLI binary silently downgrade a newer canonical binary shared by other
// pens on this computer.
func EnsureCanonicalBinary(configBase, currentVersion string, note func(string, ...any)) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	dst := state.CanonicalBinaryPath(configBase)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	if fsutil.SameFilePath(self, dst) {
		return dst, nil
	}
	if _, err := os.Stat(dst); err == nil {
		if existingVer := QueryBinaryVersion(dst); existingVer != "" {
			if cmp, ok := CompareReleaseVersions(existingVer, currentVersion); ok && cmp > 0 {
				if note != nil {
					note("keeping newer shared binary %s (%s > %s); run 'hogman update' to update %s", dst, existingVer, currentVersion, self)
				}
				return dst, nil
			}
		}
	}
	if err := fsutil.CopyExecutableAtomic(self, dst); err != nil {
		return "", err
	}
	return dst, nil
}
