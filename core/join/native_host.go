package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	nativeHostName         = "network.hogman.browser"
	nativeHostBinBase      = "hogman-native-host"
	nativeHostProtocolVer  = "1"
	maxNativeFrameBytes    = 64 * 1024
	statusTokenFilename    = "status.token"
	extensionHeartbeatFile = "extension-seen.json"
	browserIDsFile         = "browser-ids.json"
	hogmanPortMin          = 17000
	hogmanPortMax          = 26999

	proxyStateRefreshInterval = 30 * time.Second
	heartbeatWriteInterval    = 60 * time.Second
)

// Published browser extension IDs authorized to speak to the native messaging
// host. Additional developer/unpacked IDs can be registered explicitly via
// `hogman-join browser-setup --chrome-id <id> --firefox-id <id>`.
var (
	defaultChromeExtIDs = []string{
		"mgokdogedagoejnjmjpmbcmicbmhplkk", // Chrome Web Store (Chrome, Brave, Edge, Arc, Vivaldi, Chromium)
	}
	defaultFirefoxExtIDs = []string{} // populated once claimed on Mozilla AMO
)

var (
	hostedPenZoneRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,28}[a-z0-9]\.pens\.hogman\.network$`)
	chromeExtIDRE   = regexp.MustCompile(`^[a-p]{32}$`)
	firefoxExtIDRE  = regexp.MustCompile(`^(?:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+|\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})$`)
)

func isNativeHostBinary(arg0 string) bool {
	base := strings.ToLower(filepath.Base(arg0))
	base = strings.TrimSuffix(base, ".exe")
	return base == nativeHostBinBase
}

func nativeHostBinaryName(goos string) string {
	if goos == "windows" {
		return nativeHostBinBase + ".exe"
	}
	return nativeHostBinBase
}

func nativeHostBinaryPath(configBase string) string {
	return filepath.Join(configBase, "bin", nativeHostBinaryName(runtime.GOOS))
}

func isHostedPenZone(zone string) bool {
	return hostedPenZoneRE.MatchString(zone)
}

func validChromeExtID(id string) bool {
	return chromeExtIDRE.MatchString(id)
}

func validFirefoxExtID(id string) bool {
	return firefoxExtIDRE.MatchString(id)
}

// parseStrictHogmanPort enforces 127.0.0.1 and the Hogman local proxy port range
// (17000..26999) with canonical integer formatting (no leading zeros).
func parseStrictHogmanPort(addr string) (int, bool) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return 0, false
	}
	if len(portStr) == 0 || portStr[0] == '0' {
		return 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < hogmanPortMin || port > hogmanPortMax {
		return 0, false
	}
	return port, true
}

func computeStatusProof(token, nonce, zone string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(nonce))
	mac.Write([]byte("|"))
	mac.Write([]byte(zone))
	return hex.EncodeToString(mac.Sum(nil))
}

func generateHexToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type nativeRequest struct {
	Op string `json:"op"`
}

type nativePenEntry struct {
	Zone     string `json:"zone"`
	Port     int    `json:"port"`
	Up       bool   `json:"up"`
	Hosted   bool   `json:"hosted"`
	Legacy   bool   `json:"legacy,omitempty"`
	Squatted bool   `json:"squatted,omitempty"`
}

type nativeResponse struct {
	OK              bool             `json:"ok"`
	Version         string           `json:"version"`
	Pens            []nativePenEntry `json:"pens,omitempty"`
	OSProxyConflict bool             `json:"os_proxy_conflict"`
	OSProxyKind     string           `json:"os_proxy_kind,omitempty"`
	VPNOverride     bool             `json:"vpn_override"`
	VPNInterface    string           `json:"vpn_interface,omitempty"`
	Error           string           `json:"error,omitempty"`
}

func readNativeFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.NativeEndian.Uint32(lenBuf[:])
	if n == 0 || n > maxNativeFrameBytes {
		return nil, fmt.Errorf("invalid native message length: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeNativeFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(payload) > maxNativeFrameBytes {
		return fmt.Errorf("native response too large: %d bytes", len(payload))
	}
	var lenBuf [4]byte
	binary.NativeEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// runNativeHostMain is the browser Native Messaging entrypoint. It isolates fd 1
// immediately so no stray log or stdout write can corrupt length-prefixed frames.
// The host never mutates pen state or system proxies; its only local write is a
// throttled extension-seen.json timestamp used to suppress CLI VPN notices.
func runNativeHostMain() {
	out, err := isolateNativeStdout()
	if err != nil {
		os.Exit(1)
	}
	defer out.Close()
	log.SetOutput(os.Stderr)
	if err := serveNativeHost(os.Stdin, out, hogmanConfigBase(), time.Second); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "hogman-native-host: %v\n", err)
		os.Exit(1)
	}
}

type nativeHostSession struct {
	configBase    string
	detectProxy   func([]*agentConfig) systemProxyState
	now           func() time.Time
	cachedSys     systemProxyState
	lastSysCheck  time.Time
	lastHeartbeat time.Time
}

func newNativeHostSession(configBase string) *nativeHostSession {
	return &nativeHostSession{
		configBase:  configBase,
		detectProxy: detectSystemProxyState,
		now:         time.Now,
	}
}

func (s *nativeHostSession) maybeRecordHeartbeat() {
	now := s.now()
	if !s.lastHeartbeat.IsZero() && now.Sub(s.lastHeartbeat) < heartbeatWriteInterval {
		return
	}
	recordExtensionHeartbeat(s.configBase)
	s.lastHeartbeat = now
}

func (s *nativeHostSession) snapshot(allowSysRefresh bool) nativeResponse {
	pens, configs := collectNativePens(s.configBase)
	now := s.now()
	if s.lastSysCheck.IsZero() || (allowSysRefresh && now.Sub(s.lastSysCheck) >= proxyStateRefreshInterval) {
		s.cachedSys = s.detectProxy(configs)
		s.lastSysCheck = now
	}
	return nativeResponse{
		OK:              true,
		Version:         nativeHostProtocolVer,
		Pens:            pens,
		OSProxyConflict: s.cachedSys.OSProxyConflict,
		OSProxyKind:     s.cachedSys.OSProxyKind,
		VPNOverride:     s.cachedSys.VPNOverride,
		VPNInterface:    s.cachedSys.VPNInterface,
	}
}

func serveNativeHost(in io.Reader, out io.Writer, configBase string, pollInterval time.Duration) error {
	return serveNativeHostWithSession(in, out, newNativeHostSession(configBase), pollInterval)
}

func serveNativeHostWithSession(in io.Reader, out io.Writer, sess *nativeHostSession, pollInterval time.Duration) error {
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	for {
		raw, err := readNativeFrame(in)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		var req nativeRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			if werr := writeNativeFrame(out, nativeResponse{OK: false, Version: nativeHostProtocolVer, Error: "invalid request"}); werr != nil {
				return werr
			}
			continue
		}
		switch req.Op {
		case "list_pens":
			sess.maybeRecordHeartbeat()
			resp := sess.snapshot(true)
			if err := writeNativeFrame(out, resp); err != nil {
				return err
			}
		case "watch":
			sess.maybeRecordHeartbeat()
			return serveNativeWatch(in, out, sess, pollInterval)
		default:
			if err := writeNativeFrame(out, nativeResponse{OK: false, Version: nativeHostProtocolVer, Error: "unsupported op"}); err != nil {
				return err
			}
		}
	}
}

func serveNativeWatch(in io.Reader, out io.Writer, sess *nativeHostSession, pollInterval time.Duration) error {
	lastResp := sess.snapshot(true)
	lastBytes, _ := json.Marshal(lastResp)
	if err := writeNativeFrame(out, lastResp); err != nil {
		return err
	}

	type readResult struct {
		raw []byte
		err error
	}
	reads := make(chan readResult, 1)
	go func() {
		for {
			raw, err := readNativeFrame(in)
			reads <- readResult{raw: raw, err: err}
			if err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case rr := <-reads:
			if rr.err != nil {
				if errors.Is(rr.err, io.EOF) || errors.Is(rr.err, io.ErrUnexpectedEOF) {
					return nil
				}
				return rr.err
			}
			var req nativeRequest
			if err := json.Unmarshal(rr.raw, &req); err != nil {
				if err := writeNativeFrame(out, nativeResponse{OK: false, Version: nativeHostProtocolVer, Error: "invalid request"}); err != nil {
					return err
				}
				continue
			}
			switch req.Op {
			case "list_pens", "watch":
				sess.maybeRecordHeartbeat()
				cur := sess.snapshot(true)
				lastBytes, _ = json.Marshal(cur)
				if err := writeNativeFrame(out, cur); err != nil {
					return err
				}
			default:
				if err := writeNativeFrame(out, nativeResponse{OK: false, Version: nativeHostProtocolVer, Error: "unsupported op"}); err != nil {
					return err
				}
			}
		case <-ticker.C:
			// Refresh system proxy/VPN state at most once per proxyStateRefreshInterval (30s)
			// so the 1s pen-liveness tick never spawns scutil/networksetup repeatedly.
			cur := sess.snapshot(true)
			curBytes, _ := json.Marshal(cur)
			if !bytes.Equal(curBytes, lastBytes) {
				lastBytes = curBytes
				if err := writeNativeFrame(out, cur); err != nil {
					return err
				}
			}
		}
	}
}

// collectNativePens enumerates installed pens strictly: directory basename must
// equal config.json's canonical zone, ProxyAddr must be 127.0.0.1:17000-26999,
// and live ports are cryptographically verified via status.token challenge-response.
func collectNativePens(configBase string) ([]nativePenEntry, []*agentConfig) {
	entries, err := os.ReadDir(configBase)
	if err != nil {
		return []nativePenEntry{}, nil
	}
	seen := map[string]bool{}
	pens := make([]nativePenEntry, 0)
	var configs []*agentConfig
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		name := ent.Name()
		if name == "bin" || name == "shares" || strings.HasPrefix(name, ".") {
			continue
		}
		dir := filepath.Join(configBase, name)
		cfg, err := loadAgentConfig(dir)
		if err != nil {
			continue
		}
		if cfg.Zone != name || !validPACZone(cfg.Zone) || seen[cfg.Zone] {
			continue
		}
		port, ok := parseStrictHogmanPort(cfg.ProxyAddr)
		if !ok {
			continue
		}
		seen[cfg.Zone] = true
		configs = append(configs, cfg)

		state := verifyAgentEndpoint(dir, cfg)
		entry := nativePenEntry{
			Zone:   cfg.Zone,
			Port:   port,
			Up:     state == agentEndpointUp || state == agentEndpointLegacyUp,
			Hosted: isHostedPenZone(cfg.Zone),
			Legacy: state == agentEndpointLegacyUp,
		}
		if state == agentEndpointSquatted {
			// Never advertise a port answered by a non-Hogman / unverified listener.
			entry.Port = 0
			entry.Squatted = true
		}
		pens = append(pens, entry)
	}
	sort.Slice(pens, func(i, j int) bool {
		if len(pens[i].Zone) != len(pens[j].Zone) {
			return len(pens[i].Zone) > len(pens[j].Zone)
		}
		return pens[i].Zone < pens[j].Zone
	})
	return pens, configs
}

type agentEndpointState int

const (
	agentEndpointDown agentEndpointState = iota
	agentEndpointUp
	agentEndpointLegacyUp
	agentEndpointSquatted
)

func verifyAgentEndpoint(dir string, cfg *agentConfig) agentEndpointState {
	tokBytes, tokErr := os.ReadFile(filepath.Join(dir, statusTokenFilename))
	token := strings.TrimSpace(string(tokBytes))
	noTokenFile := errors.Is(tokErr, os.ErrNotExist)

	nonce, err := generateHexToken(16)
	if err != nil {
		return agentEndpointDown
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+cfg.ProxyAddr+"/status", nil)
	if err != nil {
		return agentEndpointDown
	}
	req.Header.Set("X-Hogman-Challenge", nonce)
	client := &http.Client{
		Timeout: 400 * time.Millisecond,
		Transport: &http.Transport{
			Proxy: nil, // always hit loopback directly
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return agentEndpointDown
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return agentEndpointSquatted
	}

	var st agentStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&st); err != nil {
		return agentEndpointSquatted
	}
	if st.Zone != cfg.Zone {
		return agentEndpointSquatted
	}

	// Agents started before status.token was introduced have no token file on disk.
	// Treat a valid matching /status JSON from such an agent as legacy/unverified
	// rather than falsely reporting a healthy pen as squatted right after update.
	if noTokenFile {
		if !st.Up {
			return agentEndpointDown
		}
		return agentEndpointLegacyUp
	}

	// Token file is present (or unreadable): require valid HMAC proof.
	if tokErr != nil || token == "" {
		return agentEndpointSquatted
	}
	gotProof := strings.TrimSpace(resp.Header.Get("X-Hogman-Proof"))
	wantProof := computeStatusProof(token, nonce, cfg.Zone)
	if gotProof == "" || !hmac.Equal([]byte(gotProof), []byte(wantProof)) {
		return agentEndpointSquatted
	}
	if !st.Up {
		return agentEndpointDown
	}
	return agentEndpointUp
}

type extensionHeartbeat struct {
	LastSeen int64 `json:"last_seen"`
}

func recordExtensionHeartbeat(configBase string) {
	if configBase == "" {
		return
	}
	b, _ := json.Marshal(extensionHeartbeat{LastSeen: time.Now().Unix()})
	_ = os.WriteFile(filepath.Join(configBase, extensionHeartbeatFile), b, 0o600)
}

func extensionRecentlySeen(configBase string, maxAge time.Duration) bool {
	b, err := os.ReadFile(filepath.Join(configBase, extensionHeartbeatFile))
	if err != nil {
		return false
	}
	var hb extensionHeartbeat
	if err := json.Unmarshal(b, &hb); err != nil || hb.LastSeen <= 0 {
		return false
	}
	return time.Since(time.Unix(hb.LastSeen, 0)) <= maxAge
}

// ------------------------------------------------ persisted extension IDs --

type savedBrowserIDs struct {
	ChromeIDs  []string `json:"chrome_ids,omitempty"`
	FirefoxIDs []string `json:"firefox_ids,omitempty"`
}

func loadSavedBrowserIDs(configBase string) savedBrowserIDs {
	b, err := os.ReadFile(filepath.Join(configBase, browserIDsFile))
	if err != nil {
		return savedBrowserIDs{}
	}
	var saved savedBrowserIDs
	if err := json.Unmarshal(b, &saved); err != nil {
		return savedBrowserIDs{}
	}
	return saved
}

func saveBrowserIDs(configBase string, ids savedBrowserIDs) error {
	if err := os.MkdirAll(configBase, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(ids, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(configBase, browserIDsFile), append(b, '\n'), 0o600)
}

func mergeUniqueIDs(groups ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range groups {
		for _, id := range g {
			id = strings.TrimSpace(id)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// --------------------------------------------------------- manifest install --

type chromeNativeManifest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Path           string   `json:"path"`
	Type           string   `json:"type"`
	AllowedOrigins []string `json:"allowed_origins"`
}

type firefoxNativeManifest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedExtensions []string `json:"allowed_extensions"`
}

func renderChromeNativeManifest(hostPath string, chromeIDs []string) ([]byte, error) {
	if !filepath.IsAbs(hostPath) {
		return nil, fmt.Errorf("native host path must be absolute: %s", hostPath)
	}
	origins := make([]string, 0, len(chromeIDs))
	seen := map[string]bool{}
	for _, id := range chromeIDs {
		id = strings.ToLower(strings.TrimSpace(id))
		if !validChromeExtID(id) {
			return nil, fmt.Errorf("invalid Chrome extension ID %q (expected 32 chars a-p)", id)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		origins = append(origins, "chrome-extension://"+id+"/")
	}
	if len(origins) == 0 {
		return nil, errors.New("at least one Chrome extension ID is required")
	}
	m := chromeNativeManifest{
		Name:           nativeHostName,
		Description:    "Hogman pen discovery (read-only)",
		Path:           hostPath,
		Type:           "stdio",
		AllowedOrigins: origins,
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func renderFirefoxNativeManifest(hostPath string, firefoxIDs []string) ([]byte, error) {
	if !filepath.IsAbs(hostPath) {
		return nil, fmt.Errorf("native host path must be absolute: %s", hostPath)
	}
	exts := make([]string, 0, len(firefoxIDs))
	seen := map[string]bool{}
	for _, id := range firefoxIDs {
		id = strings.TrimSpace(id)
		if !validFirefoxExtID(id) {
			return nil, fmt.Errorf("invalid Firefox extension ID %q", id)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		exts = append(exts, id)
	}
	if len(exts) == 0 {
		return nil, errors.New("at least one Firefox extension ID is required")
	}
	m := firefoxNativeManifest{
		Name:              nativeHostName,
		Description:       "Hogman pen discovery (read-only)",
		Path:              hostPath,
		Type:              "stdio",
		AllowedExtensions: exts,
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// installNativeHost copies the current hogman-join binary to the pen-independent
// <configBase>/bin/hogman-native-host path and writes browser Native Messaging
// manifests for installed browsers. Always user-space (no sudo).
func installNativeHost(configBase string, extraChromeIDs, extraFirefoxIDs []string) (string, int, error) {
	self, err := os.Executable()
	if err != nil {
		return "", 0, err
	}
	binDir := filepath.Join(configBase, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return "", 0, err
	}
	hostPath := nativeHostBinaryPath(configBase)
	if !sameFilePath(self, hostPath) {
		if err := copyExecutableAtomic(self, hostPath); err != nil {
			return "", 0, err
		}
	}

	saved := loadSavedBrowserIDs(configBase)
	if len(extraChromeIDs) > 0 || len(extraFirefoxIDs) > 0 {
		saved.ChromeIDs = mergeUniqueIDs(saved.ChromeIDs, extraChromeIDs)
		saved.FirefoxIDs = mergeUniqueIDs(saved.FirefoxIDs, extraFirefoxIDs)
		if err := saveBrowserIDs(configBase, saved); err != nil {
			return hostPath, 0, err
		}
	}

	chromeIDs := mergeUniqueIDs(defaultChromeExtIDs, saved.ChromeIDs)
	firefoxIDs := mergeUniqueIDs(defaultFirefoxExtIDs, saved.FirefoxIDs)

	count, err := registerNativeManifests(configBase, hostPath, chromeIDs, firefoxIDs)
	return hostPath, count, err
}

func copyExecutableAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".hogman-native-host-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := replaceExecutable(tmpPath, dst); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func removeNativeHost(configBase string) {
	unregisterNativeManifests(configBase)
	_ = os.Remove(nativeHostBinaryPath(configBase))
	_ = os.Remove(filepath.Join(configBase, extensionHeartbeatFile))
	_ = os.Remove(filepath.Join(configBase, browserIDsFile))
	_ = os.Remove(filepath.Join(configBase, "bin"))
}

// --------------------------------------------------------------- CLI cmds --

func browserSetupCmd(args []string, o options) error {
	var extraChrome, extraFirefox []string
	if o.chromeID != "" {
		id := strings.ToLower(strings.TrimSpace(o.chromeID))
		if !validChromeExtID(id) {
			return errorf("invalid --chrome-id %q (expected 32 lowercase letters a-p)", o.chromeID)
		}
		extraChrome = append(extraChrome, id)
	}
	if o.firefoxID != "" {
		id := strings.TrimSpace(o.firefoxID)
		if !validFirefoxExtID(id) {
			return errorf("invalid --firefox-id %q (expected Gecko add-on ID like name@domain or {uuid})", o.firefoxID)
		}
		extraFirefox = append(extraFirefox, id)
	}
	if len(args) > 0 {
		return errorf("usage: hogman-join browser-setup [--chrome-id <32-char-id>] [--firefox-id <gecko-id>]")
	}
	base := hogmanConfigBase()
	hostPath, n, err := installNativeHost(base, extraChrome, extraFirefox)
	if err != nil {
		return errorf("could not set up browser extension host: %v", err)
	}
	say("✓ Installed Hogman browser native host at %s (%d browser manifest(s) written).", hostPath, n)
	saved := loadSavedBrowserIDs(base)
	if len(defaultChromeExtIDs) == 0 && len(saved.ChromeIDs) == 0 && len(defaultFirefoxExtIDs) == 0 && len(saved.FirefoxIDs) == 0 {
		note("No published extension IDs are built in yet. For developer testing, pass --chrome-id <32-char-id> and/or --firefox-id <gecko-id>.")
	} else if n == 0 {
		note("No supported browser profile directories were found yet; re-run hogman-join browser-setup after launching your browser.")
	}
	return nil
}

func statusCmd() error {
	base := hogmanConfigBase()
	pens, configs := collectNativePens(base)
	if len(pens) == 0 {
		say("No pens installed on this computer.")
	} else {
		say("Pens:")
		for _, p := range pens {
			state := "down"
			if p.Squatted {
				state = "port squatted by another process"
			} else if p.Legacy {
				state = "up (older agent; run hogman-join update to enable status verification)"
			} else if p.Up {
				state = "up"
			}
			addr := "-"
			if p.Port > 0 {
				addr = fmt.Sprintf("127.0.0.1:%d", p.Port)
			}
			say("  %-42s  %-16s  %s", p.Zone, addr, state)
		}
	}

	hostPath := nativeHostBinaryPath(base)
	if _, err := os.Stat(hostPath); err == nil {
		extState := "installed (not yet contacted by browser extension)"
		if extensionRecentlySeen(base, 7*24*time.Hour) {
			extState = "active (browser extension connected)"
		}
		say("\nBrowser extension host: %s", extState)
	} else {
		say("\nBrowser extension host: not installed (run: hogman-join browser-setup)")
	}

	sys := detectSystemProxyState(configs)
	if sys.VPNOverride {
		say("\n! VPN override detected (%s): macOS system PAC is hidden while this VPN is connected.", sys.VPNInterface)
		if !extensionRecentlySeen(base, 7*24*time.Hour) {
			say("  To browse pen sites with your VPN on, use the Hogman browser extension (Chrome, Brave, Edge, or Firefox) or pause the VPN (Safari requires pausing the VPN).")
		}
	}
	if sys.OSProxyConflict {
		say("\n! Non-Hogman system proxy active: %s", sys.OSProxyDetail)
	}
	return nil
}
