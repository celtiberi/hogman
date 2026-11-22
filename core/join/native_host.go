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
	hogmanPortMin          = 17000
	hogmanPortMax          = 26999

	defaultFirefoxExtID = "hogman-browser@hogman.network"
)

// defaultChromeExtIDs holds published Chromium extension IDs (32 chars a-p)
// authorized to speak to the native messaging host. Populated when the
// extension's key/store ID is published; additional dev IDs can be registered
// explicitly via `hogman-join browser-setup --chrome-id <id>`.
var defaultChromeExtIDs = []string{}

var (
	hostedPenZoneRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,28}[a-z0-9]\.pens\.hogman\.network$`)
	chromeExtIDRE   = regexp.MustCompile(`^[a-p]{32}$`)
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
	Squatted bool   `json:"squatted,omitempty"`
}

type nativeResponse struct {
	OK              bool             `json:"ok"`
	Version         string           `json:"version"`
	Pens            []nativePenEntry `json:"pens,omitempty"`
	OSProxyConflict bool             `json:"os_proxy_conflict"`
	OSProxyDetail   string           `json:"os_proxy_detail,omitempty"`
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

func serveNativeHost(in io.Reader, out io.Writer, configBase string, pollInterval time.Duration) error {
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
			recordExtensionHeartbeat(configBase)
			resp := buildNativeSnapshot(configBase)
			if err := writeNativeFrame(out, resp); err != nil {
				return err
			}
		case "watch":
			recordExtensionHeartbeat(configBase)
			return serveNativeWatch(in, out, configBase, pollInterval)
		default:
			if err := writeNativeFrame(out, nativeResponse{OK: false, Version: nativeHostProtocolVer, Error: "unsupported op"}); err != nil {
				return err
			}
		}
	}
}

func serveNativeWatch(in io.Reader, out io.Writer, configBase string, pollInterval time.Duration) error {
	lastResp := buildNativeSnapshot(configBase)
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
				recordExtensionHeartbeat(configBase)
				cur := buildNativeSnapshot(configBase)
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
			cur := buildNativeSnapshot(configBase)
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

func buildNativeSnapshot(configBase string) nativeResponse {
	pens, configs := collectNativePens(configBase)
	sys := detectSystemProxyState(configs)
	return nativeResponse{
		OK:              true,
		Version:         nativeHostProtocolVer,
		Pens:            pens,
		OSProxyConflict: sys.OSProxyConflict,
		OSProxyDetail:   sys.OSProxyDetail,
		VPNOverride:     sys.VPNOverride,
		VPNInterface:    sys.VPNInterface,
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
			Up:     state == agentEndpointUp,
			Hosted: isHostedPenZone(cfg.Zone),
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
	agentEndpointSquatted
)

func verifyAgentEndpoint(dir string, cfg *agentConfig) agentEndpointState {
	tokBytes, tokErr := os.ReadFile(filepath.Join(dir, statusTokenFilename))
	token := strings.TrimSpace(string(tokBytes))

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
	}
	resp, err := client.Do(req)
	if err != nil {
		return agentEndpointDown
	}
	defer resp.Body.Close()

	// Something answered on this port. Unless it proves knowledge of this user's
	// per-run status.token AND matches zone, treat it as squatted.
	if tokErr != nil || token == "" {
		return agentEndpointSquatted
	}
	gotProof := strings.TrimSpace(resp.Header.Get("X-Hogman-Proof"))
	wantProof := computeStatusProof(token, nonce, cfg.Zone)
	if gotProof == "" || !hmac.Equal([]byte(gotProof), []byte(wantProof)) {
		return agentEndpointSquatted
	}
	var st agentStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&st); err != nil {
		return agentEndpointSquatted
	}
	if st.Zone != cfg.Zone {
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
		if id == "" || seen[id] {
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
// manifests. Always user-space (no sudo).
func installNativeHost(configBase string, extraChromeIDs []string) (string, int, error) {
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
	chromeIDs := append([]string{}, defaultChromeExtIDs...)
	chromeIDs = append(chromeIDs, extraChromeIDs...)
	firefoxIDs := []string{defaultFirefoxExtID}

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
	_ = os.Remove(filepath.Join(configBase, "bin"))
}

// --------------------------------------------------------------- CLI cmds --

func browserSetupCmd(args []string, o options) error {
	var extra []string
	if o.chromeID != "" {
		if !validChromeExtID(strings.ToLower(strings.TrimSpace(o.chromeID))) {
			return errorf("invalid --chrome-id %q (expected 32 lowercase letters a-p)", o.chromeID)
		}
		extra = append(extra, o.chromeID)
	}
	if len(args) > 0 {
		return errorf("usage: hogman-join browser-setup [--chrome-id <32-char-id>]")
	}
	hostPath, n, err := installNativeHost(hogmanConfigBase(), extra)
	if err != nil {
		return errorf("could not set up browser extension host: %v", err)
	}
	say("✓ Installed Hogman browser native host at %s (%d browser manifest(s) written).", hostPath, n)
	if len(defaultChromeExtIDs) == 0 && len(extra) == 0 {
		note("Firefox manifest registered (%s). For an unpacked Chrome/Brave/Edge extension, pass --chrome-id <id>.", defaultFirefoxExtID)
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
			say("  To browse pen sites with your VPN on, install the Hogman extension in Chrome, Brave, Edge, or Firefox (Safari requires pausing the VPN).")
		}
	}
	if sys.OSProxyConflict {
		say("\n! Non-Hogman system proxy active: %s", sys.OSProxyDetail)
	}
	return nil
}
