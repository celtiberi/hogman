package nativehost

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"hogman/join/internal/agent"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
)

const (
	HostName      = "network.hogman.browser"
	BinBase       = "hogman-native-host"
	ProtocolVer   = "1"
	MaxFrameBytes = 64 * 1024

	proxyStateRefreshInterval = 30 * time.Second
	heartbeatWriteInterval    = 60 * time.Second
)

// Published browser extension IDs authorized to speak to the native messaging
// host. Additional developer/unpacked IDs can be registered explicitly via
// `hogman browser-setup --chrome-id <id> --firefox-id <id>`.
var (
	DefaultChromeExtIDs = []string{
		"mgokdogedagoejnjmjpmbcmicbmhplkk", // Chrome Web Store (Chrome, Brave, Edge, Arc, Vivaldi, Chromium)
	}
	DefaultFirefoxExtIDs = []string{
		"hogman-browser@hogman.network", // Mozilla Add-ons (Firefox, LibreWolf)
	}
)

var (
	chromeExtIDRE  = regexp.MustCompile(`^[a-p]{32}$`)
	firefoxExtIDRE = regexp.MustCompile(`^(?:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+|\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})$`)
)

func IsBinary(arg0 string) bool {
	base := strings.ToLower(filepath.Base(arg0))
	base = strings.TrimSuffix(base, ".exe")
	return base == BinBase
}

func BinaryName(goos string) string {
	if goos == "windows" {
		return BinBase + ".exe"
	}
	return BinBase
}

func BinaryPath(configBase string) string {
	return filepath.Join(configBase, "bin", BinaryName(runtime.GOOS))
}

func ValidChromeExtID(id string) bool { return chromeExtIDRE.MatchString(id) }

func ValidFirefoxExtID(id string) bool { return firefoxExtIDRE.MatchString(id) }

type Request struct {
	Op string `json:"op"`
}

// PenEntry is a discovered pen returned over Native Messaging. configuredPort
// and statusReason remain unexported so json.Marshal never exposes them on the
// wire while local CLI commands (status, doctor) can inspect them via accessors.
type PenEntry struct {
	Zone           string `json:"zone"`
	Port           int    `json:"port"`
	Up             bool   `json:"up"`
	Hosted         bool   `json:"hosted"`
	Squatted       bool   `json:"squatted,omitempty"`
	configuredPort int
	statusReason   string
}

func (e PenEntry) ConfiguredPort() int  { return e.configuredPort }
func (e PenEntry) StatusReason() string { return e.statusReason }

type Response struct {
	OK              bool       `json:"ok"`
	Version         string     `json:"version"`
	Pens            []PenEntry `json:"pens,omitempty"`
	OSProxyConflict bool       `json:"os_proxy_conflict"`
	OSProxyKind     string     `json:"os_proxy_kind,omitempty"`
	VPNOverride     bool       `json:"vpn_override"`
	VPNInterface    string     `json:"vpn_interface,omitempty"`
	Error           string     `json:"error,omitempty"`
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.NativeEndian.Uint32(lenBuf[:])
	if n == 0 || n > MaxFrameBytes {
		return nil, fmt.Errorf("invalid native message length: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func WriteFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(payload) > MaxFrameBytes {
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

// RunMain is the browser Native Messaging entrypoint. It isolates fd 1
// immediately so no stray log or stdout write can corrupt length-prefixed frames.
func RunMain() int {
	out, err := isolateNativeStdout()
	if err != nil {
		return 1
	}
	defer out.Close()
	log.SetOutput(os.Stderr)
	if err := Serve(os.Stdin, out, state.ConfigBase(), time.Second); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "hogman-native-host: %v\n", err)
		return 1
	}
	return 0
}

type Session struct {
	ConfigBase    string
	DetectProxy   func([]*state.AgentConfig) platform.SystemProxyState
	Now           func() time.Time
	cachedSys     platform.SystemProxyState
	lastSysCheck  time.Time
	lastHeartbeat time.Time
}

func NewSession(configBase string) *Session {
	return &Session{
		ConfigBase:  configBase,
		DetectProxy: platform.DetectSystemProxyState,
		Now:         time.Now,
	}
}

func (s *Session) maybeRecordHeartbeat() {
	now := s.Now()
	if !s.lastHeartbeat.IsZero() && now.Sub(s.lastHeartbeat) < heartbeatWriteInterval {
		return
	}
	RecordExtensionHeartbeat(s.ConfigBase)
	s.lastHeartbeat = now
}

func (s *Session) snapshot(allowSysRefresh bool) Response {
	pens, configs := CollectPens(s.ConfigBase)
	now := s.Now()
	if s.lastSysCheck.IsZero() || (allowSysRefresh && now.Sub(s.lastSysCheck) >= proxyStateRefreshInterval) {
		s.cachedSys = s.DetectProxy(configs)
		s.lastSysCheck = now
	}
	return Response{
		OK:              true,
		Version:         ProtocolVer,
		Pens:            pens,
		OSProxyConflict: s.cachedSys.OSProxyConflict,
		OSProxyKind:     s.cachedSys.OSProxyKind,
		VPNOverride:     s.cachedSys.VPNOverride,
		VPNInterface:    s.cachedSys.VPNInterface,
	}
}

func Serve(in io.Reader, out io.Writer, configBase string, pollInterval time.Duration) error {
	return ServeWithSession(in, out, NewSession(configBase), pollInterval)
}

func ServeWithSession(in io.Reader, out io.Writer, sess *Session, pollInterval time.Duration) error {
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	for {
		raw, err := ReadFrame(in)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		var req Request
		if err := json.Unmarshal(raw, &req); err != nil {
			if werr := WriteFrame(out, Response{OK: false, Version: ProtocolVer, Error: "invalid request"}); werr != nil {
				return werr
			}
			continue
		}
		switch req.Op {
		case "list_pens":
			sess.maybeRecordHeartbeat()
			resp := sess.snapshot(true)
			if err := WriteFrame(out, resp); err != nil {
				return err
			}
		case "watch":
			sess.maybeRecordHeartbeat()
			return serveWatch(in, out, sess, pollInterval)
		default:
			if err := WriteFrame(out, Response{OK: false, Version: ProtocolVer, Error: "unsupported op"}); err != nil {
				return err
			}
		}
	}
}

func serveWatch(in io.Reader, out io.Writer, sess *Session, pollInterval time.Duration) error {
	lastResp := sess.snapshot(true)
	lastBytes, _ := json.Marshal(lastResp)
	if err := WriteFrame(out, lastResp); err != nil {
		return err
	}

	type readResult struct {
		raw []byte
		err error
	}
	reads := make(chan readResult, 1)
	go func() {
		for {
			raw, err := ReadFrame(in)
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
			var req Request
			if err := json.Unmarshal(rr.raw, &req); err != nil {
				if err := WriteFrame(out, Response{OK: false, Version: ProtocolVer, Error: "invalid request"}); err != nil {
					return err
				}
				continue
			}
			switch req.Op {
			case "list_pens", "watch":
				sess.maybeRecordHeartbeat()
				cur := sess.snapshot(true)
				lastBytes, _ = json.Marshal(cur)
				if err := WriteFrame(out, cur); err != nil {
					return err
				}
			default:
				if err := WriteFrame(out, Response{OK: false, Version: ProtocolVer, Error: "unsupported op"}); err != nil {
					return err
				}
			}
		case <-ticker.C:
			cur := sess.snapshot(true)
			curBytes, _ := json.Marshal(cur)
			if !bytes.Equal(curBytes, lastBytes) {
				lastBytes = curBytes
				if err := WriteFrame(out, cur); err != nil {
					return err
				}
			}
		}
	}
}

// CollectPens enumerates installed pens strictly: directory basename must equal
// config.json's canonical zone, ProxyAddr must be 127.0.0.1:17000-26999, and
// live ports are cryptographically verified via status.token challenge-response.
func CollectPens(configBase string) ([]PenEntry, []*state.AgentConfig) {
	scanned := state.ScanInstalledPens(configBase)
	pens := make([]PenEntry, 0, len(scanned.Pens))
	var configs []*state.AgentConfig
	for _, p := range scanned.Pens {
		port, ok := state.ParseStrictHogmanPort(p.Config.ProxyAddr)
		if !ok {
			continue
		}
		configs = append(configs, p.Config)

		st, detail := agent.VerifyEndpointDetail(p.Dir, p.Config)
		entry := PenEntry{
			Zone:           p.Zone,
			Port:           port,
			Up:             st == agent.EndpointUp,
			Hosted:         state.IsHostedPenZone(p.Zone),
			configuredPort: port,
			statusReason:   detail.Reason,
		}
		if st == agent.EndpointSquatted {
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

type extensionHeartbeat struct {
	LastSeen int64 `json:"last_seen"`
}

func RecordExtensionHeartbeat(configBase string) {
	if configBase == "" {
		return
	}
	b, _ := json.Marshal(extensionHeartbeat{LastSeen: time.Now().Unix()})
	_ = fsutil.WriteFileAtomic(filepath.Join(configBase, state.ExtensionHeartbeatFile), b, 0o600)
}

func ExtensionRecentlySeen(configBase string, maxAge time.Duration) bool {
	b, err := os.ReadFile(filepath.Join(configBase, state.ExtensionHeartbeatFile))
	if err != nil {
		return false
	}
	var hb extensionHeartbeat
	if err := json.Unmarshal(b, &hb); err != nil || hb.LastSeen <= 0 {
		return false
	}
	return time.Since(time.Unix(hb.LastSeen, 0)) <= maxAge
}

// SavedBrowserIDs persists extra developer extension IDs registered via browser-setup.
type SavedBrowserIDs struct {
	ChromeIDs  []string `json:"chrome_ids,omitempty"`
	FirefoxIDs []string `json:"firefox_ids,omitempty"`
}

func LoadSavedBrowserIDs(configBase string) SavedBrowserIDs {
	b, err := os.ReadFile(filepath.Join(configBase, state.BrowserIDsFile))
	if err != nil {
		return SavedBrowserIDs{}
	}
	var saved SavedBrowserIDs
	if err := json.Unmarshal(b, &saved); err != nil {
		return SavedBrowserIDs{}
	}
	return saved
}

func SaveBrowserIDs(configBase string, ids SavedBrowserIDs) error {
	b, err := json.MarshalIndent(ids, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(configBase, state.BrowserIDsFile), append(b, '\n'), 0o600)
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

func RenderChromeManifest(hostPath string, chromeIDs []string) ([]byte, error) {
	if !filepath.IsAbs(hostPath) {
		return nil, fmt.Errorf("native host path must be absolute: %s", hostPath)
	}
	origins := make([]string, 0, len(chromeIDs))
	seen := map[string]bool{}
	for _, id := range chromeIDs {
		id = strings.ToLower(strings.TrimSpace(id))
		if !ValidChromeExtID(id) {
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
		Name:           HostName,
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

func RenderFirefoxManifest(hostPath string, firefoxIDs []string) ([]byte, error) {
	if !filepath.IsAbs(hostPath) {
		return nil, fmt.Errorf("native host path must be absolute: %s", hostPath)
	}
	exts := make([]string, 0, len(firefoxIDs))
	seen := map[string]bool{}
	for _, id := range firefoxIDs {
		id = strings.TrimSpace(id)
		if !ValidFirefoxExtID(id) {
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
		Name:              HostName,
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

// Install ensures the canonical binary is present (via ensureCanonical), links
// (Unix) or copies (Windows) <configBase>/bin/hogman-native-host to it, and
// writes browser Native Messaging manifests for installed browsers.
func Install(configBase string, ensureCanonical func(string) (string, error), extraChromeIDs, extraFirefoxIDs []string, note func(string, ...any)) (string, int, error) {
	canonicalBin, err := ensureCanonical(configBase)
	if err != nil {
		return "", 0, err
	}
	hostPath := BinaryPath(configBase)
	if err := InstallBinary(canonicalBin, hostPath); err != nil {
		return "", 0, err
	}

	saved := LoadSavedBrowserIDs(configBase)
	if len(extraChromeIDs) > 0 || len(extraFirefoxIDs) > 0 {
		saved.ChromeIDs = mergeUniqueIDs(saved.ChromeIDs, extraChromeIDs)
		saved.FirefoxIDs = mergeUniqueIDs(saved.FirefoxIDs, extraFirefoxIDs)
		if err := SaveBrowserIDs(configBase, saved); err != nil {
			return hostPath, 0, err
		}
	}

	chromeIDs := mergeUniqueIDs(DefaultChromeExtIDs, saved.ChromeIDs)
	firefoxIDs := mergeUniqueIDs(DefaultFirefoxExtIDs, saved.FirefoxIDs)

	count, err := registerNativeManifests(configBase, hostPath, chromeIDs, firefoxIDs, note)
	return hostPath, count, err
}

func Remove(configBase string) {
	unregisterNativeManifests(configBase)
	hostPath := BinaryPath(configBase)
	if err := os.Remove(hostPath); err != nil && !os.IsNotExist(err) {
		stopRunningNativeHosts(hostPath)
		removeFileWithRetry(hostPath)
	}
	_ = os.Remove(filepath.Join(configBase, state.ExtensionHeartbeatFile))
	_ = os.Remove(filepath.Join(configBase, state.BrowserIDsFile))
	_ = os.Remove(filepath.Join(configBase, "bin"))
}

func removeFileWithRetry(path string) {
	for i := 0; i < 20; i++ {
		err := os.Remove(path)
		if err == nil || os.IsNotExist(err) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
