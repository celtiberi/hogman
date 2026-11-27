package state

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
)

const (
	StatusTokenFilename    = "status.token"
	UpdatingMarkerName     = ".updating"
	ExtensionHeartbeatFile = "extension-seen.json"
	BrowserIDsFile         = "browser-ids.json"
	PortMin                = 17000
	PortMax                = 26999
)

// AgentConfig holds one joined pen's side-by-side agent configuration on disk.
type AgentConfig struct {
	Zone        string `json:"zone"`
	LoginServer string `json:"login_server"`
	DNSServer   string `json:"dns_server"` // mesh address of the pen's DNS
	Hostname    string `json:"hostname"`
	ProxyAddr   string `json:"proxy_addr"` // 127.0.0.1:<port>
	// ControlCA is set only for test networks whose public control host has a
	// self-signed certificate (the --control-ca option). The agent then trusts
	// exactly this certificate for its connection to the control host.
	ControlCA string `json:"control_ca,omitempty"`
}

// TrustControlCA makes this process trust the test network's control
// certificate, and nothing else, for TLS. Must run before any TLS is used.
func (c *AgentConfig) TrustControlCA() {
	if c.ControlCA == "" {
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(c.ControlCA)) {
		return
	}
	gd := os.Getenv("GODEBUG")
	if gd != "" {
		gd += ","
	}
	_ = os.Setenv("GODEBUG", gd+"x509usefallbackroots=1")
	x509.SetFallbackRoots(pool)
}

func LoadAgentConfig(dir string) (*AgentConfig, error) {
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, err
	}
	var c AgentConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *AgentConfig) Save(dir string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, "config.json"), b, 0o600)
}

func (c *AgentConfig) ProxyURL() string { return "http://" + c.ProxyAddr }
func (c *AgentConfig) PACURL() string   { return "http://" + c.ProxyAddr + "/proxy.pac" }
func (c *AgentConfig) PAC() string      { return RenderPAC([]*AgentConfig{c}) }

func (c *AgentConfig) InZone(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == c.Zone || strings.HasSuffix(host, "."+c.Zone)
}

// ShareConfig holds one local share's configuration on disk.
type ShareConfig struct {
	Name              string `json:"name"`
	PrivateName       bool   `json:"private_name,omitempty"`
	BootstrapHostname string `json:"bootstrap_hostname,omitempty"`
	Zone              string `json:"zone"`
	LoginServer       string `json:"login_server"`
	DNSServer         string `json:"dns_server"`
	Target            string `json:"target"` // http://host:port, unix:///path/to.sock, or an absolute folder path
	Folder            bool   `json:"folder,omitempty"`
	Note              string `json:"note,omitempty"`
	ControlCA         string `json:"control_ca,omitempty"`
	UpstreamHost      string `json:"upstream_host,omitempty"`
	IdentityHeaders   bool   `json:"identity_headers,omitempty"`
}

func (c *ShareConfig) FQDN() string { return c.Name + "." + c.Zone }
func (c *ShareConfig) URL() string  { return "https://" + c.FQDN() }

func (c *ShareConfig) AgentConfig() *AgentConfig {
	host := c.Name
	if host == "" {
		host = c.BootstrapHostname
	}
	if host == "" {
		host = "site"
	}
	return &AgentConfig{
		Zone:        c.Zone,
		LoginServer: c.LoginServer,
		DNSServer:   c.DNSServer,
		Hostname:    host,
		ControlCA:   c.ControlCA,
	}
}

func (c *ShareConfig) Showing() string {
	if c.Folder {
		return "the folder " + c.Target
	}
	return c.Target
}

func LoadShare(dir string) (*ShareConfig, error) {
	b, err := os.ReadFile(filepath.Join(dir, "share.json"))
	if err != nil {
		return nil, err
	}
	var c ShareConfig
	return &c, json.Unmarshal(b, &c)
}

func (c *ShareConfig) Save(dir string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, "share.json"), b, 0o600)
}

type ShareStatus struct {
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

func WriteShareStatus(dir, state, msg string) {
	b, _ := json.Marshal(ShareStatus{State: state, Error: msg})
	_ = fsutil.WriteFileAtomic(filepath.Join(dir, "status.json"), b, 0o600)
}

func ReadShareStatus(dir string) ShareStatus {
	var st ShareStatus
	b, _ := os.ReadFile(filepath.Join(dir, "status.json"))
	_ = json.Unmarshal(b, &st)
	return st
}

// StateDir is where one pen's side-by-side agent keeps its identity and settings.
func StateDir(zone string) string {
	base, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "hogman", zone)
}

func ConfigBase() string { return filepath.Dir(StateDir("x")) }

// SharesBase is kept apart from pen connections (StateDir) so leaving a pen and
// sharing on it don't trip over each other.
func SharesBase() string {
	return filepath.Join(filepath.Dir(filepath.Dir(StateDir("x"))), "hogman-shares")
}

func ShareDir(zone, name string) string {
	return filepath.Clean(filepath.Join(SharesBase(), zone, name))
}

func InstalledBinaryName(goos string) string {
	if goos == "windows" {
		return "hogman.exe"
	}
	return "hogman"
}

func LegacyBinaryName(goos string) string {
	if goos == "windows" {
		return "hogman-join.exe"
	}
	return "hogman-join"
}

// CanonicalBinaryPath is the single managed hogman binary shared by all pen
// agents and background shares on this computer.
func CanonicalBinaryPath(configBase string) string {
	return filepath.Join(configBase, "bin", InstalledBinaryName(runtime.GOOS))
}

func ReadUpdatingMarker(dir string) (present bool, hadService bool) {
	b, err := os.ReadFile(filepath.Join(dir, UpdatingMarkerName))
	if err != nil {
		return false, false
	}
	return true, strings.TrimSpace(string(b)) == "service"
}

func WriteUpdatingMarker(dir string, hadService bool) {
	val := "detached\n"
	if hadService {
		val = "service\n"
	}
	_ = fsutil.WriteFileAtomic(filepath.Join(dir, UpdatingMarkerName), []byte(val), 0o600)
}

func ClearUpdatingMarker(dir string) {
	_ = os.Remove(filepath.Join(dir, UpdatingMarkerName))
}

func GenerateHexToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func ComputeStatusProof(token, nonce, zone string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(nonce))
	mac.Write([]byte("|"))
	mac.Write([]byte(zone))
	return hex.EncodeToString(mac.Sum(nil))
}

// WriteStatusToken atomically writes a fresh 128-bit status authentication
// token to dir/status.token (mode 0600).
func WriteStatusToken(dir string) (string, error) {
	tok, err := GenerateHexToken(16)
	if err != nil {
		return "", err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, StatusTokenFilename), []byte(tok), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

type InstalledPen struct {
	Zone   string
	Dir    string
	Config *AgentConfig
}

type PenScanResult struct {
	Pens    []InstalledPen
	Corrupt []string
}

// ScanInstalledPens enumerates pen state directories under configBase in one
// pass, enforcing that each directory basename matches config.json's canonical
// zone and is a valid DNS zone name.
func ScanInstalledPens(configBase string) PenScanResult {
	entries, err := os.ReadDir(configBase)
	if err != nil {
		return PenScanResult{}
	}
	var res PenScanResult
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		name := ent.Name()
		if name == "bin" || name == "shares" || strings.HasPrefix(name, ".") {
			continue
		}
		dir := filepath.Join(configBase, name)
		cfg, err := LoadAgentConfig(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			res.Corrupt = append(res.Corrupt, name)
			continue
		}
		if cfg.Zone == "" || cfg.Zone != name || !ValidPACZone(cfg.Zone) {
			res.Corrupt = append(res.Corrupt, name)
			continue
		}
		res.Pens = append(res.Pens, InstalledPen{
			Zone:   cfg.Zone,
			Dir:    dir,
			Config: cfg,
		})
	}
	sort.Slice(res.Pens, func(i, j int) bool { return res.Pens[i].Zone < res.Pens[j].Zone })
	sort.Strings(res.Corrupt)
	return res
}

func LoadInstalledPenConfigs(configBase string) []*AgentConfig {
	scanned := ScanInstalledPens(configBase)
	pens := make([]*AgentConfig, 0, len(scanned.Pens))
	for _, p := range scanned.Pens {
		pens = append(pens, p.Config)
	}
	return NormalizePenConfigs(pens, nil)
}

func CorruptPenConfigs(configBase string) []string {
	return ScanInstalledPens(configBase).Corrupt
}

// AllSharesIn lists share directories under base, optionally filtered to one pen zone.
func AllSharesIn(base, zone string) []string {
	pattern := filepath.Join(base, "*", "*", "share.json")
	if zone != "" {
		clean, err := link.ValidatePenQuery(zone)
		if err != nil {
			return nil
		}
		pattern = filepath.Join(base, clean, "*", "share.json")
	}
	m, _ := filepath.Glob(pattern)
	sort.Strings(m)
	out := make([]string, 0, len(m))
	for _, f := range m {
		d := filepath.Dir(f)
		// Skip transient staging directories (e.g. .pending-<hex> during --private-name claim).
		if strings.HasPrefix(filepath.Base(d), ".") {
			continue
		}
		out = append(out, d)
	}
	return out
}

func AllShares(zone string) []string {
	return AllSharesIn(SharesBase(), zone)
}
