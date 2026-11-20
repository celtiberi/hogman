package main

// Sharing: one command puts something on the pen under a name of its own.
//
//	hogman-join share blog 3000                     https://blog.<pen>.hogman -> this computer's port 3000
//	hogman-join share notes ./public                a folder, served as a website
//	hogman-join share blog 3000 '<server link>'     a computer that isn't on the pen yet
//
// Each share is a small device of its own: a server (so the pen lets members
// in), named after the share. It names itself, gets its certificate from the
// pen's CA, and passes visitors to the port or serves the folder. This
// computer opens no ports and needs no administrator rights; its own
// connection to the pen (personal devices accept no visitors) is untouched.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/tsnet"
)

const shareUsage = `hogman-join share: put something on your pen under its own name

usage:
  hogman-join share NAME WHAT                  share from this computer (it must be on the pen)
  hogman-join share NAME WHAT '<server link>'  share from a computer that isn't on the pen
  hogman-join share list                       what this computer shares
  hogman-join share stop NAME                  take a share down and give its name back

WHAT is a port on this computer (3000), a local web address
(http://localhost:8080) or a folder (./site) to serve as a website.
NAME becomes https://NAME.<pen>.hogman, open to everyone in the pen.

options:
  --note TEXT    short one-line description shown on the pen's home page (--note "" clears it)
  --background   keep running after this window closes (until the computer restarts)
  --pen ZONE     which pen, if this computer is on more than one
`

type shareConfig struct {
	Name        string `json:"name"`
	Zone        string `json:"zone"`
	LoginServer string `json:"login_server"`
	DNSServer   string `json:"dns_server"`
	RootCA      string `json:"root_ca"`
	Target      string `json:"target"` // http://host:port, or an absolute folder path
	Folder      bool   `json:"folder,omitempty"`
	Note        string `json:"note,omitempty"`
	ControlCA   string `json:"control_ca,omitempty"`
}

func (c *shareConfig) fqdn() string { return c.Name + "." + c.Zone }
func (c *shareConfig) url() string  { return "https://" + c.fqdn() }

func (c *shareConfig) agentConfig() *agentConfig {
	return &agentConfig{Zone: c.Zone, LoginServer: c.LoginServer, DNSServer: c.DNSServer,
		Hostname: c.Name, ControlCA: c.ControlCA}
}

func (c *shareConfig) showing() string {
	if c.Folder {
		return "the folder " + c.Target
	}
	return c.Target
}

// Shares live apart from the pen connections (stateDir), so leaving a pen
// and sharing on it don't trip over each other.
func sharesBase() string {
	return filepath.Join(filepath.Dir(filepath.Dir(stateDir("x"))), "hogman-shares")
}

func shareDir(zone, name string) string {
	return filepath.Clean(filepath.Join(sharesBase(), zone, name))
}

func loadShare(dir string) (*shareConfig, error) {
	b, err := os.ReadFile(filepath.Join(dir, "share.json"))
	if err != nil {
		return nil, err
	}
	var c shareConfig
	return &c, json.Unmarshal(b, &c)
}

func (c *shareConfig) save(dir string) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(filepath.Join(dir, "share.json"), b, 0o600)
}

// allShares lists this computer's shares, optionally for one pen.
func allShares(zone string) []string {
	pattern := filepath.Join(sharesBase(), "*", "*", "share.json")
	if zone != "" {
		pattern = filepath.Join(sharesBase(), zone, "*", "share.json")
	}
	m, _ := filepath.Glob(pattern)
	sort.Strings(m)
	out := make([]string, 0, len(m))
	for _, f := range m {
		out = append(out, filepath.Dir(f))
	}
	return out
}

var shareNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){0,3}$`)

// shareTarget reads WHAT: a port, a local web address or a folder.
func shareTarget(what string) (target string, folder bool, err error) {
	if n, err := strconv.Atoi(what); err == nil {
		if n < 1 || n > 65535 {
			return "", false, errorf("%d is not a port number", n)
		}
		return "http://127.0.0.1:" + what, false, nil
	}
	if strings.HasPrefix(what, "http://") || strings.HasPrefix(what, "https://") {
		u, err := url.Parse(what)
		if err != nil || u.Host == "" {
			return "", false, errorf("%q is not a web address", what)
		}
		return strings.TrimSuffix(u.String(), "/"), false, nil
	}
	abs, err := filepath.Abs(what)
	if err != nil {
		return "", false, err
	}
	fi, err := os.Stat(abs)
	if err != nil || !fi.IsDir() {
		return "", false, errorf("%q is not a port, a web address (http://localhost:8080) or a folder", what)
	}
	return abs, true, nil
}

// ------------------------------------------------------------- commands --

func shareCmd(args []string, o options) error {
	switch {
	case len(args) == 1 && args[0] == "list":
		return shareList()
	case len(args) == 2 && args[0] == "stop":
		return shareStop(args[1], o)
	case len(args) == 2 || len(args) == 3:
		link := ""
		if len(args) == 3 {
			link = args[2]
		}
		return shareStart(args[0], args[1], link, o)
	}
	fmt.Print(shareUsage)
	os.Exit(2)
	return nil
}

func resolveShareNote(old *shareConfig, note string, noteSet bool) string {
	if noteSet {
		return strings.TrimSpace(note)
	}
	if old != nil {
		return old.Note
	}
	return ""
}

func shareStart(name, what, rawLink string, o options) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if !shareNameRE.MatchString(name) || name == "list" || name == "stop" {
		return errorf("%q can't be a name: use lowercase letters, digits and dashes, like blog or my-notes", name)
	}
	target, folder, err := shareTarget(what)
	if err != nil {
		return err
	}

	var cfg *shareConfig
	key := ""
	if rawLink != "" {
		cfg, key, err = shareFromLink(name, rawLink, o)
	} else {
		cfg, key, err = shareFromMembership(name, o)
	}
	if err != nil {
		return err
	}
	cfg.Target, cfg.Folder = target, folder

	dir := shareDir(cfg.Zone, name)
	var prev *shareConfig
	if old, err := loadShare(dir); err == nil {
		if pid := sharePID(dir); pid != 0 {
			return errorf("%s is already being shared from this computer (process %d). Stop it first: hogman-join share stop %s", old.url(), pid, name)
		}
		key = "" // this share already has its device; reuse it
		cfg.ControlCA = old.ControlCA
		prev = old
	} else if key == "" {
		return errorf("no way to add a device for this share")
	}
	cfg.Note = resolveShareNote(prev, o.note, o.noteSet)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := cfg.save(dir); err != nil {
		return err
	}
	if key != "" {
		if err := os.WriteFile(filepath.Join(dir, "authkey"), []byte(key), 0o600); err != nil {
			return err
		}
	}

	if o.background {
		return shareBackground(dir, cfg)
	}
	step("Sharing %s as %s", cfg.showing(), cfg.url())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveShare(ctx, dir, func(c *shareConfig) {
		shareReady(c, false)
		say("  Stop: Ctrl-C. The name stays yours: run the same command to bring it back.")
	})
}

func shareReady(c *shareConfig, background bool) {
	say("\n✓ %s is up.", c.url())
	say("  Everyone in the pen can open it.")
	say("  It shows %s.", c.showing())
	if background {
		say("  It runs in the background until this computer restarts.")
	}
	say("  Take it down and give the name back: hogman-join share stop %s", c.Name)
}

// shareFromLink sets up a share on a computer that only has a server link.
func shareFromLink(name, raw string, o options) (*shareConfig, string, error) {
	link, err := ParseLink(raw)
	if err != nil {
		return nil, "", errorf("%v", err)
	}
	if link.DeviceKey == "" {
		return nil, "", errorf("that is an invite. Use a share link: on your pen's home page, press Get a share link")
	}
	client, err := controlClient(o.controlCA)
	if err != nil {
		return nil, "", err
	}
	step("Checking the network at %s", link.Host)
	n, err := fetchNetwork(client, link.Host)
	if err != nil {
		return nil, "", err
	}
	if _, err := CheckRoot(n.RootCA, link.Fingerprint, n.Zone); err != nil {
		return nil, "", errorf("%v", err)
	}
	if n.DNSServer == "" {
		return nil, "", errorf("this pen's server is too old to share from here (it does not publish its DNS address)")
	}
	cfg := &shareConfig{Name: name, Zone: n.Zone, LoginServer: n.LoginServer, DNSServer: n.DNSServer, RootCA: n.RootCA}
	if o.controlCA != "" {
		b, err := os.ReadFile(o.controlCA)
		if err != nil {
			return nil, "", errorf("--control-ca: %v", err)
		}
		cfg.ControlCA = string(b)
	}
	return cfg, link.DeviceKey, nil
}

type penConn struct {
	zone      string
	proxy     string // side by side: the agent's proxy; empty for this computer's Tailscale
	controlCA string
}

// myPens finds the pens this computer is on: side-by-side connections and
// this computer's Tailscale.
func myPens() []penConn {
	var out []penConn
	m, _ := filepath.Glob(filepath.Join(filepath.Dir(stateDir("x")), "*", "config.json"))
	for _, f := range m {
		if c, err := loadAgentConfig(filepath.Dir(f)); err == nil && c.Zone != "" {
			out = append(out, penConn{zone: c.Zone, proxy: c.proxyURL(), controlCA: c.ControlCA})
		}
	}
	if ts, err := findTailscale(); err == nil {
		if st, err := ts.Status(); err == nil && st.BackendState == "Running" && st.CurrentTailnet != nil {
			z := strings.TrimPrefix(st.CurrentTailnet.MagicDNSSuffix, "nodes.")
			if z != st.CurrentTailnet.MagicDNSSuffix && zoneRE.MatchString(z) {
				dup := false
				for _, p := range out {
					dup = dup || p.zone == z
				}
				if !dup {
					out = append(out, penConn{zone: z})
				}
			}
		}
	}
	return out
}

func pickPen(want string) (*penConn, error) {
	var found []penConn
	for _, p := range myPens() {
		if want == "" || p.zone == want {
			found = append(found, p)
		}
	}
	switch {
	case len(found) == 1:
		return &found[0], nil
	case len(found) == 0 && want != "":
		return nil, errorf("this computer is not on %s", want)
	case len(found) == 0:
		return nil, errorf("this computer is not on a pen yet. Join first (hogman-join '<link>'),\n  or share with a server link: hogman-join share NAME WHAT '<server link>'")
	}
	zs := []string{}
	for _, p := range found {
		zs = append(zs, p.zone)
	}
	return nil, errorf("this computer is on several pens (%s); pick one with --pen", strings.Join(zs, ", "))
}

// memberClient talks to the pen's home page as this computer's member.
func (p *penConn) memberClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	if p.proxy != "" {
		pu, _ := url.Parse(p.proxy)
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: tr}
}

type meView struct {
	Member struct {
		Handle string `json:"handle"`
	} `json:"member"`
	ThisDevice struct {
		ID   int64  `json:"id"`
		Kind string `json:"kind"`
	} `json:"this_device"`
	Network *networkInfo `json:"network"`
}

func homeAPI(c *http.Client, zone, method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "https://home."+zone+"/api"+path, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return resp.StatusCode, errors.New(e.Error)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("unreadable answer: %v", err)
		}
	}
	return resp.StatusCode, nil
}

// shareFromMembership sets up a share using this computer's place on the pen:
// it asks the pen for a server key in the member's name.
func shareFromMembership(name string, o options) (*shareConfig, string, error) {
	p, err := pickPen(o.pen)
	if err != nil {
		return nil, "", err
	}
	c := p.memberClient()
	var me meView
	if _, err := homeAPI(c, p.zone, "GET", "/me", nil, &me); err != nil {
		var ue x509.UnknownAuthorityError
		if errors.As(err, &ue) {
			return nil, "", errorf("this computer doesn't trust %s's certificate (was it joined with --no-trust?)", p.zone)
		}
		return nil, "", errorf("could not reach home.%s as you: %v", p.zone, err)
	}
	if me.Network == nil || me.Network.DNSServer == "" || me.Network.Zone != p.zone {
		return nil, "", errorf("this pen's server is too old for sharing; ask its keeper to upgrade it")
	}
	if _, err := CheckRoot(me.Network.RootCA, me.Network.RootFingerprint, p.zone); err != nil {
		return nil, "", errorf("%v", err)
	}
	cfg := &shareConfig{Name: name, Zone: p.zone, LoginServer: me.Network.LoginServer,
		DNSServer: me.Network.DNSServer, RootCA: me.Network.RootCA, ControlCA: p.controlCA}
	if old, err := loadShare(shareDir(p.zone, name)); err == nil && old.Zone == p.zone {
		return cfg, "", nil // already has its device
	}
	if me.ThisDevice.Kind == "server" {
		return nil, "", errorf("this computer is one of your servers, so it can't add devices.\n  Share from a personal device, or with a server link: hogman-join share NAME WHAT '<server link>'")
	}
	step("Adding a server for %s.%s to your devices (%s)", name, p.zone, me.Member.Handle)
	var dk struct {
		AuthKey string `json:"auth_key"`
	}
	if _, err := homeAPI(c, p.zone, "POST", "/devices", map[string]string{"kind": "server"}, &dk); err != nil {
		return nil, "", errorf("the pen would not add a server: %v", err)
	}
	return cfg, dk.AuthKey, nil
}

// --------------------------------------------------------------- serving --

// shareNode brings a share's own device onto the pen and returns it with a
// client for reaching the pen through it.
func shareNode(ctx context.Context, dir string, c *shareConfig) (*tsnet.Server, *agent, *http.Client, error) {
	ac := c.agentConfig()
	ac.trustControlCA()
	key, _ := os.ReadFile(filepath.Join(dir, "authkey"))
	node := newNode(dir, ac, strings.TrimSpace(string(key)))
	upCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	st, err := node.Up(upCtx)
	if err != nil {
		node.Close()
		return nil, nil, nil, errorf("the share could not join the pen: %v", err)
	}
	_ = os.Remove(filepath.Join(dir, "authkey")) // single use, and now spent
	server := false
	if st.Self != nil && st.Self.Tags != nil {
		for _, t := range st.Self.Tags.All() {
			server = server || t == "tag:server"
		}
	}
	if !server {
		node.Close()
		return nil, nil, nil, errorf("that link adds a personal device, which can't be visited. Use a share link (Get a share link on your home page)")
	}
	a := newAgent(ac, node)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(c.RootCA))
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext:     func(ctx context.Context, _, addr string) (net.Conn, error) { return a.dial(ctx, addr) },
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	return node, a, hc, nil
}

// untilOK retries fn while the pen is still catching up with a new device
// (its access rules follow a few seconds behind).
func untilOK(ctx context.Context, d time.Duration, fn func() (retry bool, err error)) error {
	deadline := time.Now().Add(d)
	for {
		retry, err := fn()
		if err == nil || !retry || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// serveShare runs a share until ctx ends. ready is called once its name and
// certificate are in place.
func serveShare(ctx context.Context, dir string, ready func(*shareConfig)) error {
	c, err := loadShare(dir)
	if err != nil {
		return err
	}
	// Foreground or background, the pid file says a share is running, so
	// list, stop and a second start all see it.
	pidFile := filepath.Join(dir, "share.pid")
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
	defer os.Remove(pidFile)
	writeShareStatus(dir, "starting", "")
	fail := func(err error) error { writeShareStatus(dir, "error", err.Error()); return err }

	_, statErr := os.Stat(filepath.Join(dir, "certs"))
	fresh := os.IsNotExist(statErr) // never got as far as a certificate
	node, _, hc, err := shareNode(ctx, dir, c)
	if err != nil {
		return fail(err)
	}
	defer node.Close()

	// Name ourselves.
	err = untilOK(ctx, 90*time.Second, func() (bool, error) {
		code, err := homeAPI(hc, c.Zone, "POST", "/names", map[string]string{"name": c.Name, "note": c.Note}, nil)
		if err == nil {
			return false, nil
		}
		// Not through the pen's rules yet, or not recorded yet: wait.
		return code == 0 || strings.Contains(err.Error(), "not enrolled"), err
	})
	if err != nil {
		if fresh {
			// A brand-new share that can't have its name: take its device back
			// out, so nothing is left behind on the pen or here.
			_ = giveBackDevice(ctx, hc, c)
			node.Close()
			_ = os.RemoveAll(filepath.Join(dir, "node"))
			_ = os.Remove(filepath.Join(dir, "share.json"))
		}
		return fail(errorf("could not claim %s: %v", c.fqdn(), err))
	}

	m := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		HostPolicy:  autocert.HostWhitelist(c.fqdn()),
		Cache:       autocert.DirCache(filepath.Join(dir, "certs")),
		RenewBefore: 56 * time.Hour, // the pen's certificates last a week
		Client:      &acme.Client{DirectoryURL: "https://ca." + c.Zone + ":9000/acme/acme/directory", HTTPClient: hc},
	}
	h, closeH, err := shareHandler(c)
	if err != nil {
		return fail(err)
	}
	defer closeH()
	ln443, err := node.Listen("tcp", ":443")
	if err != nil {
		return fail(err)
	}
	ln80, err := node.Listen("tcp", ":80")
	if err != nil {
		return fail(err)
	}
	quiet := log.New(io.Discard, "", 0)
	tlsSrv := &http.Server{Handler: h, TLSConfig: m.TLSConfig(), ReadHeaderTimeout: 20 * time.Second, ErrorLog: quiet}
	webSrv := &http.Server{Handler: m.HTTPHandler(nil), ReadHeaderTimeout: 20 * time.Second, ErrorLog: quiet}
	go func() { _ = tlsSrv.ServeTLS(ln443, "", "") }()
	go func() { _ = webSrv.Serve(ln80) }()
	defer tlsSrv.Close()
	defer webSrv.Close()

	// Get the certificate now, rather than on the first visitor.
	hello := &tls.ClientHelloInfo{ServerName: c.fqdn(),
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12}}
	err = untilOK(ctx, 2*time.Minute, func() (bool, error) {
		_, err := m.GetCertificate(hello)
		return true, err
	})
	if err != nil {
		return fail(errorf("no certificate for %s from the pen's CA: %v", c.fqdn(), err))
	}
	writeShareStatus(dir, "up", "")
	if ready != nil {
		ready(c)
	}
	<-ctx.Done()
	writeShareStatus(dir, "stopped", "")
	return nil
}

func shareHandler(c *shareConfig) (http.Handler, func(), error) {
	if c.Folder {
		// os.Root keeps every read inside the folder: a symlink pointing out
		// of it (to ~/.ssh, say) is refused, not followed.
		root, err := os.OpenRoot(c.Target)
		if err != nil {
			return nil, nil, errorf("cannot open the folder %s: %v", c.Target, err)
		}
		return http.FileServerFS(root.FS()), func() { _ = root.Close() }, nil
	}
	u, err := url.Parse(c.Target)
	if err != nil {
		return nil, nil, err
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u) // Host becomes the target's: dev servers expect their own
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "%s is shared from a computer where the app isn't answering right now.\n", c.fqdn())
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}, func() {}, nil
}

// ------------------------------------------------- background, status --

type shareStatus struct {
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

func writeShareStatus(dir, state, msg string) {
	b, _ := json.Marshal(shareStatus{State: state, Error: msg})
	_ = os.WriteFile(filepath.Join(dir, "status.json"), b, 0o600)
}

func readShareStatus(dir string) shareStatus {
	var st shareStatus
	b, _ := os.ReadFile(filepath.Join(dir, "status.json"))
	_ = json.Unmarshal(b, &st)
	return st
}

// sharePID is the process serving a share in the background, or 0.
func sharePID(dir string) int {
	b, err := os.ReadFile(filepath.Join(dir, "share.pid"))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || !processAlive(pid) {
		return 0
	}
	return pid
}

func shareBackground(dir string, c *shareConfig) error {
	bin, err := installedBinary(dir)
	if err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dir, "status.json"))
	step("Sharing %s as %s, in the background", c.showing(), c.url())
	logPath := filepath.Join(dir, "share.log")
	pid, err := spawnDetached(logPath, bin, "__share-run", dir)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		st := readShareStatus(dir)
		if st.State != "up" && st.State != "error" && !processAlive(pid) {
			return errorf("the share stopped before it came up. Log: %s", logPath)
		}
		switch st.State {
		case "up":
			shareReady(c, true)
			return nil
		case "error":
			return errorf("%s", st.Error)
		}
	}
	return errorf("the share did not come up in time. Log: %s", filepath.Join(dir, "share.log"))
}

// runShareProcess is the background process (`__share-run DIR`).
func runShareProcess(dir string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveShare(ctx, dir, func(c *shareConfig) { log.Printf("%s is up, showing %s", c.url(), c.showing()) })
}

func stopShareProcess(dir string) {
	pid := sharePID(dir)
	if pid == 0 {
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Signal(syscall.SIGTERM)
		for i := 0; i < 25 && sharePID(dir) != 0; i++ {
			time.Sleep(200 * time.Millisecond)
		}
		if sharePID(dir) != 0 {
			_ = p.Kill()
		}
	}
	_ = os.Remove(filepath.Join(dir, "share.pid"))
}

// ------------------------------------------------------------ list, stop --

func shareList() error {
	dirs := allShares("")
	if len(dirs) == 0 {
		say("This computer shares nothing. Start with: hogman-join share NAME WHAT")
		return nil
	}
	for _, d := range dirs {
		c, err := loadShare(d)
		if err != nil {
			continue
		}
		state := "not running"
		if sharePID(d) != 0 {
			state = "running in the background"
		}
		say("%-40s %s  (%s)", c.url(), c.showing(), state)
	}
	return nil
}

func findShare(name, zone string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	var hits []string
	for _, d := range allShares(zone) {
		if filepath.Base(d) == name {
			hits = append(hits, d)
		}
	}
	switch len(hits) {
	case 0:
		return "", errorf("this computer doesn't share anything called %s (see: hogman-join share list)", name)
	case 1:
		return hits[0], nil
	}
	return "", errorf("%s is shared on more than one pen here; pick one with --pen", name)
}

func shareStop(name string, o options) error {
	dir, err := findShare(name, o.pen)
	if err != nil {
		return err
	}
	c, err := loadShare(dir)
	if err != nil {
		return err
	}
	step("Taking down %s", c.url())
	if err := removeShare(dir, c); err != nil {
		return err
	}
	say("\n✓ %s is down, and the name is free again.", c.url())
	return nil
}

// removeShare stops a share, gives its name back and removes its device.
func removeShare(dir string, c *shareConfig) error {
	stopShareProcess(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	node, _, hc, err := shareNode(ctx, dir, c)
	if err != nil {
		return errorf("could not reach the pen (%v).\n  Remove the server on your home page instead, then delete %s", err, dir)
	}
	err = giveBack(ctx, hc, c)
	node.Close()
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func giveBack(ctx context.Context, hc *http.Client, c *shareConfig) error {
	var me meView
	err := untilOK(ctx, 60*time.Second, func() (bool, error) {
		code, err := homeAPI(hc, c.Zone, "GET", "/me", nil, &me)
		return code == 0, err
	})
	if err != nil {
		return errorf("could not reach home.%s from the share: %v", c.Zone, err)
	}
	if code, err := homeAPI(hc, c.Zone, "DELETE", "/names/"+url.PathEscape(c.Name), nil, nil); err != nil && code != 404 {
		return errorf("could not give back %s: %v", c.fqdn(), err)
	}
	note("gave back the name %s", c.fqdn())
	if err := giveBackDevice(ctx, hc, c); err != nil {
		return err
	}
	note("removed its server from your devices")
	return nil
}

// giveBackDevice removes the share's own device from the pen.
func giveBackDevice(ctx context.Context, hc *http.Client, c *shareConfig) error {
	var me meView
	if _, err := homeAPI(hc, c.Zone, "GET", "/me", nil, &me); err != nil {
		return errorf("could not reach home.%s from the share: %v", c.Zone, err)
	}
	code, err := homeAPI(hc, c.Zone, "DELETE", "/devices/"+strconv.FormatInt(me.ThisDevice.ID, 10), nil, nil)
	// The pen drops this device as it answers, so the answer may never
	// arrive (code 0); a 404 means it is already gone. Anything else is real.
	if err != nil && code != 0 && code != 404 {
		return errorf("the pen would not remove the share's server: %v", err)
	}
	return nil
}
