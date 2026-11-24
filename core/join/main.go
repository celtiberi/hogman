// Command hogman-join puts a device on a Hogman network in one step:
//
//	hogman-join 'https://bobo.gate.example.com/join#t=...'
//
// It verifies the network over this computer's built-in trusted certificates,
// redeems the invite (or uses the device key in the link), joins side by side
// with a local proxy for pen names only, and checks the portal loads over HTTPS.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

var version = "dev"

type userError struct{ msg string }

func (e *userError) Error() string { return e.msg }

func errorf(f string, a ...any) error { return &userError{fmt.Sprintf(f, a...)} }

const usageText = `hogman-join: join this device to a Hogman private network

usage:
  hogman-join [options] '<link>'      join, using an invite or device link
  hogman-join update ['<link|host>']  update hogman-join from a pen's server (verifies SHA-256)
  hogman-join leave '<pen>'           take this computer out of one pen (its link, host or name)
  hogman-join leave-all               take this computer out of every pen (asks first)
  hogman-join uninstall               leave every pen and remove Hogman's settings (asks first)
  hogman-join status                  show installed pens, browser extension host, and VPN proxy state
  hogman-join browser-setup           register the browser extension native messaging host (no sudo)
  hogman-join share NAME WHAT         put a port or a folder on the pen over HTTPS
                                      (hogman-join share --help for more)
  hogman-join version                 print version and platform
  hogman-join help [share|update]     show usage

options:
  --handle NAME     the name you want on the network (invite links only; asked if missing)
  --hostname NAME   what this device is called on the network (default: this computer's name)
  --no-service      don't register a login item, just run in the background
  --no-system-proxy don't change this computer's automatic proxy setting
  --dry-run         check the link and the network, then stop without changing anything
  --no-open         don't open the portal in a browser at the end
  --yes             answer prompts automatically where supported
  --verbose         show the commands being run
  --force           leave/share stop: override safety checks or clean up an unreachable pen
  --version         print version and platform
  --control-ca FILE extra certificate to trust for the public control server
                    (test networks with a self-signed control host only)

Quote the link: it contains '#' and '&'.
`

type options struct {
	handle, hostname, controlCA string
	yes, dryRun, noOpen         bool
	force                       bool // leave/uninstall/share stop: override checks or clean up unreachable pen
	alongside                   bool // accepted for old scripts; it's the only way now
	noService, noSystemProxy    bool
	pen                         string // share/update: which pen
	background                  bool   // share: keep running after the window closes
	note                        string // share: one-line note for the pen directory
	noteSet                     bool
	chromeID                    string // browser-setup: optional unpacked Chrome extension ID
	firefoxID                   string // browser-setup: optional Firefox Gecko extension ID
	seenFlags                   map[string]bool
}

func usageForSubcmd(subcmd string) string {
	switch subcmd {
	case "share":
		return shareUsage
	case "update":
		return updateUsage
	default:
		return usageText
	}
}

func isBoolFlag(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	type boolFlagger interface{ IsBoolFlag() bool }
	bf, ok := f.Value.(boolFlagger)
	return ok && bf.IsBoolFlag()
}

func validateSubcommandFlags(pos []string, o options) error {
	if len(o.seenFlags) == 0 || len(pos) == 0 {
		return nil
	}
	// Harmless global flags are accepted everywhere so scripts (like e2e
	// harnesses prefixing --no-open) keep working. Only reject flags that
	// would be unsafe or misleading if silently ignored (e.g. --dry-run on a
	// destructive command, --force where it doesn't apply, or action flags on
	// an unrelated subcommand).
	sub := ""
	var allowed map[string]bool
	switch pos[0] {
	case "leave":
		sub = "leave"
		allowed = map[string]bool{"force": true}
	case "leave-all", "uninstall":
		sub = pos[0]
		allowed = map[string]bool{"force": true}
	case "update":
		sub = "update"
		allowed = map[string]bool{"pen": true, "dry-run": true, "no-service": true}
	case "share":
		if len(pos) >= 2 && pos[1] == "list" {
			sub = "share list"
			allowed = map[string]bool{"pen": true}
		} else if len(pos) >= 2 && pos[1] == "stop" {
			sub = "share stop"
			allowed = map[string]bool{"pen": true, "force": true}
		} else {
			sub = "share"
			allowed = map[string]bool{"note": true, "background": true, "no-service": true, "pen": true}
		}
	case "status":
		sub = "status"
		allowed = map[string]bool{}
	case "browser-setup":
		sub = "browser-setup"
		allowed = map[string]bool{"chrome-id": true, "firefox-id": true}
	case "help", "version", "agent", "__agent-logout", "__share-run":
		sub = pos[0]
		allowed = map[string]bool{}
	default:
		if !strings.Contains(trimMatchingQuotes(pos[0]), "://") {
			// Unknown command; reject unsafe flags like --dry-run instead of
			// treating it as a join.
			sub = pos[0]
			allowed = map[string]bool{}
		} else {
			sub = "join"
			allowed = map[string]bool{
				"handle": true, "hostname": true, "dry-run": true,
				"no-service": true, "no-system-proxy": true,
			}
		}
	}
	harmless := map[string]bool{
		"no-open": true, "verbose": true, "yes": true,
		"control-ca": true, "alongside": true,
	}
	var bad []string
	for name := range o.seenFlags {
		if !harmless[name] && !allowed[name] {
			bad = append(bad, "--"+name)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	// Deterministic order for error messages and tests.
	for i := 0; i < len(bad); i++ {
		for j := i + 1; j < len(bad); j++ {
			if bad[j] < bad[i] {
				bad[i], bad[j] = bad[j], bad[i]
			}
		}
	}
	return errorf("%s is not supported with %q", strings.Join(bad, ", "), sub)
}

func parseCLIArgs(raw []string) (pos []string, o options, showVersion bool, err error) {
	fs := flag.NewFlagSet("hogman-join", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {} // printed explicitly by caller so --help goes to stdout with exit 0
	fs.StringVar(&o.handle, "handle", "", "")
	fs.StringVar(&o.hostname, "hostname", "", "")
	fs.StringVar(&o.controlCA, "control-ca", "", "")
	fs.BoolVar(&o.yes, "yes", false, "")
	fs.BoolVar(&o.force, "force", false, "")
	fs.BoolVar(&o.dryRun, "dry-run", false, "")
	fs.BoolVar(&o.noOpen, "no-open", false, "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.BoolVar(&o.alongside, "alongside", false, "")

	fs.BoolVar(&o.noService, "no-service", false, "")
	fs.BoolVar(&o.noSystemProxy, "no-system-proxy", false, "")
	fs.StringVar(&o.pen, "pen", "", "")
	gone := fs.Bool("tailscale", false, "") // removed (D-11); kept only to explain
	fs.BoolVar(&o.background, "background", false, "")
	fs.StringVar(&o.note, "note", "", "")
	fs.StringVar(&o.chromeID, "chrome-id", "", "")
	fs.StringVar(&o.firefoxID, "firefox-id", "", "")
	ver := fs.Bool("version", false, "")

	seen := map[string]bool{}
	// Allow options before or after the link / share target, while honoring `--`
	// as strict end-of-options and not confusing flag values (like `--note --`).
	for i := 0; i < len(raw); {
		arg := raw[i]
		if arg == "--" {
			pos = append(pos, raw[i+1:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			pos = append(pos, arg)
			i++
			continue
		}
		name := strings.TrimPrefix(arg, "-")
		name = strings.TrimPrefix(name, "-")
		hasEq := strings.Contains(name, "=")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		step := 1
		if !hasEq && fs.Lookup(name) != nil && !isBoolFlag(fs, name) && i+1 < len(raw) {
			step = 2
		}
		if err := fs.Parse(raw[i : i+step]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				sub := ""
				if len(pos) > 0 {
					sub = pos[0]
				}
				return []string{sub}, o, false, flag.ErrHelp
			}
			return nil, o, false, err
		}
		fs.Visit(func(f *flag.Flag) {
			seen[f.Name] = true
			if f.Name == "note" {
				o.noteSet = true
			}
		})
		i += step
	}
	o.seenFlags = seen
	if *gone {
		return nil, o, false, errorf("--tailscale no longer exists: every computer joins through Hogman's own connection,\n" +
			"  which carries HTTPS to the pen and nothing else. Run the same command without it.\n" +
			"  Why: https://hogman.network/docs/faq.html#not")
	}
	if !*ver {
		if err := validateSubcommandFlags(pos, o); err != nil {
			return nil, o, false, err
		}
	}
	return pos, o, *ver, nil
}

func main() {
	if isNativeHostBinary(os.Args[0]) {
		runNativeHostMain()
		return
	}
	pos, o, showVersion, err := parseCLIArgs(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			sub := ""
			if len(pos) > 0 {
				sub = pos[0]
			}
			fmt.Print(usageForSubcmd(sub))
			return
		}
		var u *userError
		if errors.As(err, &u) {
			fmt.Fprintf(os.Stderr, "\n✗ %s\n", u.msg)
		} else {
			fmt.Fprint(os.Stderr, usageText)
		}
		os.Exit(2)
	}
	if showVersion || (len(pos) == 1 && pos[0] == "version") {
		fmt.Println("hogman-join", version, runtime.GOOS+"/"+runtime.GOARCH)
		return
	}
	if len(pos) >= 1 && pos[0] == "help" {
		sub := ""
		if len(pos) >= 2 {
			sub = pos[1]
		}
		fmt.Print(usageForSubcmd(sub))
		return
	}
	switch {
	case len(pos) == 2 && pos[0] == "__agent-logout":
		agentLogout(pos[1])
		return
	case len(pos) == 2 && pos[0] == "agent":
		// Internal: the long-running side-by-side connection.
		if aerr := runAgent(pos[1]); aerr != nil {
			fmt.Fprintln(os.Stderr, aerr.Error())
			os.Exit(1)
		}
		return
	case len(pos) == 2 && pos[0] == "__share-run":
		// Internal: a share running in the background. Permanent failures exit 0
		// after recording "error" in status.json so launchd (SuccessfulExit=false)
		// and systemd (Restart=on-failure) do not restart them in a loop.
		if serr := runShareProcess(pos[1]); serr != nil {
			if isPermanentShareError(serr) {
				fmt.Fprintf(os.Stderr, "%s (permanent failure; stopping automatic restarts)\n", serr.Error())
			} else {
				fmt.Fprintln(os.Stderr, serr.Error())
			}
			os.Exit(shareExitCode(serr))
		}
		return
	case len(pos) >= 1 && pos[0] == "update":
		err = updateCmd(pos[1:], o)
	case len(pos) >= 1 && pos[0] == "share":
		err = shareCmd(pos[1:], o)
	case len(pos) >= 1 && pos[0] == "status":
		if len(pos) != 1 {
			err = errorf("usage: hogman-join status")
		} else {
			err = statusCmd()
		}
	case len(pos) >= 1 && pos[0] == "browser-setup":
		err = browserSetupCmd(pos[1:], o)
	case len(pos) >= 1 && pos[0] == "leave":
		err = leaveCmd(pos[1:], o)
	case len(pos) >= 1 && pos[0] == "leave-all":
		err = leaveAllCmd(pos[1:], o)
	case len(pos) >= 1 && pos[0] == "uninstall":
		err = uninstallCmd(pos[1:], o)
	case len(pos) == 1:
		trimmed := trimMatchingQuotes(pos[0])
		if !strings.Contains(trimmed, "://") {
			fmt.Fprintf(os.Stderr, "\n✗ unknown command %q (run 'hogman-join --help' for usage)\n", pos[0])
			os.Exit(2)
		}
		err = join(pos[0], o)
	default:
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	if err != nil {
		var u *userError
		if errors.As(err, &u) {
			fmt.Fprintf(os.Stderr, "\n✗ %s\n", u.msg)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\n✗ unexpected error: %v\n", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- network --

type networkInfo struct {
	Zone        string `json:"zone"`
	LoginServer string `json:"login_server"`
	CertMode    string `json:"cert_mode"`
	Portal      string `json:"portal"`
	DNSServer   string `json:"dns_server"`
}

type enrolment struct {
	Handle  string `json:"handle"`
	AuthKey string `json:"auth_key"`
}

func controlClient(caFile string) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		b, err := os.ReadFile(caFile)
		if err != nil || !pool.AppendCertsFromPEM(b) {
			return nil, errorf("--control-ca: cannot read a certificate from %s", caFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			orig := via[0].URL
			if !strings.EqualFold(req.URL.Host, orig.Host) {
				return fmt.Errorf("refusing cross-host redirect to %s", req.URL.Host)
			}
			if strings.EqualFold(orig.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
				return errors.New("refusing HTTPS downgrade redirect")
			}
			return nil
		},
	}, nil
}

var (
	zoneRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?\.hogman$`)
	dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func validPublicDNSName(name string) bool {
	if name == "" || len(name) > 253 || name != strings.ToLower(name) ||
		strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lbl := range labels {
		if !dnsLabelRE.MatchString(lbl) {
			return false
		}
	}
	return true
}

func validatePublicZone(inviteHost, zone string) error {
	h := strings.TrimSpace(inviteHost)
	if hostPart, _, err := net.SplitHostPort(h); err == nil {
		h = hostPart
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if net.ParseIP(h) != nil || !validPublicDNSName(h) {
		return errorf("%s is not a valid domain name for public certificates", inviteHost)
	}
	if !validPublicDNSName(zone) || strings.HasSuffix(zone, ".hogman") {
		return errorf("%s sent an unexpected network name %q", inviteHost, zone)
	}
	eTLD1, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return errorf("%s is not under a registrable public domain: %v", inviteHost, err)
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(zone); err != nil {
		return errorf("%s sent an invalid public network name %q", inviteHost, zone)
	}
	// Hosted gates (<pen>.gate.<base>) must bind exclusively to <pen>.pens.<base>.
	if parts := strings.SplitN(h, ".", 3); len(parts) == 3 && parts[1] == "gate" && parts[0] != "" && parts[2] != "" &&
		(parts[2] == eTLD1 || strings.HasSuffix(parts[2], "."+eTLD1)) {
		want := parts[0] + ".pens." + parts[2]
		if zone != want {
			return errorf("refusing: %s claimed zone %q instead of %q", inviteHost, zone, want)
		}
		return nil
	}
	// Self-hosted gates must choose a strict subdomain of the gate's registrable domain.
	if !strings.HasSuffix(zone, "."+eTLD1) || len(zone) <= len("."+eTLD1) {
		return errorf("refusing: %s claimed zone %q outside %s", inviteHost, zone, eTLD1)
	}
	return nil
}

func testACMECAPool() (*x509.CertPool, error) {
	path := strings.TrimSpace(os.Getenv("HOGMAN_ACME_CA_ROOT"))
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errorf("HOGMAN_ACME_CA_ROOT: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errorf("HOGMAN_ACME_CA_ROOT: %s contains no valid certificate", path)
	}
	return pool, nil
}

func validateNetworkInfo(host string, n *networkInfo) error {
	if n.CertMode != "" && n.CertMode != "public" {
		return errorf("%s returned unsupported certificate mode %q", host, n.CertMode)
	}
	if err := validatePublicZone(host, n.Zone); err != nil {
		return err
	}
	if n.LoginServer != "https://"+host {
		return errorf("refusing: %s redirected login to %q instead of https://%s", host, n.LoginServer, host)
	}
	if n.Portal != "https://home."+n.Zone {
		return errorf("refusing: %s returned unexpected portal address %q", host, n.Portal)
	}
	if n.DNSServer != "" {
		addr, err := netip.ParseAddr(n.DNSServer)
		if err != nil || !inMeshRanges(addr) {
			return errorf("refusing: %s returned non-mesh DNS address %q", host, n.DNSServer)
		}
	}
	return nil
}

func fetchNetwork(c *http.Client, host string) (*networkInfo, error) {
	resp, err := c.Get("https://" + host + "/hogman/v1/network")
	if err != nil {
		return nil, errorf("cannot reach the network at %s: %v", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errorf("%s did not answer as a Hogman network (HTTP %d)", host, resp.StatusCode)
	}
	var n networkInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&n); err != nil {
		return nil, errorf("%s sent an unreadable answer: %v", host, err)
	}
	if err := validateNetworkInfo(host, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

func writeTempCert(pemText string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "hogman-*")
	if err != nil {
		return "", nil, err
	}
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, err
	}
	certFile := filepath.Join(tmpDir, "root.crt")
	if err := os.WriteFile(certFile, []byte(pemText), 0o600); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, err
	}
	return certFile, func() { _ = os.RemoveAll(tmpDir) }, nil
}

func redeem(c *http.Client, host, token, handle string) (*enrolment, error) {
	body, _ := json.Marshal(map[string]string{"token": token, "handle": handle})
	resp, err := c.Post("https://"+host+"/hogman/v1/redeem", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, errorf("cannot reach the network: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 201 {
		var e struct{ Error string }
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, &redeemError{status: resp.StatusCode, msg: e.Error}
	}
	var en enrolment
	if err := json.Unmarshal(data, &en); err != nil || en.AuthKey == "" {
		return nil, errorf("the network accepted the invite but sent an unreadable answer")
	}
	return &en, nil
}

type redeemError struct {
	status int
	msg    string
}

func (e *redeemError) Error() string { return e.msg }

var handleRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)

var nonHostnameRE = regexp.MustCompile(`[^a-z0-9-]+`)

func sanitizeHostname(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	h = strings.Split(h, ".")[0]
	h = nonHostnameRE.ReplaceAllString(h, "-")
	h = strings.Trim(h, "-")
	if len(h) > 63 {
		h = strings.TrimRight(h[:63], "-")
	}
	return h
}

func defaultHostname() string {
	h, _ := os.Hostname()
	if h = sanitizeHostname(h); h != "" {
		return h
	}
	return "device"
}

// ------------------------------------------------------------------- join --

func join(raw string, o options) error {
	link, err := ParseLink(raw)
	if err != nil {
		return errorf("%v", err)
	}
	if link.ForShare {
		return errorf("that's a server link: it's for putting something in the pen, not for joining a computer.\n" +
			"  Use it with share, for example: hogman-join share blog 8080 '<this link>'")
	}
	client, err := controlClient(o.controlCA)
	if err != nil {
		return err
	}

	step("Checking the network at %s", link.Host)
	n, err := fetchNetwork(client, link.Host)
	if err != nil {
		return err
	}
	note("network: %s", n.Zone)

	// One way in (D-11): the agent, which runs as this user and carries HTTPS to
	// the pen's names and nothing else. Joining through this computer's
	// Tailscale app was removed: it put every program on the pen and gave the
	// pen's control server this computer's DNS, a choice that should never be
	// one member's to make for the whole pen.
	if ts, err := findTailscale(); err == nil {
		if st, err := ts.Status(); err == nil && st.BackendState == "Running" && st.OnNetwork(n.Zone) {
			return errorf("this computer is on %s through its Tailscale app, which Hogman no longer uses.\n"+
				"  First get a fresh one-time link: open %s, press Add a device, copy the link.\n"+
				"  Then run hogman-join leave %s, and join with the fresh link.", n.Zone, n.Portal, n.Zone)
		}
	}
	return joinAlongside(link, n, client, o, "the pen's own small connection: HTTPS to the pen and nothing else")
}

func firstLine(s string) string { return strings.SplitN(strings.TrimSpace(s), "\n", 2)[0] }

func orAsk(h string) string {
	if h == "" {
		return "will ask"
	}
	return h
}

func redeemWithHandle(c *http.Client, link *Link, o options) (*enrolment, error) {
	handle := strings.ToLower(strings.TrimSpace(o.handle))
	for attempt := 0; ; attempt++ {
		if handle == "" {
			if !isTerminal() {
				return nil, errorf("choose a name with --handle (lowercase letters, digits, dashes)")
			}
			handle = strings.ToLower(ask("  Choose your name on the network (lowercase letters, digits, dashes): "))
		}
		if !handleRE.MatchString(handle) {
			if o.handle != "" || !isTerminal() {
				return nil, errorf("%q is not a valid name: 2-32 lowercase letters, digits or dashes, starting with a letter", handle)
			}
			note("that is not a valid name")
			handle = ""
			continue
		}
		en, err := redeem(c, link.Host, link.InviteToken, handle)
		var re *redeemError
		if errors.As(err, &re) && re.status == 409 && o.handle == "" && isTerminal() && attempt < 5 {
			note("%s", re.msg)
			handle = ""
			continue
		}
		if errors.As(err, &re) {
			return nil, errorf("the invite was not accepted: %s", re.msg)
		}
		return en, err
	}
}
