// Command hogman-join puts a device on a Hogman network in one step:
//
//	hogman-join 'https://hs.example.com/join#t=...&fp=...'
//
// It checks the network's certificate against the fingerprint in the link,
// redeems the invite (or uses the device key in the link), adds the
// certificate to this computer's trust store, joins with the Tailscale client
// as a separate profile, and checks the network's portal loads over HTTPS.
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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var version = "dev"

type userError struct{ msg string }

func (e *userError) Error() string { return e.msg }

func errorf(f string, a ...any) error { return &userError{fmt.Sprintf(f, a...)} }

const usageText = `hogman-join: join this device to a Hogman private network

usage:
  hogman-join [options] '<link>'      join, using an invite or device link
  hogman-join leave '<link>'          remove the network's certificate and log out of it
  hogman-join share NAME WHAT         put a port or a folder on the pen as https://NAME.<pen>.hogman
                                      (hogman-join share --help for more)

options:
  --handle NAME     the name you want on the network (invite links only; asked if missing)
  --hostname NAME   what this device is called on the network (default: this computer's name)
  --no-service      don't register a login item, just run in the background
  --no-system-proxy don't change this computer's automatic proxy setting
  --dry-run         check the link and the network, then stop without changing anything
  --no-trust        don't add the network's certificate to this computer
  --no-open         don't open the portal in a browser at the end
  --verbose         show the commands being run
  --control-ca FILE extra certificate to trust for the public control server
                    (test networks with a self-signed control host only)

Quote the link: it contains '#' and '&'.
`

type options struct {
	handle, hostname, controlCA  string
	yes, dryRun, noTrust, noOpen bool
	alongside                    bool // accepted for old scripts; it's the only way now
	noService, noSystemProxy     bool
	pen                          string // share: which pen
	background                   bool   // share: keep running after the window closes
	note                         string // share: one-line note for the pen directory
	noteSet                      bool
}

func parseCLIArgs(raw []string) (pos []string, o options, showVersion bool, err error) {
	fs := flag.NewFlagSet("hogman-join", flag.ContinueOnError)
	fs.Usage = func() {
		if len(pos) > 0 && pos[0] == "share" {
			fmt.Print(shareUsage)
		} else {
			fmt.Print(usageText)
		}
	}
	fs.StringVar(&o.handle, "handle", "", "")
	fs.StringVar(&o.hostname, "hostname", "", "")
	fs.StringVar(&o.controlCA, "control-ca", "", "")
	fs.BoolVar(&o.yes, "yes", false, "")
	fs.BoolVar(&o.dryRun, "dry-run", false, "")
	fs.BoolVar(&o.noTrust, "no-trust", false, "")
	fs.BoolVar(&o.noOpen, "no-open", false, "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.BoolVar(&o.alongside, "alongside", false, "")

	fs.BoolVar(&o.noService, "no-service", false, "")
	fs.BoolVar(&o.noSystemProxy, "no-system-proxy", false, "")
	fs.StringVar(&o.pen, "pen", "", "")
	fs.BoolVar(&o.background, "background", false, "")
	fs.StringVar(&o.note, "note", "", "")
	ver := fs.Bool("version", false, "")

	// Allow options before or after the link / share target.
	args := raw
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, o, false, err
		}
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "note" {
				o.noteSet = true
			}
		})
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return pos, o, *ver, nil
}

func main() {
	pos, o, showVersion, err := parseCLIArgs(os.Args[1:])
	if err != nil {
		os.Exit(2)
	}
	if showVersion {
		fmt.Println("hogman-join", version, runtime.GOOS+"/"+runtime.GOARCH)
		return
	}
	switch {
	case len(pos) == 2 && pos[0] == "__check-portal":
		// Internal: runs in a fresh process so the trust store is read anew
		// (Go loads the system's certificates once per process on Linux).
		who, cerr := checkPortal(pos[1], 45*time.Second)
		if cerr != nil {
			fmt.Fprintln(os.Stderr, cerr.Error())
			os.Exit(1)
		}
		fmt.Println(who)
		return
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
		// Internal: a share running in the background.
		if serr := runShareProcess(pos[1]); serr != nil {
			fmt.Fprintln(os.Stderr, serr.Error())
			os.Exit(1)
		}
		return
	case len(pos) >= 1 && pos[0] == "share":
		err = shareCmd(pos[1:], o)
	case len(pos) == 1:
		err = join(pos[0], o)
	case len(pos) == 2 && pos[0] == "leave":
		err = leave(pos[1], o)
	default:
		fmt.Print(usageText)
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
	Zone            string `json:"zone"`
	LoginServer     string `json:"login_server"`
	RootCA          string `json:"root_ca"`
	RootFingerprint string `json:"root_fingerprint"`
	Portal          string `json:"portal"`
	DNSServer       string `json:"dns_server"`
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
	return &http.Client{Timeout: 20 * time.Second, Transport: tr}, nil
}

var zoneRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?\.hogman$`)

func validateNetworkInfo(host string, n *networkInfo) error {
	if !zoneRE.MatchString(n.Zone) {
		return errorf("%s sent an unexpected network name %q", host, n.Zone)
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

func defaultHostname() string {
	h, _ := os.Hostname()
	h = strings.ToLower(strings.Split(h, ".")[0])
	h = regexp.MustCompile(`[^a-z0-9-]+`).ReplaceAllString(h, "-")
	return strings.Trim(h, "-")
}

// ------------------------------------------------------------------- join --

func join(raw string, o options) error {
	link, err := ParseLink(raw)
	if err != nil {
		return errorf("%v", err)
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
	root, err := CheckRoot(n.RootCA, link.Fingerprint, n.Zone)
	if err != nil {
		return errorf("%v", err)
	}
	note("network: %s", n.Zone)
	note("its certificate matches the link (%s)", short(root.Fingerprint))
	note("and can only vouch for names ending in .%s", n.Zone)

	// One way in (D-11): the agent, which runs as this user and carries HTTPS to
	// the pen's names and nothing else. Joining through this computer's
	// Tailscale app was removed: it put every program on the pen and gave the
	// pen's control server this computer's DNS, a choice that should never be
	// one member's to make for the whole pen.
	if ts, err := findTailscale(); err == nil {
		if st, err := ts.Status(); err == nil && st.BackendState == "Running" && st.OnNetwork(n.Zone) {
			return errorf("this computer is on %s through its Tailscale app, which Hogman no longer uses.\n"+
				"  Run hogman-join leave '<this link>' first, then join again with the same link.", n.Zone)
		}
	}
	return joinAlongside(link, n, root, client, o, "the pen's own small connection: HTTPS to the pen and nothing else")
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

// checkPortalFresh runs checkPortal in a new copy of this program, so the
// check sees the trust store as any newly started app would.
func checkPortalFresh(portal string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return checkPortal(portal, 45*time.Second)
	}
	cmd := exec.Command(self, "__check-portal", portal)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return "", errorf("%s", strings.TrimSpace(errOut.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// checkPortal loads the portal using this computer's own trust store and DNS:
// exactly what a browser will do. It returns the member's handle.
func checkPortal(portal string, d time.Duration) (string, error) {
	c := &http.Client{Timeout: 8 * time.Second}
	if p := os.Getenv("HOGMAN_CHECK_PROXY"); p != "" {
		if pu, err := url.Parse(p); err == nil {
			c.Transport = &http.Transport{Proxy: http.ProxyURL(pu)}
		}
	}
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		resp, err := c.Get(portal + "/api/me")
		if err == nil {
			var me struct {
				Member struct{ Handle string }
			}
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode == 200 && json.Unmarshal(data, &me) == nil {
				return me.Member.Handle, nil
			}
			err = fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	var ue x509.UnknownAuthorityError
	if errors.As(last, &ue) {
		return "", errorf("the portal's certificate is not trusted on this computer yet: %v", last)
	}
	var dnsErr *net.DNSError
	if errors.As(last, &dnsErr) {
		return "", errorf("this computer cannot find the network's names yet (%v). Is Tailscale's DNS enabled?", last)
	}
	return "", errorf("joined, but the portal did not load: %v", last)
}

// ------------------------------------------------------------------ leave --

func leave(raw string, o options) error {
	link, err := ParseLink(raw)
	if err != nil {
		return errorf("%v", err)
	}
	client, err := controlClient(o.controlCA)
	if err != nil {
		return err
	}
	step("Leaving the network at %s", link.Host)
	n, err := fetchNetwork(client, link.Host)
	if err != nil {
		return err
	}
	root, err := CheckRoot(n.RootCA, link.Fingerprint, n.Zone)
	if err != nil {
		return errorf("%v", err)
	}
	// Shares on this pen go first, while they can still give their names back.
	for _, dir := range allShares(n.Zone) {
		if c, err := loadShare(dir); err == nil {
			if err := removeShare(dir, c); err != nil {
				note("could not take down %s: %v", c.url(), firstLine(err.Error()))
			} else {
				note("took down %s", c.url())
			}
		}
	}
	// The certificate: it is the part that matters on this computer, and it
	// needs nothing from the network.
	certFile, cleanupCert, err := writeTempCert(root.PEM)
	if err != nil {
		return err
	}
	defer cleanupCert()
	had := trustInstalled(root)
	if err := removeTrust(root, certFile); err != nil {
		return err
	}
	if had {
		note("removed the %s certificate", n.Zone)
	} else {
		note("the %s certificate was not installed", n.Zone)
	}
	leaveAlongside(n.Zone)
	if ts, err := findTailscale(); err == nil {
		if st, err := ts.Status(); err == nil && st.OnNetwork(n.Zone) {
			if err := ts.Logout(); err != nil {
				// Logging out needs the control server. If it can't be reached,
				// at least disconnect this device locally.
				_ = ts.Down()
				note("disconnected, but could not log out (%v)", firstLine(err.Error()))
				note("the network still lists this device until an admin removes it")
			} else {
				note("logged out of %s", n.Zone)
			}
			note("to return to another Tailscale network: tailscale switch --list")
		}
		if removed := ts.RemoveProfiles(link.Host); removed > 0 {
			note("removed the saved %s profile from Tailscale", n.Zone)
		}
	}
	say("\n✓ Left %s.", n.Zone)
	return nil
}
