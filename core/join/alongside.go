package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// stateDir is where one pen's side-by-side agent keeps its identity and settings.
func stateDir(zone string) string {
	base, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "hogman", zone)
}

func hasAlongside(zone string) bool {
	_, err := os.Stat(filepath.Join(stateDir(zone), "config.json"))
	return err == nil
}

// pickLocalAddr chooses a deterministic port outside the OS ephemeral range
// (17000-26999) from the zone name, scanning forward if that port is in use.
func pickLocalAddr(zone string) (string, error) {
	const basePort = 17000
	const span = 10000
	sum := sha256.Sum256([]byte(zone))
	start := int(binary.BigEndian.Uint32(sum[:4]) % span)
	for i := 0; i < span; i++ {
		port := basePort + (start+i)%span
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		_ = l.Close()
		return l.Addr().String(), nil
	}
	return "", fmt.Errorf("no free local port in %d-%d", basePort, basePort+span-1)
}

func agentState(c *agentConfig) (*agentStatus, error) {
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get(c.proxyURL() + "/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var st agentStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	if st.Zone != c.Zone {
		return nil, fmt.Errorf("something else is listening on %s", c.ProxyAddr)
	}
	return &st, nil
}

func waitAgentUp(c *agentConfig, d time.Duration) (*agentStatus, error) {
	deadline := time.Now().Add(d)
	for {
		st, err := agentState(c)
		if err == nil && st.Up {
			return st, nil
		}
		if err == nil && st.Error != "" {
			return nil, errorf("could not join the pen: %s", st.Error)
		}
		if time.Now().After(deadline) {
			return nil, errorf("the pen connection did not come up within %s. Log: %s", d, filepath.Join(stateDir(c.Zone), "agent.log"))
		}
		time.Sleep(time.Second)
	}
}

// joinAlongside sets up side-by-side mode. why explains, in a few words, why
// this mode was chosen.
func joinAlongside(link *Link, n *networkInfo, root *RootInfo, client *http.Client, o options, why string) error {
	if n.DNSServer == "" {
		return errorf("this pen's server is too old for side-by-side mode (it does not publish its DNS address)")
	}
	dir := stateDir(n.Zone)
	hostname := o.hostname
	if hostname == "" {
		hostname = defaultHostname()
	}
	note("%s", why)
	note("joining side by side: only names ending in .%s use the pen; nothing else on this computer changes", n.Zone)

	existing, _ := loadAgentConfig(dir)
	if o.dryRun {
		step("Dry run: nothing changed. Would:")
		if existing == nil && link.InviteToken != "" {
			note("redeem the invite (handle: %s)", orAsk(o.handle))
		}
		if !o.noTrust {
			note("add the %s certificate to this computer's trust store (trusted now: %v)", n.Zone, trustInstalled(root))
		}
		note("run a small background agent as %q, with a local proxy for .%s (already set up: %v)", hostname, n.Zone, existing != nil)
		return nil
	}

	// A pen can't take over a name this computer already uses for another pen:
	// two roots trusted for one zone would let either impersonate the other.
	// Refuse before trusting anything.
	if existing != nil && existing.LoginServer != n.LoginServer {
		return errorf("this computer is already in a pen called %s (at %s), and %s claims the same name.\n"+
			"  Refusing: two pens with one name could impersonate each other. If you meant to switch,\n"+
			"  leave the other one first: hogman-join leave '<its link>'",
			n.Zone, strings.TrimPrefix(existing.LoginServer, "https://"), link.Host)
	}

	certFile, cleanupCert, err := writeTempCert(root.PEM)
	if err != nil {
		return err
	}
	defer cleanupCert()
	trustedBefore := trustInstalled(root)
	if !o.noTrust {
		step("Adding the %s certificate to this computer", n.Zone)
		if err := installTrust(root, certFile); err != nil {
			return err
		}
	}

	handle := ""
	cfg := existing
	if cfg != nil {
		step("This computer is already set up for %s", n.Zone)
		if link.InviteToken != "" {
			note("not using the invite; it stays valid for another device or person")
		}
	} else {
		key := link.DeviceKey
		if link.InviteToken != "" {
			step("Redeeming the invite")
			en, err := redeemWithHandle(client, link, o)
			if err != nil {
				return err
			}
			key, handle = en.AuthKey, en.Handle
			note("welcome, %s", handle)
		}
		addr, err := pickLocalAddr(n.Zone)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		cfg = &agentConfig{Zone: n.Zone, LoginServer: n.LoginServer, DNSServer: n.DNSServer, Hostname: hostname, ProxyAddr: addr}
		if o.controlCA != "" {
			pemBytes, err := os.ReadFile(o.controlCA)
			if err != nil {
				return errorf("--control-ca: %v", err)
			}
			cfg.ControlCA = string(pemBytes)
		}
		if err := cfg.save(dir); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "authkey"), []byte(key), 0o600); err != nil {
			return err
		}
	}

	step("Starting the pen connection as %q", cfg.Hostname)
	if st, err := agentState(cfg); err != nil || !st.Up {
		if err := startAgent(dir, cfg, o); err != nil {
			return err
		}
	}
	st, err := waitAgentUp(cfg, 90*time.Second)
	if err != nil {
		return err
	}
	if st.Server {
		// An old server link without the for=share mark: never expose a whole
		// computer to the pen. Undo the join.
		leaveAlongside(n.Zone)
		if !o.noTrust && !trustedBefore {
			_ = removeTrust(root, certFile)
		}
		return errorf("that's a server link: it's for putting something in the pen, not for joining a computer.\n" +
			"  Use a new one with share, for example: hogman-join share blog 8080 '<server link>'")
	}
	note("online as %s", strings.Join(st.IPs, ", "))

	browsers := "set your browser's automatic proxy configuration to " + cfg.pacURL()
	if !o.noSystemProxy {
		if msg, err := setSystemProxy(cfg); err != nil {
			note("could not point browsers at the pen automatically: %v", err)
		} else if msg != "" {
			browsers = msg
		}
	}

	step("Checking %s loads securely", n.Portal)
	who, err := checkPortalVia(n.Portal, cfg.proxyURL(), root, o.noTrust)
	if err != nil {
		return err
	}
	if handle == "" {
		handle = who
	}
	say("\n✓ You're in. You are %s on %s.", handle, n.Zone)
	say("  Start at %s", n.Portal)
	say("")
	say("  Browsers: %s", browsers)
	say("  Other tools reach the pen through its proxy, %s", cfg.proxyURL())
	// Per command, not exported: the proxy only serves the pen, so a global
	// https_proxy would break everything else in that shell.
	say("    curl / most CLIs:  https_proxy=%s curl https://<site>.%s", cfg.proxyURL(), n.Zone)
	say("    git:               git config --global http.https://%s/.proxy %s   (per site)", "<site>."+n.Zone, cfg.proxyURL())
	say("  The pen carries HTTPS only.")
	say("  To leave: hogman-join leave '<this link>'")
	if !o.noOpen {
		openURL(n.Portal)
	}
	return nil
}

// checkPortalVia loads the portal through the agent's proxy. With pinned set,
// it trusts only the pen's root (used when the certificate was not installed).
func checkPortalVia(portal, proxy string, root *RootInfo, pinned bool) (string, error) {
	if !pinned {
		// A fresh process, so a just-installed certificate is seen.
		os.Setenv("HOGMAN_CHECK_PROXY", proxy)
		defer os.Unsetenv("HOGMAN_CHECK_PROXY")
		return checkPortalFresh(portal)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(root.PEM))
	pu, _ := url.Parse(proxy)
	c := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}}}
	return pollPortal(c, portal, 45*time.Second)
}

func pollPortal(c *http.Client, portal string, d time.Duration) (string, error) {
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
	return "", errorf("joined, but the portal did not load: %v", last)
}

// leaveAlongside undoes side-by-side mode for a pen. Reports whether there was anything to undo.
func leaveAlongside(zone string) bool {
	dir := stateDir(zone)
	cfg, err := loadAgentConfig(dir)
	if err != nil {
		return false
	}
	if msg := clearSystemProxy(cfg); msg != "" {
		note("%s", msg)
	}
	stopAgent(dir, cfg)
	if self, err := os.Executable(); err == nil {
		_, _ = run(false, self, "__agent-logout", dir)
	}
	_ = os.RemoveAll(dir)
	note("stopped the pen connection and removed its settings")
	return true
}

// stopDetached stops an agent that was started as a plain background process.
func stopDetached(dir string) {
	b, err := os.ReadFile(filepath.Join(dir, "agent.pid"))
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Signal(syscall.SIGTERM)
		for i := 0; i < 20; i++ {
			if _, err := os.Stat(filepath.Join(dir, "agent.pid")); err != nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		_ = p.Kill()
	}
}

// installedBinary copies this program next to the agent's settings, so the
// background service keeps working after the download is deleted.
func installedBinary(dir string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	name := "hogman-join"
	if strings.HasSuffix(strings.ToLower(self), ".exe") {
		name += ".exe"
	}
	dst := filepath.Join(dir, name)
	if self == dst {
		return dst, nil
	}
	in, err := os.Open(self)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return "", err
	}
	return dst, out.Close()
}
