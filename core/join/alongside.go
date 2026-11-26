package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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

func hogmanConfigBase() string { return filepath.Dir(stateDir("x")) }

func pickPACHost(remaining []*agentConfig) *agentConfig {
	if len(remaining) == 0 {
		return nil
	}
	for _, p := range remaining {
		if st, err := agentState(p); err == nil && st.Up {
			return p
		}
	}
	for _, p := range remaining {
		if _, err := agentState(p); err == nil {
			return p
		}
	}
	return remaining[0]
}

// pickLocalAddr chooses a random port outside the OS ephemeral range
// (17000-26999), scanning forward if that port is in use, so remote web pages
// cannot predict a pen's loopback proxy port from its zone name.
func pickLocalAddr(_ string) (string, error) {
	const basePort = 17000
	const span = 10000
	var rb [4]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return "", fmt.Errorf("pick local port: %w", err)
	}
	start := int(binary.BigEndian.Uint32(rb[:]) % span)
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
	return agentStateInDir(stateDir(c.Zone), c)
}

func agentStateInDir(dir string, c *agentConfig) (*agentStatus, error) {
	tokBytes, err := os.ReadFile(filepath.Join(dir, statusTokenFilename))
	token := strings.TrimSpace(string(tokBytes))
	if err != nil || token == "" {
		return nil, fmt.Errorf("missing agent status token for %s", c.Zone)
	}
	nonce, err := generateHexToken(16)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, c.proxyURL()+"/status", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Hogman-Challenge", nonce)
	client := &http.Client{
		Timeout:       2 * time.Second,
		Transport:     loopbackStatusTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("something else is listening on %s", c.ProxyAddr)
	}
	var st agentStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&st); err != nil {
		return nil, err
	}
	if st.Zone != c.Zone {
		return nil, fmt.Errorf("something else is listening on %s", c.ProxyAddr)
	}
	gotProof := strings.TrimSpace(resp.Header.Get("X-Hogman-Proof"))
	wantProof := computeStatusProof(token, nonce, c.Zone)
	if gotProof == "" || !hmac.Equal([]byte(gotProof), []byte(wantProof)) {
		return nil, fmt.Errorf("unverified process listening on %s", c.ProxyAddr)
	}
	return &st, nil
}

type agentJoinError struct{ msg string }

func (e *agentJoinError) Error() string { return e.msg }

func waitAgentUp(c *agentConfig, d time.Duration) (*agentStatus, error) {
	return waitAgentUpCtx(context.Background(), c, d)
}

func waitAgentUpCtx(ctx context.Context, c *agentConfig, d time.Duration) (*agentStatus, error) {
	deadline := time.Now().Add(d)
	lastStatusErr := ""
	for {
		st, err := agentState(c)
		if err == nil && st.Up {
			return st, nil
		}
		if err == nil && st.Error != "" {
			// Only abort immediately on a fatal startup error (!Enrolled, e.g.
			// rejected authkey) or an explicit NeedsLogin rejection. Once the
			// device has enrolled (st.Enrolled), "not connected to pen" is a
			// transient state while the registrar's Sync loop adds this device's
			// IP to Headscale's ACL policy (I-21).
			if !st.Enrolled || st.NeedsLogin {
				return nil, &agentJoinError{msg: fmt.Sprintf("could not join the pen: %s", st.Error)}
			}
			lastStatusErr = st.Error
		}
		if err := ctx.Err(); err != nil {
			return nil, errorf("cancelled before the pen connection came up (saved credentials were kept; re-run the same command to resume)")
		}
		if time.Now().After(deadline) {
			if lastStatusErr != "" {
				return nil, errorf("enrolled on %s, but the pen connection did not come up within %s (last status: %s).\n  Saved credentials were kept so this device is not orphaned; re-run hogman to retry, or run 'hogman leave %s' to remove it.\n  Log: %s", c.Zone, d, lastStatusErr, c.Zone, filepath.Join(stateDir(c.Zone), "agent.log"))
			}
			return nil, errorf("the pen connection did not come up within %s. Log: %s", d, filepath.Join(stateDir(c.Zone), "agent.log"))
		}
		select {
		case <-ctx.Done():
			return nil, errorf("cancelled before the pen connection came up (saved credentials were kept; re-run the same command to resume)")
		case <-time.After(time.Second):
		}
	}
}

// existingPenNeedsReenroll reports whether an already-configured pen's running
// agent explicitly proves (via verified status.token HMAC) that the control
// plane rejected this device (NeedsLogin). Unspent authkeys from an interrupted
// join are NOT treated as stale so we retry them without burning a fresh invite.
func existingPenNeedsReenroll(dir string, cfg *agentConfig) bool {
	if cfg == nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "authkey")); err == nil {
		return false
	}
	if state, detail := verifyAgentEndpointDetail(dir, cfg); state == agentEndpointDown && detail.verified && detail.needsLogin {
		return true
	}
	return false
}

// reenrollExistingPen acquires the new authkey BEFORE touching existing local
// state (so a failed invite redeem never destroys the saved pen setup), then
// stops the old agent and swaps in the fresh credentials.
func reenrollExistingPen(dir string, existing *agentConfig, n *networkInfo, hostname string, o options, acquireKey func() (key, handle string, err error), stopFn func(string, *agentConfig)) (*agentConfig, string, error) {
	key, handle, err := acquireKey()
	if err != nil {
		return nil, "", err
	}
	if stopFn != nil {
		stopFn(dir, existing)
	}
	_ = os.RemoveAll(filepath.Join(dir, "node"))
	_ = os.Remove(filepath.Join(dir, "authkey"))
	addr := existing.ProxyAddr
	if addr == "" {
		addr, err = pickLocalAddr(n.Zone)
		if err != nil {
			return nil, "", err
		}
	}
	cfg := &agentConfig{
		Zone:        n.Zone,
		LoginServer: n.LoginServer,
		DNSServer:   n.DNSServer,
		Hostname:    hostname,
		ProxyAddr:   addr,
		ControlCA:   existing.ControlCA,
	}
	if o.controlCA != "" {
		pemBytes, rerr := os.ReadFile(o.controlCA)
		if rerr != nil {
			return nil, "", errorf("--control-ca: %v", rerr)
		}
		cfg.ControlCA = string(pemBytes)
	}
	if err := cfg.save(dir); err != nil {
		return nil, "", err
	}
	if _, err := writeStatusToken(dir); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "authkey"), []byte(key), 0o600); err != nil {
		return nil, "", err
	}
	return cfg, handle, nil
}

// shouldRollbackFreshJoin decides whether a failed fresh join should tear down
// local state. Roll back only when enrollment itself failed before the device
// joined the control plane (an unspent authkey is still on disk and the agent
// reported a definite rejection). Once the device has enrolled on the server
// (authkey removed by the agent), never log it out on a follow-up check failure
// so the user never ends up with an orphaned device on the server (I-21).
func shouldRollbackFreshJoin(freshJoin bool, dir string, err error) bool {
	if !freshJoin || err == nil {
		return false
	}
	if _, statErr := os.Stat(filepath.Join(dir, "authkey")); statErr != nil {
		return false
	}
	var aje *agentJoinError
	return errors.As(err, &aje)
}

// joinAlongside sets up side-by-side mode. why explains, in a few words, why
// this mode was chosen.
func joinAlongside(link *Link, n *networkInfo, client *http.Client, o options, why string) error {
	if n.DNSServer == "" {
		return errorf("this pen's server is too old for side-by-side mode (it does not publish its DNS address)")
	}
	dir := stateDir(n.Zone)
	hostname := defaultHostname()
	if strings.TrimSpace(o.hostname) != "" {
		hostname = sanitizeHostname(o.hostname)
		if hostname == "" {
			return errorf("--hostname %q contains no letters or digits", o.hostname)
		}
	}
	note("%s", why)
	note("joining side by side: only names ending in .%s use the pen; nothing else on this computer changes", n.Zone)

	existing, _ := loadAgentConfig(dir)
	reenroll := existing != nil && (link.InviteToken != "" || link.DeviceKey != "") && existingPenNeedsReenroll(dir, existing)
	var oldSameServer []penTarget
	if existing == nil {
		oldSameServer = findLegacySameServerPens(hogmanConfigBase(), n.Zone, n.LoginServer)
	}
	if o.dryRun {
		step("Dry run: nothing changed. Would:")
		if (existing == nil || reenroll) && link.InviteToken != "" {
			note("redeem the invite (handle: %s)", orAsk(o.handle))
		}
		note("verify %s using this computer's built-in trusted certificates", n.Zone)
		note("run a small background agent as %q, with a local proxy for .%s (already set up: %v)", hostname, n.Zone, existing != nil && !reenroll)
		for _, old := range oldSameServer {
			note("retire old %s pen setup (%s)", old.zone, old.dir)
		}
		return nil
	}

	acquireKey := func() (string, string, error) {
		if link.InviteToken != "" {
			step("Redeeming the invite")
			en, err := redeemWithHandle(client, link, o)
			if err != nil {
				return "", "", err
			}
			note("welcome, %s", en.Handle)
			return en.AuthKey, en.Handle, nil
		}
		return link.DeviceKey, "", nil
	}

	handle := ""
	cfg := existing
	freshJoin := existing == nil
	if cfg != nil && reenroll {
		step("Previous %s setup needs a fresh login; re-enrolling with the new link", n.Zone)
		var err error
		cfg, handle, err = reenrollExistingPen(dir, existing, n, hostname, o, acquireKey, stopAgent)
		if err != nil {
			return err
		}
		freshJoin = true
	} else if cfg != nil {
		step("This computer is already set up for %s", n.Zone)
		if link.InviteToken != "" {
			note("not using the invite; it stays valid for another device or person")
		}
		if cfg.LoginServer != n.LoginServer {
			cfg.LoginServer = n.LoginServer
			if err := cfg.save(dir); err != nil {
				return err
			}
		}
	} else {
		key, h, err := acquireKey()
		if err != nil {
			return err
		}
		handle = h
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
		if _, err := writeStatusToken(dir); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "authkey"), []byte(key), 0o600); err != nil {
			return err
		}
	}

	ctx, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSig()

	step("Starting the pen connection as %q", cfg.Hostname)
	if err := startAgent(dir, cfg, o); err != nil {
		return err
	}
	st, err := waitAgentUpCtx(ctx, cfg, 90*time.Second)
	if err != nil {
		if shouldRollbackFreshJoin(freshJoin, dir, err) {
			leaveAlongside(n.Zone, false)
		}
		var aje *agentJoinError
		if errors.As(err, &aje) {
			return errorf("%s", aje.msg)
		}
		return err
	}
	// If this pen still had a legacy per-pen hogman-join binary, clean it up
	// now that the canonical hogman agent is online.
	cleanupLegacyPenBinary(dir)
	if st.Server {
		// An old server link without the for=share mark: never expose a whole
		// computer to the pen. Undo the join.
		leaveAlongside(n.Zone, false)
		return errorf("that's a server link: it's for putting something in the pen, not for joining a computer.\n" +
			"  Use a new one with share, for example: hogman share blog 8080 '<server link>'")
	}
	note("online as %s", strings.Join(st.IPs, ", "))

	step("Checking %s loads securely", n.Portal)
	who, err := checkPortalViaCtx(ctx, n.Portal, cfg.proxyURL())
	if err != nil {
		if ctx.Err() == nil && shouldRollbackFreshJoin(freshJoin, dir, err) {
			leaveAlongside(n.Zone, false)
		}
		return err
	}
	if handle == "" {
		handle = who
	}
	retireLegacySameServerPens(oldSameServer, defaultLegacyRetireOps())

	pens := normalizePenConfigs(loadInstalledPenConfigs(hogmanConfigBase()), cfg)
	if _, _, err := installNativeHost(hogmanConfigBase(), nil, nil); err != nil {
		note("could not register browser extension host: %v", err)
	}
	browsers := "set your browser's automatic proxy configuration to " + cfg.pacURL()
	proxyConfigured := false
	if !o.noSystemProxy {
		if msg, ok, err := setSystemProxy(cfg, pens); err != nil {
			note("could not point browsers at the pen automatically: %v", err)
		} else {
			proxyConfigured = ok
			if msg != "" {
				browsers = msg
			}
		}
	}
	say("\n✓ You're in. You are %s on %s.", handle, n.Zone)
	say("  Start at %s", n.Portal)
	say("")
	say("  Browsers: %s", browsers)
	if !o.noSystemProxy && !extensionRecentlySeen(hogmanConfigBase(), 7*24*time.Hour) {
		if sys := detectSystemProxyState(pens); sys.VPNOverride {
			say("  ! VPN active (%s): macOS hides automatic proxy settings while a VPN is connected.", sys.VPNInterface)
			say("    Install the Hogman extension in Chrome, Brave, Edge, or Firefox to browse pen sites with your VPN on (Safari requires pausing the VPN).")
		}
	}
	say("  Other tools reach the pen through its proxy, %s", cfg.proxyURL())
	// Per command, not exported: the proxy only serves the pen, so a global
	// https_proxy would break everything else in that shell.
	say("    curl / most CLIs:  https_proxy=%s curl https://<site>.%s", cfg.proxyURL(), n.Zone)
	say("    git:               git config --global http.https://%s/.proxy %s   (per site)", "<site>."+n.Zone, cfg.proxyURL())
	say("  The pen carries HTTPS only.")
	say("  To leave: hogman leave '<this link>'")
	if !o.noOpen {
		// On macOS, only auto-open home.<zone> when a Hogman proxy or browser
		// extension is already configured; otherwise opening immediately would
		// flash a broken DNS error tab before the user pastes the PAC URL.
		shouldOpen := runtime.GOOS != "darwin" || proxyConfigured || extensionRecentlySeen(hogmanConfigBase(), 7*24*time.Hour)
		if shouldOpen {
			openURL(n.Portal)
		}
	}
	return nil
}

func checkPortalViaCtx(ctx context.Context, portal, proxy string) (string, error) {
	pool, err := testACMECAPool()
	if err != nil {
		return "", err
	}
	pu, err := url.Parse(proxy)
	if err != nil || pu == nil || pu.Host == "" {
		return "", errorf("invalid local proxy URL %q", proxy)
	}
	c := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	return pollPortalCtx(ctx, c, portal, 45*time.Second)
}

func pollPortalCtx(ctx context.Context, c *http.Client, portal string, d time.Duration) (string, error) {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return "", errorf("cancelled while checking the portal")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, portal+"/api/me", nil)
		if err == nil {
			var resp *http.Response
			resp, err = c.Do(req)
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
		}
		if ctx.Err() != nil {
			return "", errorf("cancelled while checking the portal")
		}
		last = err
		select {
		case <-ctx.Done():
			return "", errorf("cancelled while checking the portal")
		case <-time.After(2 * time.Second):
		}
	}
	var ue x509.UnknownAuthorityError
	if errors.As(last, &ue) {
		return "", errorf("the portal's certificate is not trusted on this computer: %v", last)
	}
	return "", errorf("joined, but the portal did not load: %v", last)
}

// removeOwnDevice asks the pen, as this computer, to remove this computer's
// device. Best effort: leaving still works if the pen can't be reached. It
// reports whether the pen accepted that.
func removeOwnDevice(zone string) bool {
	dir := stateDir(zone)
	cfg, err := loadAgentConfig(dir)
	if err != nil {
		return false
	}
	// Only skip device removal / logout when the running agent passes HMAC
	// status.token verification AND the control plane explicitly reports NeedsLogin.
	if state, detail := verifyAgentEndpointDetail(dir, cfg); state == agentEndpointDown && detail.verified && detail.needsLogin {
		note("this computer was already removed from the pen")
		return true
	}
	c, err := penClient(cfg)
	if err != nil {
		note("could not reach the pen while leaving: %v", err)
		return false
	}
	checkNeedsLogin := func(_ context.Context) bool {
		state, detail := verifyAgentEndpointDetail(dir, cfg)
		return state == agentEndpointDown && detail.verified && detail.needsLogin
	}
	return removeOwnDeviceWith(context.Background(), c, zone, checkNeedsLogin)
}

func removeOwnDeviceWith(ctx context.Context, c *http.Client, zone string, checkNeedsLogin func(context.Context) bool) bool {
	var me meView
	if _, err := homeAPICtx(ctx, c, zone, "GET", "/me", nil, &me); err != nil || me.ThisDevice.ID == 0 {
		note("could not remove this computer from your devices (the keeper can, on the home page)")
		return false
	}
	delCtx, delCancel := context.WithTimeout(ctx, selfDeleteTimeout)
	defer delCancel()
	delClient := *c
	if delClient.Timeout == 0 || delClient.Timeout > selfDeleteTimeout {
		delClient.Timeout = selfDeleteTimeout
	}
	code, err := homeAPICtx(delCtx, &delClient, zone, "DELETE", "/devices/"+strconv.FormatInt(me.ThisDevice.ID, 10), nil, nil)
	if err == nil || code == http.StatusNotFound {
		note("removed this computer from your devices")
		return true
	}
	if code == 0 && ctx.Err() == nil {
		if confirmDeviceRemoved(ctx, c, zone, checkNeedsLogin) {
			note("removed this computer from your devices")
			return true
		}
		note("could not confirm removal from your devices; check Devices on home.%s", zone)
		return false
	}
	if err != nil {
		note("could not remove this computer from your devices: %v", firstLine(err.Error()))
	}
	return false
}

// penClient talks to the pen's home page as this computer, through its own
// running connection.
func penClient(cfg *agentConfig) (*http.Client, error) {
	pool, err := testACMECAPool()
	if err != nil {
		return nil, fmt.Errorf("reading HOGMAN_ACME_CA_ROOT: %w", err)
	}
	pu, err := url.Parse(cfg.proxyURL())
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}}}, nil
}

// leaveAlongside undoes side-by-side mode for a pen. Reports whether there was
// anything to undo. deviceGone: the pen already removed this device, so logging
// it out (a fresh connection that can only time out) is skipped.
func leaveAlongside(zone string, deviceGone bool) bool {
	dir := stateDir(zone)
	cfg, err := loadAgentConfig(dir)
	if err != nil {
		return false
	}
	stopAgent(dir, cfg)
	if !deviceGone {
		if self, err := os.Executable(); err == nil {
			_, _ = run(self, "__agent-logout", dir)
		}
	}
	_ = os.RemoveAll(dir)
	remaining := loadInstalledPenConfigs(hogmanConfigBase())
	if len(remaining) == 0 {
		removeNativeHost(hogmanConfigBase())
	}
	if msg := clearSystemProxy(cfg, remaining); msg != "" {
		note("%s", msg)
	}
	note("stopped the pen connection and removed its settings")
	return true
}

func findLegacySameServerPens(configBase, newZone, loginServer string) []penTarget {
	if loginServer == "" {
		return nil
	}
	var out []penTarget
	for _, p := range loadPenTargets(configBase) {
		if p.zone != newZone && p.cfg.LoginServer == loginServer {
			out = append(out, p)
		}
	}
	return out
}

type legacyRetireOps struct {
	stop   func(dir string, c *agentConfig)
	logout func(dir string)
}

func defaultLegacyRetireOps() legacyRetireOps {
	return legacyRetireOps{
		stop: stopAgent,
		logout: func(dir string) {
			if self, err := os.Executable(); err == nil && self != "" {
				_, _ = run(self, "__agent-logout", dir)
			}
		},
	}
}

func retireLegacySameServerPens(oldPens []penTarget, ops legacyRetireOps) {
	if len(oldPens) == 0 {
		return
	}
	for _, old := range oldPens {
		step("Retiring old %s pen setup", old.zone)
		if ops.stop != nil {
			ops.stop(old.dir, old.cfg)
		}
		if ops.logout != nil {
			ops.logout(old.dir)
		}
		if err := os.RemoveAll(old.dir); err != nil {
			note("could not remove old settings folder %s: %v", old.dir, err)
		}
	}
}

func hasLegacyPenBinary(dir string) bool {
	p := filepath.Join(dir, legacyBinaryName(runtime.GOOS))
	_, err := os.Stat(p)
	return err == nil
}

// currentAgentHealthy reports whether the pen's agent is already up, passes
// HMAC status verification, and is NOT accompanied by a legacy per-pen
// hogman-join copy that still needs replacing.
func currentAgentHealthy(dir string, c *agentConfig) bool {
	if c == nil || hasLegacyPenBinary(dir) {
		return false
	}
	st, err := agentStateInDir(dir, c)
	return err == nil && st.Up
}

func cleanupLegacyPenBinary(dir string) {
	p := filepath.Join(dir, legacyBinaryName(runtime.GOOS))
	self, _ := resolvedExePath()
	canon := canonicalBinaryPath(hogmanConfigBase())
	if sameFilePath(p, self) || sameFilePath(p, canon) {
		return
	}
	if _, err := os.Stat(p); err == nil {
		_ = os.Remove(p)
	}
}

// stopDetached stops an agent that was started as a plain background process,
// waiting until the process has actually exited so its proxy port is released,
// and also stops any orphaned legacy hogman-join agent still bound to dir.
func stopDetached(dir string) {
	pidPath := filepath.Join(dir, "agent.pid")
	if b, err := os.ReadFile(pidPath); err == nil {
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || pid <= 0 {
			_ = os.Remove(pidPath)
		} else {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Signal(syscall.SIGTERM)
				for i := 0; i < 20; i++ {
					if !processAlive(pid) {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				if processAlive(pid) {
					_ = p.Kill()
					for i := 0; i < 10; i++ {
						if !processAlive(pid) {
							break
						}
						time.Sleep(100 * time.Millisecond)
					}
				}
			}
			_ = os.Remove(pidPath)
		}
	}
	stopOrphanAgentForDir(dir)
}

// canonicalBinaryPath is the single managed hogman binary shared by all
// pen agents and background shares on this computer.
func canonicalBinaryPath(configBase string) string {
	return filepath.Join(configBase, "bin", installedBinaryName(runtime.GOOS))
}

// ensureCanonicalBinary ensures the single canonical managed binary under
// <configBase>/bin/hogman is up to date atomically, while refusing to let an
// older CLI binary silently downgrade a newer canonical binary shared by other
// pens on this computer.
func ensureCanonicalBinary(configBase string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	dst := canonicalBinaryPath(configBase)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	if sameFilePath(self, dst) {
		return dst, nil
	}
	// Never let an older CLI binary (e.g. a forgotten ~/hogman-join or old ~/hogman)
	// silently downgrade a newer canonical binary shared by other pens on this machine.
	if _, err := os.Stat(dst); err == nil {
		if existingVer := queryBinaryVersion(dst); existingVer != "" {
			if cmp, ok := compareReleaseVersions(existingVer, version); ok && cmp > 0 {
				note("keeping newer shared binary %s (%s > %s); run 'hogman update' to update %s", dst, existingVer, version, self)
				return dst, nil
			}
		}
	}
	if err := copyExecutableAtomic(self, dst); err != nil {
		return "", err
	}
	return dst, nil
}

// installedBinary ensures the single canonical managed binary under
// <configBase>/bin/hogman is up to date atomically, so all pen agents and
// background shares share one copy instead of duplicating a binary per pen/share.
func installedBinary(_ string) (string, error) {
	return ensureCanonicalBinary(hogmanConfigBase())
}
