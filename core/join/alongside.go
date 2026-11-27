package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"hogman/join/internal/agent"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/nativehost"
	"hogman/join/internal/penapi"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
)

func startAgent(dir string, c *state.AgentConfig, o options) error {
	if agent.CurrentHealthy(dir, c) {
		return nil
	}
	bin, err := installedBinary(dir)
	if err != nil {
		return err
	}
	return platform.StartAgentService(bin, dir, c, o.noService, note)
}

// existingPenNeedsReenroll reports whether an already-configured pen's running
// agent explicitly proves (via verified status.token HMAC) that the control
// plane rejected this device (NeedsLogin). Unspent authkeys from an interrupted
// join are NOT treated as stale so we retry them without burning a fresh invite.
func existingPenNeedsReenroll(dir string, cfg *state.AgentConfig) bool {
	if cfg == nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "authkey")); err == nil {
		return false
	}
	if st, detail := agent.VerifyEndpointDetail(dir, cfg); st == agent.EndpointDown && detail.Verified && detail.NeedsLogin {
		return true
	}
	return false
}

// reenrollExistingPen acquires the new authkey BEFORE touching existing local
// state (so a failed invite redeem never destroys the saved pen setup), then
// stops the old agent and swaps in the fresh credentials.
func reenrollExistingPen(dir string, existing *state.AgentConfig, n *penapi.NetworkInfo, hostname string, o options, acquireKey func() (key, handle string, err error), stopFn func(string, *state.AgentConfig)) (*state.AgentConfig, string, error) {
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
		addr, err = agent.PickLocalAddr(n.Zone)
		if err != nil {
			return nil, "", err
		}
	}
	cfg := &state.AgentConfig{
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
	if err := cfg.Save(dir); err != nil {
		return nil, "", err
	}
	if _, err := state.WriteStatusToken(dir); err != nil {
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
	var aje *agent.JoinError
	return errors.As(err, &aje)
}

// joinAlongside sets up side-by-side mode. why explains, in a few words, why
// this mode was chosen.
func joinAlongside(l *link.Link, n *penapi.NetworkInfo, client *http.Client, o options, why string) error {
	if n.DNSServer == "" {
		return errorf("this pen's server is too old for side-by-side mode (it does not publish its DNS address)")
	}
	dir := state.StateDir(n.Zone)
	var hostname string
	if strings.TrimSpace(o.hostname) != "" {
		var err error
		hostname, err = link.SanitizeHostname(o.hostname)
		if err != nil {
			return err
		}
		if hostname == "" {
			return errorf("--hostname %q contains no letters or digits", o.hostname)
		}
	} else {
		var err error
		hostname, err = link.DefaultHostname()
		if err != nil {
			return err
		}
	}
	note("%s", why)
	note("joining side by side: only names ending in .%s use the pen; nothing else on this computer changes", n.Zone)

	existing, _ := state.LoadAgentConfig(dir)
	reenroll := existing != nil && (l.InviteToken != "" || l.DeviceKey != "") && existingPenNeedsReenroll(dir, existing)
	var oldSameServer []penTarget
	if existing == nil {
		oldSameServer = findLegacySameServerPens(state.ConfigBase(), n.Zone, n.LoginServer)
	}
	if o.dryRun {
		step("Dry run: nothing changed. Would:")
		if (existing == nil || reenroll) && l.InviteToken != "" {
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
		if l.InviteToken != "" {
			step("Redeeming the invite")
			en, err := redeemWithHandle(client, l, o)
			if err != nil {
				return "", "", err
			}
			note("welcome, %s", en.Handle)
			return en.AuthKey, en.Handle, nil
		}
		return l.DeviceKey, "", nil
	}

	handle := ""
	cfg := existing
	freshJoin := existing == nil
	if cfg != nil && reenroll {
		step("Previous %s setup needs a fresh login; re-enrolling with the new link", n.Zone)
		var err error
		cfg, handle, err = reenrollExistingPen(dir, existing, n, hostname, o, acquireKey, platform.StopAgent)
		if err != nil {
			return err
		}
		freshJoin = true
	} else if cfg != nil {
		step("This computer is already set up for %s", n.Zone)
		if l.InviteToken != "" {
			note("not using the invite; it stays valid for another device or person")
		}
		if cfg.LoginServer != n.LoginServer {
			cfg.LoginServer = n.LoginServer
			if err := cfg.Save(dir); err != nil {
				return err
			}
		}
	} else {
		key, h, err := acquireKey()
		if err != nil {
			return err
		}
		handle = h
		addr, err := agent.PickLocalAddr(n.Zone)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		cfg = &state.AgentConfig{Zone: n.Zone, LoginServer: n.LoginServer, DNSServer: n.DNSServer, Hostname: hostname, ProxyAddr: addr}
		if o.controlCA != "" {
			pemBytes, err := os.ReadFile(o.controlCA)
			if err != nil {
				return errorf("--control-ca: %v", err)
			}
			cfg.ControlCA = string(pemBytes)
		}
		if err := cfg.Save(dir); err != nil {
			return err
		}
		if _, err := state.WriteStatusToken(dir); err != nil {
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
	st, err := agent.WaitUpCtx(ctx, cfg, 90*time.Second)
	if err != nil {
		if shouldRollbackFreshJoin(freshJoin, dir, err) {
			leaveAlongside(n.Zone, false)
		}
		var aje *agent.JoinError
		if errors.As(err, &aje) {
			return errorf("%s", aje.Msg)
		}
		return err
	}
	cleanupLegacyPenBinary(dir)
	if st.Server {
		leaveAlongside(n.Zone, false)
		return errorf("that's a server link: it's for putting something in the pen, not for joining a computer.\n" +
			"  Use a new one with share, for example: hogman share blog 8080 '<server link>'")
	}
	note("online as %s", strings.Join(st.IPs, ", "))

	step("Checking %s loads securely", n.Portal)
	who, err := checkPortalViaCtx(ctx, n.Portal, cfg.ProxyURL())
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

	pens := state.NormalizePenConfigs(state.LoadInstalledPenConfigs(state.ConfigBase()), cfg)
	if _, _, err := nativehost.Install(state.ConfigBase(), ensureCanonicalBinary, nil, nil, note); err != nil {
		note("could not register browser extension host: %v", err)
	}
	browsers := "set your browser's automatic proxy configuration to " + cfg.PACURL()
	proxyConfigured := false
	if !o.noSystemProxy {
		if msg, ok, err := platform.SetSystemProxy(cfg, pens, note); err != nil {
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
	if !o.noSystemProxy && !nativehost.ExtensionRecentlySeen(state.ConfigBase(), 7*24*time.Hour) {
		if sys := platform.DetectSystemProxyState(pens); sys.VPNOverride {
			say("  ! VPN active (%s): macOS hides automatic proxy settings while a VPN is connected.", sys.VPNInterface)
			say("    Install the Hogman browser extension (%s; Firefox: coming soon), then open its popup and turn on %s to browse pen sites with your VPN on (Safari requires pausing the VPN).", platform.ChromeExtensionStoreURL, n.Zone)
		}
	}
	say("  Other tools reach the pen through its proxy, %s", cfg.ProxyURL())
	say("    curl / most CLIs:  https_proxy=%s curl https://<site>.%s", cfg.ProxyURL(), n.Zone)
	say("    git:               git config --global http.https://%s/.proxy %s   (per site)", "<site>."+n.Zone, cfg.ProxyURL())
	say("  The pen carries HTTPS only.")
	say("  To leave: hogman leave '<this link>'")
	if !o.noOpen {
		shouldOpen := runtime.GOOS != "darwin" || proxyConfigured || nativehost.ExtensionRecentlySeen(state.ConfigBase(), 7*24*time.Hour)
		if shouldOpen {
			platform.OpenURL(n.Portal)
		}
	}
	return nil
}

func checkPortalViaCtx(ctx context.Context, portal, proxy string) (string, error) {
	pool, err := penapi.TestACMECAPool()
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
	dir := state.StateDir(zone)
	cfg, err := state.LoadAgentConfig(dir)
	if err != nil {
		return false
	}
	// Only skip device removal / logout when the running agent passes HMAC
	// status.token verification AND the control plane explicitly reports NeedsLogin.
	if st, detail := agent.VerifyEndpointDetail(dir, cfg); st == agent.EndpointDown && detail.Verified && detail.NeedsLogin {
		note("this computer was already removed from the pen")
		return true
	}
	c, err := penapi.PenClient(cfg)
	if err != nil {
		note("could not reach the pen while leaving: %v", err)
		return false
	}
	checkNeedsLogin := func(_ context.Context) bool {
		st, detail := agent.VerifyEndpointDetail(dir, cfg)
		return st == agent.EndpointDown && detail.Verified && detail.NeedsLogin
	}
	return removeOwnDeviceWith(context.Background(), c, zone, checkNeedsLogin)
}

func removeOwnDeviceWith(ctx context.Context, c *http.Client, zone string, checkNeedsLogin func(context.Context) bool) bool {
	res := penapi.DeleteSelfDevice(ctx, c, zone, 0, checkNeedsLogin)
	switch res.Outcome {
	case penapi.SelfDeleteRemoved:
		note("removed this computer from your devices")
		return true
	case penapi.SelfDeleteLookupFailed, penapi.SelfDeleteMissingID:
		note("could not remove this computer from your devices (the keeper can, on the home page)")
		return false
	case penapi.SelfDeleteUnconfirmed:
		note("could not confirm removal from your devices; check Devices on home.%s", zone)
		return false
	default:
		if res.Err != nil {
			note("could not remove this computer from your devices: %v", link.SingleLine(res.Err.Error()))
		}
		return false
	}
}

// leaveAlongside undoes side-by-side mode for a pen. Reports whether there was
// anything to undo. deviceGone: the pen already removed this device, so logging
// it out (a fresh connection that can only time out) is skipped.
func leaveAlongside(zone string, deviceGone bool) bool {
	dir := state.StateDir(zone)
	cfg, err := state.LoadAgentConfig(dir)
	if err != nil {
		return false
	}
	platform.StopAgent(dir, cfg)
	if !deviceGone {
		if self, err := os.Executable(); err == nil {
			_, _ = platform.Run(self, "__agent-logout", dir)
		}
	}
	_ = os.RemoveAll(dir)
	remaining := state.LoadInstalledPenConfigs(state.ConfigBase())
	if len(remaining) == 0 {
		nativehost.Remove(state.ConfigBase())
	}
	if msg := platform.ClearSystemProxy(cfg, remaining); msg != "" {
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
	stop   func(dir string, c *state.AgentConfig)
	logout func(dir string)
}

func defaultLegacyRetireOps() legacyRetireOps {
	return legacyRetireOps{
		stop: platform.StopAgent,
		logout: func(dir string) {
			if self, err := os.Executable(); err == nil && self != "" {
				_, _ = platform.Run(self, "__agent-logout", dir)
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

func cleanupLegacyPenBinary(dir string) {
	p := filepath.Join(dir, state.LegacyBinaryName(runtime.GOOS))
	self, _ := fsutil.ResolvedExePath()
	canon := state.CanonicalBinaryPath(state.ConfigBase())
	if fsutil.SameFilePath(p, self) || fsutil.SameFilePath(p, canon) {
		return
	}
	if _, err := os.Stat(p); err == nil {
		_ = os.Remove(p)
	}
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
	dst := state.CanonicalBinaryPath(configBase)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	if fsutil.SameFilePath(self, dst) {
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
	if err := fsutil.CopyExecutableAtomic(self, dst); err != nil {
		return "", err
	}
	return dst, nil
}

// installedBinary ensures the single canonical managed binary under
// <configBase>/bin/hogman is up to date atomically, so all pen agents and
// background shares share one copy instead of duplicating a binary per pen/share.
func installedBinary(_ string) (string, error) {
	return ensureCanonicalBinary(state.ConfigBase())
}
