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
	"hogman/join/internal/ui"
	"hogman/join/internal/updater"
)

func startAgent(dir string, c *state.AgentConfig, o options, u *ui.UI) error {
	if agent.CurrentHealthy(dir, c) {
		return nil
	}
	bin, err := updater.EnsureCanonicalBinary(state.ConfigBase(), version, u.Note)
	if err != nil {
		return err
	}
	return platform.StartAgentService(bin, dir, c, o.noService, u.Note)
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
func joinAlongside(l *link.Link, n *penapi.NetworkInfo, client *http.Client, o options, why string, u *ui.UI) error {
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
	u.Note("%s", why)
	u.Note("joining side by side: only names ending in .%s use the pen; nothing else on this computer changes", n.Zone)

	existing, _ := state.LoadAgentConfig(dir)
	reenroll := existing != nil && (l.InviteToken != "" || l.DeviceKey != "") && existingPenNeedsReenroll(dir, existing)
	var oldSameServer []updater.PenTarget
	if existing == nil {
		oldSameServer = updater.FindLegacySameServerPens(state.ConfigBase(), n.Zone, n.LoginServer)
	}
	if o.dryRun {
		u.Step("Dry run: nothing changed. Would:")
		if (existing == nil || reenroll) && l.InviteToken != "" {
			u.Note("redeem the invite (handle: %s)", orAsk(o.handle))
		}
		u.Note("verify %s using this computer's built-in trusted certificates", n.Zone)
		u.Note("run a small background agent as %q, with a local proxy for .%s (already set up: %v)", hostname, n.Zone, existing != nil && !reenroll)
		for _, old := range oldSameServer {
			u.Note("retire old %s pen setup (%s)", old.Zone, old.Dir)
		}
		return nil
	}

	acquireKey := func() (string, string, error) {
		if l.InviteToken != "" {
			u.Step("Redeeming the invite")
			en, err := redeemWithHandle(client, l, o, u)
			if err != nil {
				return "", "", err
			}
			u.Note("welcome, %s", en.Handle)
			return en.AuthKey, en.Handle, nil
		}
		return l.DeviceKey, "", nil
	}

	handle := ""
	cfg := existing
	freshJoin := existing == nil
	if cfg != nil && reenroll {
		u.Step("Previous %s setup needs a fresh login; re-enrolling with the new link", n.Zone)
		var err error
		cfg, handle, err = reenrollExistingPen(dir, existing, n, hostname, o, acquireKey, platform.StopAgent)
		if err != nil {
			return err
		}
		freshJoin = true
	} else if cfg != nil {
		u.Step("This computer is already set up for %s", n.Zone)
		if l.InviteToken != "" {
			u.Note("not using the invite; it stays valid for another device or person")
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

	u.Step("Starting the pen connection as %q", cfg.Hostname)
	if err := startAgent(dir, cfg, o, u); err != nil {
		return err
	}
	st, err := agent.WaitUpCtx(ctx, cfg, 90*time.Second)
	if err != nil {
		if shouldRollbackFreshJoin(freshJoin, dir, err) {
			leaveAlongside(n.Zone, false, u)
		}
		var aje *agent.JoinError
		if errors.As(err, &aje) {
			return errorf("%s", aje.Msg)
		}
		return err
	}
	cleanupLegacyPenBinary(dir)
	if st.Server {
		leaveAlongside(n.Zone, false, u)
		return errorf("that's a server link: it's for putting something in the pen, not for joining a computer.\n" +
			"  Use a new one with share, for example: hogman share blog 8080 '<server link>'")
	}
	u.Note("online as %s", strings.Join(st.IPs, ", "))

	u.Step("Checking %s loads securely", n.Portal)
	who, err := checkPortalViaCtx(ctx, n.Portal, cfg.ProxyURL())
	if err != nil {
		if ctx.Err() == nil && shouldRollbackFreshJoin(freshJoin, dir, err) {
			leaveAlongside(n.Zone, false, u)
		}
		return err
	}
	if handle == "" {
		handle = who
	}
	updater.RetireLegacySameServerPens(oldSameServer, updater.DefaultLegacyRetireOps(), u)

	pens := state.NormalizePenConfigs(state.LoadInstalledPenConfigs(state.ConfigBase()), cfg)
	ensureBin := func(base string) (string, error) {
		return updater.EnsureCanonicalBinary(base, version, u.Note)
	}
	if _, _, err := nativehost.Install(state.ConfigBase(), ensureBin, nil, nil, u.Note); err != nil {
		u.Note("could not register browser extension host: %v", err)
	}
	browsers := "set your browser's automatic proxy configuration to " + cfg.PACURL()
	proxyConfigured := false
	if !o.noSystemProxy {
		if msg, ok, err := platform.SetSystemProxy(cfg, pens, u.Note); err != nil {
			u.Note("could not point browsers at the pen automatically: %v", err)
		} else {
			proxyConfigured = ok
			if msg != "" {
				browsers = msg
			}
		}
	}
	u.Say("\n✓ You're in. You are %s on %s.", handle, n.Zone)
	u.Say("  Start at %s", n.Portal)
	u.Say("")
	u.Say("  Browsers: %s", browsers)
	if !o.noSystemProxy && !nativehost.ExtensionRecentlySeen(state.ConfigBase(), 7*24*time.Hour) {
		if sys := platform.DetectSystemProxyState(pens); sys.VPNOverride {
			u.Say("  ! VPN active (%s): macOS hides automatic proxy settings while a VPN is connected.", sys.VPNInterface)
			u.Say("    Install the Hogman browser extension (%s; Firefox: coming soon), then open its popup and turn on %s to browse pen sites with your VPN on (Safari requires pausing the VPN).", platform.ChromeExtensionStoreURL, n.Zone)
		}
	}
	for _, line := range joinSummaryCLILines(runtime.GOOS, cfg.ProxyURL(), n.Zone) {
		u.Say("%s", line)
	}
	if !o.noOpen {
		shouldOpen := runtime.GOOS != "darwin" || proxyConfigured || nativehost.ExtensionRecentlySeen(state.ConfigBase(), 7*24*time.Hour)
		if shouldOpen {
			platform.OpenURL(n.Portal)
		}
	}
	return nil
}

func joinSummaryCLILines(goos, proxyURL, zone string) []string {
	if goos == "windows" {
		return []string{
			fmt.Sprintf("  Other tools reach the pen through its proxy, %s", proxyURL),
			fmt.Sprintf("    curl:              curl.exe --proxy %s https://<site>.%s", proxyURL, zone),
			fmt.Sprintf("    PowerShell CLIs:   $env:HTTPS_PROXY=%q", proxyURL),
			fmt.Sprintf("    git:               git config --global http.https://%s/.proxy %s   (per site)", "<site>."+zone, proxyURL),
			"  The pen carries HTTPS only.",
			`  To leave: ~\hogman.exe leave '<this link>'`,
		}
	}
	return []string{
		fmt.Sprintf("  Other tools reach the pen through its proxy, %s", proxyURL),
		fmt.Sprintf("    curl / most CLIs:  https_proxy=%s curl https://<site>.%s", proxyURL, zone),
		fmt.Sprintf("    git:               git config --global http.https://%s/.proxy %s   (per site)", "<site>."+zone, proxyURL),
		"  The pen carries HTTPS only.",
		"  To leave: hogman leave '<this link>'",
	}
}

const maxPortalMeResponseBytes = 1 << 20

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
				data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxPortalMeResponseBytes+1))
				resp.Body.Close()
				switch {
				case readErr != nil:
					err = readErr
				case len(data) > maxPortalMeResponseBytes:
					err = fmt.Errorf("HTTP %d: portal response exceeded %d bytes", resp.StatusCode, maxPortalMeResponseBytes)
				case resp.StatusCode == 200 && json.Unmarshal(data, &me) == nil:
					return me.Member.Handle, nil
				default:
					err = errors.New(penapi.FormatHTTPResponseError(resp.StatusCode, resp.Header.Get("Content-Type"), data))
				}
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
// device. Best effort: leaving still works if the pen can't be reached.
func removeOwnDevice(zone string, u *ui.UI) bool {
	dir := state.StateDir(zone)
	cfg, err := state.LoadAgentConfig(dir)
	if err != nil {
		return false
	}
	if st, detail := agent.VerifyEndpointDetail(dir, cfg); st == agent.EndpointDown && detail.Verified && detail.NeedsLogin {
		u.Note("this computer was already removed from the pen")
		return true
	}
	c, err := penapi.PenClient(cfg)
	if err != nil {
		u.Note("could not reach the pen while leaving: %v", err)
		return false
	}
	checkNeedsLogin := func(_ context.Context) bool {
		st, detail := agent.VerifyEndpointDetail(dir, cfg)
		return st == agent.EndpointDown && detail.Verified && detail.NeedsLogin
	}
	return removeOwnDeviceWith(context.Background(), c, zone, checkNeedsLogin, u)
}

func removeOwnDeviceWith(ctx context.Context, c *http.Client, zone string, checkNeedsLogin func(context.Context) bool, u *ui.UI) bool {
	res := penapi.DeleteSelfDevice(ctx, c, zone, 0, checkNeedsLogin)
	switch res.Outcome {
	case penapi.SelfDeleteRemoved:
		u.Note("removed this computer from your devices")
		return true
	case penapi.SelfDeleteLookupFailed, penapi.SelfDeleteMissingID:
		u.Note("could not remove this computer from your devices (the keeper can, on the home page)")
		return false
	case penapi.SelfDeleteUnconfirmed:
		u.Note("could not confirm removal from your devices; check Devices on home.%s", zone)
		return false
	default:
		if res.Err != nil {
			u.Note("could not remove this computer from your devices: %v", link.SingleLine(res.Err.Error()))
		}
		return false
	}
}

// leaveAlongside undoes side-by-side mode for a pen. Reports whether there was
// anything to undo.
func leaveAlongside(zone string, deviceGone bool, u *ui.UI) bool {
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
		u.Note("%s", msg)
	}
	u.Note("stopped the pen connection and removed its settings")
	return true
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
