package share

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"tailscale.com/tsnet"

	"hogman/join/internal/agent"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/mesh"
	"hogman/join/internal/penapi"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
)

// permanentError marks failures where automatic restarts cannot help (such as
// a refused share name, removed device, or invalid config).
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

func IsPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

func ExitCode(err error) int {
	if err == nil || IsPermanent(err) {
		return 0
	}
	return 1
}

func IsPermanentNameStatus(code int) bool {
	return code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests
}

func IsPermanentNodeError(hasAuthKey bool, backendState string, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, mesh.ErrDeviceRemoved) {
		return true
	}
	if !hasAuthKey && backendState == "NeedsLogin" {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{"invalid authkey", "authkey expired", "auth key", "not authorized", "unauthorized", "node not found", "needslogin"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// OpenNode brings a share's own device onto the pen and returns it with a
// client for reaching the pen through it.
func OpenNode(ctx context.Context, dir string, c *state.ShareConfig) (*tsnet.Server, *agent.Agent, *http.Client, error) {
	ac := c.AgentConfig()
	ac.TrustControlCA()
	key, _ := os.ReadFile(filepath.Join(dir, "authkey"))
	authKey := strings.TrimSpace(string(key))
	node := mesh.NewNode(dir, ac, authKey)
	upCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	st, err := mesh.UpNode(upCtx, node, authKey != "")
	if err != nil {
		var backendState string
		if lc, lerr := node.LocalClient(); lerr == nil {
			sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
			if status, serr := lc.StatusWithoutPeers(sctx); serr == nil && status != nil {
				backendState = status.BackendState
			}
			scancel()
		}
		node.Close()
		out := link.Errorf("the share could not join the pen: %v", err)
		if IsPermanentNodeError(authKey != "", backendState, err) {
			return nil, nil, nil, Permanent(out)
		}
		return nil, nil, nil, out
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
		return nil, nil, nil, Permanent(link.Errorf("that link adds a personal device, which can't be visited. Use a share link (Get a share link on your home page)"))
	}
	a := agent.New(ac, node)
	pool, err := penapi.TestACMECAPool()
	if err != nil {
		node.Close()
		return nil, nil, nil, Permanent(err)
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext:     func(ctx context.Context, _, addr string) (net.Conn, error) { return a.Dial(ctx, addr) },
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	return node, a, hc, nil
}

// UntilOK retries fn while the pen is still catching up with a new device
// (its access rules follow a few seconds behind).
func UntilOK(ctx context.Context, d time.Duration, fn func() (retry bool, err error)) error {
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

// ClaimName registers c's name on the pen (allocating a random private label
// via POST /api/names {"private": true} when c.PrivateName && c.Name == "").
func ClaimName(ctx context.Context, hc *http.Client, c *state.ShareConfig, dir string) (int, error) {
	var lastCode int
	err := UntilOK(ctx, 90*time.Second, func() (bool, error) {
		if c.PrivateName && c.Name == "" {
			var resp struct {
				Name string `json:"name"`
			}
			body := map[string]any{"private": true, "note": c.Note}
			code, err := penapi.HomeAPI(hc, c.Zone, "POST", "/names", body, &resp)
			lastCode = code
			if err != nil {
				return code == 0 || strings.Contains(err.Error(), "not enrolled"), err
			}
			label := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(resp.Name)), "."+c.Zone)
			if !NameRE.MatchString(label) || IsReservedName(label) {
				return false, fmt.Errorf("pen returned invalid private name %q", resp.Name)
			}
			c.Name = label
			if saveErr := c.Save(dir); saveErr != nil {
				return false, saveErr
			}
			return false, nil
		}
		code, err := penapi.HomeAPI(hc, c.Zone, "POST", "/names", map[string]string{"name": c.Name, "note": c.Note}, nil)
		lastCode = code
		if err == nil {
			return false, nil
		}
		// Not through the pen's rules yet, or not recorded yet: wait.
		return code == 0 || strings.Contains(err.Error(), "not enrolled"), err
	})
	return lastCode, err
}

// ClaimPrivateNameBootstrap enrolls a new --private-name server in a staging
// directory, claims its random label, saves share.json, and closes tsnet cleanly
// so the caller can move the directory to ShareDir(zone, label) without renaming
// open state files.
func ClaimPrivateNameBootstrap(ctx context.Context, stagingDir string, c *state.ShareConfig) error {
	node, _, hc, err := OpenNode(ctx, stagingDir, c)
	if err != nil {
		return err
	}
	lastCode, err := ClaimName(ctx, hc, c, stagingDir)
	if err != nil {
		cleanCtx, cleanCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		if derr := GiveBackDeviceWith(cleanCtx, hc, c, 0, mesh.TsnetNeedsLogin(node)); derr != nil {
			fsutil.DaemonLogger().Warn("share bootstrap cleanup failed", "err", derr)
		}
		cleanCancel()
		_ = node.Close()
		out := link.Errorf("could not claim a private name on %s: %v", c.Zone, err)
		if ctx.Err() == nil && IsPermanentNameStatus(lastCode) {
			return Permanent(out)
		}
		return out
	}
	_ = node.Close()
	return nil
}

// Serve runs a share until ctx ends. ready is called once its name and
// certificate are in place.
func Serve(ctx context.Context, dir string, u *ui.UI, ready func(*state.ShareConfig)) error {
	c, err := state.LoadShare(dir)
	if err != nil {
		state.WriteShareStatus(dir, "error", err.Error())
		return Permanent(err)
	}
	unlock, err := fsutil.AcquireShareLock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	// Foreground or background, the pid file says a share is running, so list,
	// stop and a second start all see it. Refuse to clobber a live process whose
	// status indicates it is actively starting or up (ignoring stale PIDs from
	// a prior crash whose PID number may have been recycled by the OS).
	if existing := PID(dir); existing != 0 && existing != os.Getpid() {
		if st := state.ReadShareStatus(dir); st.State == "up" || st.State == "starting" {
			return link.Errorf("%s is already running (process %d)", c.URL(), existing)
		}
	}
	pidFile := filepath.Join(dir, "share.pid")
	_ = fsutil.WritePIDFile(pidFile)
	defer fsutil.RemovePIDFile(pidFile)
	state.WriteShareStatus(dir, "starting", "")
	fail := func(err error) error { state.WriteShareStatus(dir, "error", err.Error()); return err }

	certStateDir := filepath.Join(dir, "acme")
	_, statErr := os.Stat(certStateDir)
	fresh := os.IsNotExist(statErr) // never got as far as a certificate
	node, _, hc, err := OpenNode(ctx, dir, c)
	if err != nil {
		return fail(err)
	}
	defer node.Close()

	// Name ourselves (allocating a private random label if needed).
	hadName := c.Name != ""
	lastCode, err := ClaimName(ctx, hc, c, dir)
	if err != nil {
		if fresh {
			// A brand-new share that can't have its name: take its device back
			// out, so nothing is left behind on the pen or here.
			cleanCtx, cleanCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			if derr := GiveBackDeviceWith(cleanCtx, hc, c, 0, mesh.TsnetNeedsLogin(node)); derr != nil {
				fsutil.DaemonLogger().Warn("share cleanup failed", "fqdn", c.FQDN(), "err", derr)
			}
			cleanCancel()
			node.Close()
			_ = os.RemoveAll(filepath.Join(dir, "node"))
			_ = os.Remove(filepath.Join(dir, "share.json"))
		}
		targetName := c.FQDN()
		if !hadName && c.Name == "" {
			targetName = "a private name on " + c.Zone
		}
		out := link.Errorf("could not claim %s: %v", targetName, err)
		if ctx.Err() == nil && IsPermanentNameStatus(lastCode) {
			return fail(Permanent(out))
		}
		return fail(out)
	}
	if !hadName && c.PrivateName {
		u.Say("%s", FormatPrivateNameNotice(c.FQDN()))
	}

	h, closeH, err := NewHandlerWithResolver(c, TsnetPeerResolver(node))
	if err != nil {
		if fresh {
			UndoFresh(hc, node, dir, c)
		}
		return fail(err)
	}
	defer closeH()
	ln443, err := node.Listen("tcp", ":443")
	if err != nil {
		if fresh {
			UndoFresh(hc, node, dir, c)
		}
		return fail(err)
	}
	quiet := slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)

	cm, err := NewCertManager(ACMEConfigFromEnv(c.Zone, c.FQDN(), certStateDir, hc))
	if err != nil {
		_ = ln443.Close()
		if fresh {
			UndoFresh(hc, node, dir, c)
		}
		return fail(err)
	}
	defer cm.Close()
	if err := cm.EnsureWithBackoff(ctx); err != nil {
		_ = ln443.Close()
		permanent := IsNonRetryableCertErr(err) && ctx.Err() == nil
		out := link.Errorf("no certificate for %s: %v", c.FQDN(), err)
		if fresh {
			cm.Close()
			clean := UndoFresh(hc, node, dir, c)
			out = FormatFreshCertError(c.FQDN(), c.Name, c.Zone, err, clean)
			return fail(Permanent(out))
		}
		if permanent {
			return fail(Permanent(out))
		}
		return fail(out)
	}
	go cm.RunFailoverLoop(ctx)
	tlsSrv := &http.Server{
		Handler:           h,
		TLSConfig:         cm.TLSConfig(),
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          quiet,
	}
	go func() { _ = tlsSrv.ServeTLS(ln443, "", "") }()
	defer tlsSrv.Close()
	state.WriteShareStatus(dir, "up", "")
	if ready != nil {
		ready(c)
	}
	<-ctx.Done()
	state.WriteShareStatus(dir, "stopped", "")
	return nil
}

// RunProcess is the background process entrypoint (`__share-run DIR`).
func RunProcess(dir string, u *ui.UI) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Serve(ctx, dir, u, func(c *state.ShareConfig) {
		fsutil.DaemonLogger().Info("share online", "url", c.URL(), "target", c.Showing())
	})
}

func retryAfterHint(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	mins := int((d + time.Minute - 1) / time.Minute)
	if mins < 1 {
		mins = 1
	}
	if mins <= 120 {
		if mins == 1 {
			return "try again in about 1 minute"
		}
		return fmt.Sprintf("try again in about %d minutes", mins)
	}
	hours := int((d + time.Hour - 1) / time.Hour)
	if hours < 48 {
		return fmt.Sprintf("try again in about %d hours", hours)
	}
	days := int((d + 24*time.Hour - 1) / (24 * time.Hour))
	return fmt.Sprintf("try again in about %d days", days)
}

func FormatFreshCertError(fqdn, name, zone string, err error, cleanRollback bool) error {
	var me *penapi.HomeAPIError
	rollbackNote := fmt.Sprintf("Nothing was left behind: the name %s is free again.", name)
	if !cleanRollback {
		rollbackNote = fmt.Sprintf("Cleanup could not be fully confirmed; check Sites and Devices on home.%s before sharing again.", zone)
	}
	if errors.As(err, &me) && me.Status == http.StatusTooManyRequests {
		if hint := retryAfterHint(me.RetryAfter); hint != "" {
			return link.Errorf("no certificate for %s: %s (%s)\n  %s Wait and share again\n  (if you used a one-time server link, get a fresh one).", fqdn, me.Msg, hint, rollbackNote)
		}
		return link.Errorf("no certificate for %s: %s\n  %s Wait and share again\n  (if you used a one-time server link, get a fresh one).", fqdn, me.Msg, rollbackNote)
	}
	return link.Errorf("no certificate for %s: %v\n  %s Fix the problem above,\n  then share again with a fresh share link (this one is used up).", fqdn, err, rollbackNote)
}

func GiveBackWith(ctx context.Context, hc *http.Client, c *state.ShareConfig, checkNeedsLogin func(context.Context) bool, u *ui.UI) error {
	var me penapi.MeView
	err := UntilOK(ctx, 60*time.Second, func() (bool, error) {
		code, err := penapi.HomeAPICtx(ctx, hc, c.Zone, "GET", "/me", nil, &me)
		return code == 0, err
	})
	if err != nil {
		return link.Errorf("could not reach home.%s from the share: %v", c.Zone, err)
	}
	if code, err := penapi.HomeAPICtx(ctx, hc, c.Zone, "DELETE", "/names/"+url.PathEscape(c.Name), nil, nil); err != nil && code != 404 {
		return link.Errorf("could not give back %s: %v", c.FQDN(), err)
	}
	u.Note("gave back the name %s", c.FQDN())
	if err := GiveBackDeviceWith(ctx, hc, c, me.ThisDevice.ID, checkNeedsLogin); err != nil {
		return err
	}
	u.Note("removed its server from your devices")
	return nil
}

// UndoFresh gives a brand-new share's name back and takes its server out of the
// pen, then forgets it here. Reports whether both server-side cleanup steps were
// confirmed so callers do not claim "nothing was left behind" on partial failure.
func UndoFresh(hc *http.Client, node io.Closer, dir string, c *state.ShareConfig) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var checkNL func(context.Context) bool
	if ts, ok := node.(*tsnet.Server); ok {
		checkNL = mesh.TsnetNeedsLogin(ts)
	}
	logger := fsutil.DaemonLogger()
	nameOK := true
	if code, err := penapi.HomeAPICtx(ctx, hc, c.Zone, "DELETE", "/names/"+url.PathEscape(c.Name), nil, nil); err != nil && code != 404 {
		nameOK = false
		logger.Warn("could not release share name", "fqdn", c.FQDN(), "err", err)
	}
	devOK := true
	if err := GiveBackDeviceWith(ctx, hc, c, 0, checkNL); err != nil {
		devOK = false
		logger.Warn("could not remove share device", "fqdn", c.FQDN(), "err", err)
	}
	_ = node.Close()
	for _, f := range []string{"node", "acme", "share.json", "authkey"} {
		_ = os.RemoveAll(filepath.Join(dir, f))
	}
	return nameOK && devOK
}

// GiveBackDevice removes the share's own device from the pen.
func GiveBackDevice(ctx context.Context, hc *http.Client, c *state.ShareConfig) error {
	return GiveBackDeviceWith(ctx, hc, c, 0, nil)
}

func GiveBackDeviceWith(ctx context.Context, hc *http.Client, c *state.ShareConfig, deviceID int64, checkNeedsLogin func(context.Context) bool) error {
	res := penapi.DeleteSelfDevice(ctx, hc, c.Zone, deviceID, checkNeedsLogin)
	switch res.Outcome {
	case penapi.SelfDeleteRemoved:
		return nil
	case penapi.SelfDeleteCanceled:
		return res.Err
	case penapi.SelfDeleteLookupFailed:
		return link.Errorf("could not reach home.%s from the share: %v", c.Zone, res.Err)
	case penapi.SelfDeleteMissingID:
		return link.Errorf("home.%s did not report this share's device ID", c.Zone)
	case penapi.SelfDeleteUnconfirmed:
		return link.Errorf("could not confirm removal of the share's server on %s; check Devices on home.%s", c.Zone, c.Zone)
	default:
		return link.Errorf("the pen would not remove the share's server: %v", res.Err)
	}
}
