package share

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"hogman/join/internal/link"
	"hogman/join/internal/mesh"
	"hogman/join/internal/penapi"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
)

// StartOptions configures `hogman share`.
type StartOptions struct {
	Pen             string
	ControlCA       string
	Note            string
	NoteSet         bool
	PrivateName     bool
	Background      bool
	Foreground      bool
	NoService       bool
	StateDir        string
	EnrollOnly      bool
	UpstreamHost    string
	IdentityHeaders bool
}

// EnsureBinaryFunc ensures the canonical hogman binary under configBase is up to date.
type EnsureBinaryFunc func(configBase string) (string, error)

func Start(name, what, rawLink string, o StartOptions, u *ui.UI, ensureBin EnsureBinaryFunc) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if o.PrivateName {
		if name != "" {
			return link.Errorf("cannot pass both a share name (%q) and --private-name", name)
		}
	} else {
		if !NameRE.MatchString(name) || name == "list" || name == "stop" {
			return link.Errorf("%q can't be a name: use lowercase letters, digits and dashes, like blog or my-notes", name)
		}
		if IsReservedName(name) {
			return link.Errorf("%q is reserved by the network and can't be used as a share name", name)
		}
	}
	target, folder, err := ParseTarget(what)
	if err != nil {
		return err
	}

	if o.Background && o.Foreground {
		return link.Errorf("cannot combine --background and --foreground")
	}
	if o.EnrollOnly && o.Background {
		return link.Errorf("--enroll-only cannot be combined with --background")
	}

	var cfg *state.ShareConfig
	key := ""
	explicitDir := strings.TrimSpace(o.StateDir)
	if explicitDir != "" {
		absDir, err := filepath.Abs(explicitDir)
		if err != nil {
			return err
		}
		explicitDir = absDir
	}

	if explicitDir != "" && rawLink == "" {
		if old, err := state.LoadShare(explicitDir); err == nil {
			if o.PrivateName {
				if !old.PrivateName {
					return link.Errorf("state directory %s is enrolled for share %q (not --private-name)", explicitDir, old.Name)
				}
				if old.Name == "" {
					return link.Errorf("state directory %s has no assigned private name yet; re-enroll with a share link", explicitDir)
				}
				cfgCopy := *old
				cfg = &cfgCopy
				name = old.Name
			} else {
				if old.Name != "" && old.Name != name {
					return link.Errorf("state directory %s is enrolled for share %q, not %q", explicitDir, old.Name, name)
				}
				cfgCopy := *old
				cfg = &cfgCopy
				cfg.Name = name
			}
		}
	}
	if cfg == nil {
		if rawLink != "" {
			cfg, key, err = fromLink(name, rawLink, o, u)
		} else if explicitDir != "" {
			if o.PrivateName {
				return link.Errorf("state directory %s is not enrolled yet. Enroll once with a share link:\n  hogman share --private-name %s --state-dir %s --enroll-only --link-stdin", explicitDir, what, explicitDir)
			}
			return link.Errorf("state directory %s is not enrolled yet. Enroll once with a share link:\n  hogman share %s %s --state-dir %s --enroll-only --link-stdin", explicitDir, name, what, explicitDir)
		} else {
			cfg, key, err = fromMembership(name, o, u)
		}
		if err != nil {
			return err
		}
	}
	if o.PrivateName {
		cfg.PrivateName = true
	}
	cfg.Target, cfg.Folder = target, folder
	cfg.IdentityHeaders = o.IdentityHeaders
	if cfg.IdentityHeaders {
		if err := ValidateIdentityTarget(cfg.Target, cfg.Folder); err != nil {
			return err
		}
	}
	if uh := strings.TrimSpace(o.UpstreamHost); uh != "" {
		if strings.ContainsAny(uh, " \t\r\n/\\@") || strings.Contains(uh, "://") {
			return link.Errorf("invalid --upstream-host %q (expected a bare hostname or host:port)", uh)
		}
		cfg.UpstreamHost = uh
	}

	var dir string
	var prev *state.ShareConfig
	fresh := true
	if o.PrivateName && explicitDir == "" && cfg.Name == "" {
		if key == "" {
			return link.Errorf("no way to add a device for this share")
		}
		randHex, err := state.GenerateHexToken(4)
		if err != nil {
			return err
		}
		cfg.BootstrapHostname = "site-" + randHex
		cfg.Note = ResolveNote(nil, o.Note, o.NoteSet)
		stagingDir := filepath.Join(state.SharesBase(), cfg.Zone, ".pending-"+randHex)
		if err := os.MkdirAll(stagingDir, 0o700); err != nil {
			return err
		}
		if err := cfg.Save(stagingDir); err != nil {
			_ = os.RemoveAll(stagingDir)
			return err
		}
		if err := os.WriteFile(filepath.Join(stagingDir, "authkey"), []byte(key), 0o600); err != nil {
			_ = os.RemoveAll(stagingDir)
			return err
		}
		if cfg.Note == "" {
			u.Say("%s", FormatPrivateNoteTip())
		}
		u.Step("Claiming a private hostname on %s", cfg.Zone)
		bctx, bstop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err = ClaimPrivateNameBootstrap(bctx, stagingDir, cfg)
		bstop()
		if err != nil {
			_ = os.RemoveAll(stagingDir)
			return err
		}
		dir = state.ShareDir(cfg.Zone, cfg.Name)
		if err := os.Rename(stagingDir, dir); err != nil {
			_ = os.RemoveAll(stagingDir)
			return link.Errorf("could not move private share state into %s: %v", dir, err)
		}
		u.Say("%s", FormatPrivateNameNotice(cfg.FQDN()))
	} else {
		dir = state.ShareDir(cfg.Zone, cfg.Name)
		if explicitDir != "" {
			dir = explicitDir
		}
		if old, err := state.LoadShare(dir); err == nil {
			if explicitDir == "" {
				if pid := PID(dir); pid != 0 && pid != os.Getpid() {
					return link.Errorf("%s is already being shared from this computer (process %d). Stop it first: hogman share stop %s", old.URL(), pid, cfg.Name)
				}
			}
			_, hasUnspentKey := os.Stat(filepath.Join(dir, "authkey"))
			st := state.ReadShareStatus(dir)
			staleDevice := hasUnspentKey == nil || (st.State == "error" && st.Error != "" && IsPermanentNodeError(false, "", errors.New(st.Error)))
			if rawLink != "" && key != "" && staleDevice {
				// Replacing a dead/aborted share with a fresh server link.
				_ = os.RemoveAll(filepath.Join(dir, "node"))
				_ = os.RemoveAll(filepath.Join(dir, "acme"))
				_ = os.RemoveAll(filepath.Join(dir, "authkey"))
				if cfg.ControlCA == "" {
					cfg.ControlCA = old.ControlCA
				}
				prev = old
			} else {
				key = "" // this share already has its device; reuse it
				cfg.ControlCA = old.ControlCA
				if cfg.UpstreamHost == "" {
					cfg.UpstreamHost = old.UpstreamHost
				}
				if old.PrivateName {
					cfg.PrivateName = true
				}
				if cfg.Name == "" {
					cfg.Name = old.Name
				}
				prev = old
				fresh = false
			}
		} else if key == "" {
			return link.Errorf("no way to add a device for this share")
		}
		if cfg.PrivateName && cfg.Name == "" && cfg.BootstrapHostname == "" {
			if randHex, rerr := state.GenerateHexToken(4); rerr == nil {
				cfg.BootstrapHostname = "site-" + randHex
			}
		}
		cfg.Note = ResolveNote(prev, o.Note, o.NoteSet)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := cfg.Save(dir); err != nil {
			return err
		}
		if key != "" {
			if err := os.WriteFile(filepath.Join(dir, "authkey"), []byte(key), 0o600); err != nil {
				return err
			}
		}
		if fresh {
			if cfg.PrivateName {
				if cfg.Note == "" {
					u.Say("%s", FormatPrivateNoteTip())
				}
			} else {
				u.Say("%s", FormatCertLogNotice(cfg.FQDN()))
			}
		}
	}

	if o.EnrollOnly {
		if cfg.Name != "" {
			u.Step("Enrolling %s into %s", cfg.URL(), dir)
		} else {
			u.Step("Enrolling a private-name share on %s into %s", cfg.Zone, dir)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancelReady := context.WithCancel(ctx)
		defer cancelReady()
		return Serve(ctx, dir, u, func(c *state.ShareConfig) {
			u.Say("\n✓ Enrolled %s in %s.", c.URL(), dir)
			cancelReady()
		})
	}
	if explicitDir != "" && o.Background {
		return link.Errorf("--background is not supported with --state-dir; run the container in the foreground")
	}
	if !o.Foreground && explicitDir == "" {
		err := runBackground(dir, cfg, o, u, ensureBin)
		if err != nil && fresh {
			// If UndoFresh already removed share.json, also clean up leftover
			// copied binary/log/status files so failed shares leave no orphan dirs.
			if _, statErr := os.Stat(filepath.Join(dir, "share.json")); os.IsNotExist(statErr) {
				_ = os.RemoveAll(dir)
			}
		}
		return err
	}
	if explicitDir == "" {
		platform.StopShareService(cfg)
	}
	if cfg.Name != "" {
		u.Step("Sharing %s as %s", cfg.Showing(), cfg.URL())
	} else {
		u.Step("Sharing %s under a private hostname on %s", cfg.Showing(), cfg.Zone)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Serve(ctx, dir, u, func(c *state.ShareConfig) {
		printReady(u, c, false, false)
		if c.PrivateName && explicitDir == "" {
			u.Say("  Stop: Ctrl-C. The name stays yours: run 'hogman share %s %s --foreground' to bring it back.", c.Name, what)
		} else {
			u.Say("  Stop: Ctrl-C. The name stays yours: run the same command to bring it back.")
		}
	})
}

func printReady(u *ui.UI, c *state.ShareConfig, background, managed bool) {
	u.Say("\n✓ %s is up.", c.URL())
	u.Say("  Everyone in the pen can open it.")
	u.Say("  It shows %s.", c.Showing())
	if background {
		if managed {
			u.Say("  It runs in the background and starts by itself when you log in.")
		} else {
			u.Say("  It runs in the background until this computer restarts.")
		}
	}
	if c.PrivateName {
		u.Say("  Take it down and retire the private name: hogman share stop %s", c.Name)
	} else {
		u.Say("  Take it down and give the name back: hogman share stop %s", c.Name)
	}
}

func fromLink(name, raw string, o StartOptions, u *ui.UI) (*state.ShareConfig, string, error) {
	l, err := link.Parse(raw)
	if err != nil {
		return nil, "", link.Errorf("%v", err)
	}
	if l.DeviceKey == "" {
		return nil, "", link.Errorf("that is an invite. Use a share link: on your pen's home page, press Get a share link")
	}
	client, err := penapi.ControlClient(o.ControlCA)
	if err != nil {
		return nil, "", err
	}
	u.Step("Checking the network at %s", l.Host)
	n, err := penapi.FetchNetwork(client, l.Host)
	if err != nil {
		return nil, "", err
	}
	if n.DNSServer == "" {
		return nil, "", link.Errorf("this pen's server is too old to share from here (it does not publish its DNS address)")
	}
	cfg := &state.ShareConfig{Name: name, Zone: n.Zone, LoginServer: n.LoginServer, DNSServer: n.DNSServer}
	if o.ControlCA != "" {
		b, err := os.ReadFile(o.ControlCA)
		if err != nil {
			return nil, "", link.Errorf("--control-ca: %v", err)
		}
		cfg.ControlCA = string(b)
	}
	return cfg, l.DeviceKey, nil
}

func fromMembership(name string, o StartOptions, u *ui.UI) (*state.ShareConfig, string, error) {
	p, err := ResolvePenConn(MyPens(), o.Pen, u)
	if err != nil {
		return nil, "", err
	}
	c, err := p.MemberClient()
	if err != nil {
		return nil, "", err
	}
	var me penapi.MeView
	if _, err := penapi.HomeAPI(c, p.Zone, "GET", "/me", nil, &me); err != nil {
		return nil, "", link.Errorf("could not reach home.%s as you: %v", p.Zone, err)
	}
	if me.Network == nil || me.Network.DNSServer == "" {
		return nil, "", link.Errorf("this pen's server is too old for sharing; ask its keeper to upgrade it")
	}
	loginHost := strings.TrimPrefix(p.LoginServer, "https://")
	if err := penapi.ValidateNetworkInfo(loginHost, me.Network); err != nil {
		return nil, "", err
	}
	if me.Network.Zone != p.Zone || me.Network.LoginServer != p.LoginServer {
		return nil, "", link.Errorf("refusing: %s returned mismatched network identity (%s at %s)", p.Zone, me.Network.Zone, me.Network.LoginServer)
	}
	cfg := &state.ShareConfig{Name: name, Zone: p.Zone, LoginServer: me.Network.LoginServer,
		DNSServer: me.Network.DNSServer, ControlCA: p.ControlCA}
	if name != "" {
		if old, err := state.LoadShare(state.ShareDir(p.Zone, name)); err == nil && old.Zone == p.Zone {
			return cfg, "", nil // already has its device
		}
	}
	if me.ThisDevice.Kind == "server" {
		return nil, "", link.Errorf("this computer is one of your servers, so it can't add devices.\n  Share from a personal device, or with a server link: hogman share NAME WHAT '<server link>'")
	}
	if name == "" {
		u.Step("Adding a server for a private-name share on %s to your devices (%s)", p.Zone, me.Member.Handle)
	} else {
		u.Step("Adding a server for %s.%s to your devices (%s)", name, p.Zone, me.Member.Handle)
	}
	var dk struct {
		AuthKey string `json:"auth_key"`
	}
	if _, err := penapi.HomeAPI(c, p.Zone, "POST", "/devices", map[string]string{"kind": "server"}, &dk); err != nil {
		return nil, "", link.Errorf("the pen would not add a server: %v", err)
	}
	return cfg, dk.AuthKey, nil
}

// StartBackground launches the share service (or detached process) using the canonical binary.
func StartBackground(dir string, c *state.ShareConfig, noService bool, u *ui.UI, ensureBin EnsureBinaryFunc) (bool, int, error) {
	bin, err := ensureBin(state.ConfigBase())
	if err != nil {
		return false, 0, err
	}
	if runtime.GOOS == "windows" {
		u.Note("on Windows shares do not yet restart by themselves; run this command again after a restart")
		return platform.StartShareServiceWithBinary(bin, dir, c, true, u.Note)
	}
	return platform.StartShareServiceWithBinary(bin, dir, c, noService, u.Note)
}

// PID is the live process serving a share in the background, or 0.
func PID(dir string) int {
	b, err := os.ReadFile(filepath.Join(dir, "share.pid"))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 || !platform.ProcessAlive(pid) {
		return 0
	}
	return pid
}

func runBackground(dir string, c *state.ShareConfig, o StartOptions, u *ui.UI, ensureBin EnsureBinaryFunc) error {
	_ = os.Remove(filepath.Join(dir, "status.json"))
	_ = os.Remove(filepath.Join(dir, "share.pid"))
	u.Step("Sharing %s as %s, in the background", c.Showing(), c.URL())
	managed, pid, err := StartBackground(dir, c, o.NoService, u, ensureBin)
	if err != nil {
		return err
	}
	return WaitBackground(dir, c, managed, pid, 4*time.Minute, u, func() {
		Stop(dir, c)
	})
}

func WaitBackground(dir string, c *state.ShareConfig, managed bool, pid int, timeout time.Duration, u *ui.UI, stopFn func()) error {
	logPath := filepath.Join(dir, "share.log")
	poll := time.Second
	if timeout < poll {
		poll = max(10*time.Millisecond, timeout/2)
	}
	ctx, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSig()
	start := time.Now()
	deadline := start.Add(timeout)
	warnedNoStatus := false
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			if stopFn != nil {
				stopFn()
			}
			return link.Errorf("cancelled while starting %s", c.URL())
		case <-time.After(poll):
		}
		st := state.ReadShareStatus(dir)
		if !managed && st.State != "up" && st.State != "error" && !platform.ProcessAlive(pid) {
			if stopFn != nil {
				stopFn()
			}
			return link.Errorf("the share stopped before it came up. Log: %s", logPath)
		}
		if managed && st.State == "" && !warnedNoStatus && time.Since(start) >= 15*time.Second {
			warnedNoStatus = true
			u.Note("still waiting for the background service to start; check %s if it does not come up", logPath)
		}
		switch st.State {
		case "up":
			printReady(u, c, true, managed)
			return nil
		case "error":
			if stopFn != nil {
				stopFn()
			}
			return link.Errorf("%s", st.Error)
		}
	}
	if stopFn != nil {
		stopFn()
	}
	return link.Errorf("the share did not come up in time. Log: %s", logPath)
}

func Stop(dir string, c *state.ShareConfig) {
	platform.StopShareService(c)
	StopProcess(dir)
}

func StopProcess(dir string) {
	pid := PID(dir)
	if pid == 0 {
		return
	}
	platform.StopProcess(pid, 5*time.Second)
	_ = os.Remove(filepath.Join(dir, "share.pid"))
}

func ListState(running, managed bool) string {
	switch {
	case running && managed:
		return "running in the background, starts at login"
	case running:
		return "running in the background"
	case managed:
		return "stopped (starts at login)"
	default:
		return "not running"
	}
}

type ListItem struct {
	Name    string `json:"name"`
	Zone    string `json:"zone"`
	URL     string `json:"url"`
	Target  string `json:"target"`
	Folder  bool   `json:"folder"`
	Note    string `json:"note,omitempty"`
	Private bool   `json:"private,omitempty"`
	Running bool   `json:"running"`
	Managed bool   `json:"managed"`
	State   string `json:"state"`
	Error   string `json:"error,omitempty"`
}

func CollectListItems(dirs []string) []ListItem {
	items := make([]ListItem, 0, len(dirs))
	for _, d := range dirs {
		c, err := state.LoadShare(d)
		if err != nil {
			continue
		}
		running := PID(d) != 0
		managed := platform.ShareServiceConfigured(c)
		stateLabel := ListState(running, managed)
		errMsg := ""
		if !running {
			if st := state.ReadShareStatus(d); st.State == "error" && st.Error != "" {
				errMsg = link.SingleLine(st.Error)
				stateLabel += ": " + errMsg
			}
		}
		items = append(items, ListItem{
			Name:    c.Name,
			Zone:    c.Zone,
			URL:     c.URL(),
			Target:  c.Target,
			Folder:  c.Folder,
			Note:    c.Note,
			Private: c.PrivateName,
			Running: running,
			Managed: managed,
			State:   stateLabel,
			Error:   errMsg,
		})
	}
	return items
}

func FormatListTable(w io.Writer, items []ListItem) {
	hasNote := false
	for _, item := range items {
		if item.Note != "" {
			hasNote = true
			break
		}
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if hasNote {
		fmt.Fprintln(tw, "NAME\tPEN\tURL\tTARGET\tNOTE\tSTATUS")
	} else {
		fmt.Fprintln(tw, "NAME\tPEN\tURL\tTARGET\tSTATUS")
	}
	for _, item := range items {
		pen := link.ShortPenLabel(item.Zone)
		if hasNote {
			noteCol := item.Note
			if noteCol == "" {
				noteCol = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", item.Name, pen, item.URL, item.Target, noteCol, item.State)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", item.Name, pen, item.URL, item.Target, item.State)
		}
	}
	_ = tw.Flush()
}

func List(zone string, asJSON bool, u *ui.UI) error {
	all := state.AllShares("")
	resolvedZone, err := ResolveZoneFilter(all, zone, u)
	if err != nil {
		return err
	}
	dirs := state.AllShares(resolvedZone)
	if asJSON {
		return u.WriteJSON(CollectListItems(dirs))
	}
	if len(dirs) == 0 {
		if resolvedZone != "" {
			u.Say("This computer shares nothing on %s.", resolvedZone)
		} else {
			u.Say("This computer shares nothing. Start with: hogman share <name> <target>")
		}
		return nil
	}
	FormatListTable(u.OutWriter(), CollectListItems(dirs))
	return nil
}

func NormalizeLookup(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

func MatchesLookup(shareName, shareZone, query string) bool {
	if query == "" {
		return false
	}
	sn := strings.ToLower(shareName)
	sz := strings.ToLower(shareZone)
	if query == sn || query == sn+"."+sz {
		return true
	}
	if pen := link.ShortPenLabel(sz); pen != "" && query == sn+"."+pen {
		return true
	}
	return false
}

func FormatActiveSharesHint(dirs []string) string {
	if len(dirs) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n  Active shares on this computer:")
	for _, d := range dirs {
		name := filepath.Base(d)
		zone := filepath.Base(filepath.Dir(d))
		fmt.Fprintf(&sb, "\n    hogman share stop %s   (%s)", name, link.ShortPenLabel(zone))
	}
	return sb.String()
}

func StopUsageError(zone string, u *ui.UI) error {
	all := state.AllShares("")
	dirs := all
	if resolvedZone, err := ResolveZoneFilter(all, zone, u); err == nil {
		dirs = state.AllShares(resolvedZone)
	}
	if len(dirs) == 0 {
		return link.UsageErrorf("usage: hogman share stop <name>\n  This computer currently shares nothing.")
	}
	return link.UsageErrorf("usage: hogman share stop <name>%s", FormatActiveSharesHint(dirs))
}

func Find(name, zone string, u *ui.UI) (string, error) {
	query := NormalizeLookup(name)
	all := state.AllShares("")
	resolvedZone, err := ResolveZoneFilter(all, zone, u)
	if err != nil {
		return "", err
	}
	dirs := state.AllShares(resolvedZone)
	var hits []string
	for _, d := range dirs {
		if MatchesLookup(filepath.Base(d), filepath.Base(filepath.Dir(d)), query) {
			hits = append(hits, d)
		}
	}
	switch len(hits) {
	case 0:
		if len(dirs) > 0 {
			return "", link.Errorf("this computer doesn't share anything called %s%s", strings.TrimSpace(name), FormatActiveSharesHint(dirs))
		}
		return "", link.Errorf("this computer doesn't share anything called %s (see: hogman share list)", strings.TrimSpace(name))
	case 1:
		return hits[0], nil
	}
	if u.IsTerminal() {
		u.Say("%s is shared on more than one pen:", query)
		for i, d := range hits {
			u.Say("  %d) %s", i+1, filepath.Base(filepath.Dir(d)))
		}
		ans := strings.TrimSpace(u.Ask(fmt.Sprintf("  Choose a pen [1-%d]: ", len(hits))))
		idx, err := strconv.Atoi(ans)
		if err != nil || idx < 1 || idx > len(hits) {
			return "", link.Errorf("cancelled: choose a number between 1 and %d (or pass --pen <zone>)", len(hits))
		}
		return hits[idx-1], nil
	}
	return "", link.Errorf("%s is shared on more than one pen here; pick one with --pen <zone> or set HOGMAN_PEN", query)
}

func StopCmd(name, pen string, force bool, u *ui.UI) error {
	dir, err := Find(name, pen, u)
	if err != nil {
		return err
	}
	c, err := state.LoadShare(dir)
	if err != nil {
		return err
	}
	u.Step("Taking down %s", c.URL())
	if err := RemoveWithOptions(dir, c, 30*time.Second, force, u); err != nil {
		return err
	}
	if c.PrivateName {
		u.Say("\n✓ %s is down, and its private name is retired.", c.URL())
	} else {
		u.Say("\n✓ %s is down, and the name is free again.", c.URL())
	}
	return nil
}

// RemoveForLeave tears down a share during `hogman leave`, bounding network
// wait and cleaning up local state even if the pen already removed it or is
// unreachable.
func RemoveForLeave(dir string, c *state.ShareConfig, u *ui.UI) error {
	return RemoveWithOptions(dir, c, 15*time.Second, true, u)
}

func RemoveWithOptions(dir string, c *state.ShareConfig, timeout time.Duration, cleanupOnUnreachable bool, u *ui.UI) error {
	Stop(dir, c)
	// Never got as far as joining the pen (its one-time key is still unused,
	// or has expired): there's nothing on the pen to give back.
	if _, err := os.Stat(filepath.Join(dir, "authkey")); err == nil {
		u.Note("%s never came up; removed it from this computer", c.URL())
		return os.RemoveAll(dir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	node, _, hc, err := OpenNode(ctx, dir, c)
	if err != nil {
		if IsPermanent(err) {
			u.Note("%s was already removed from the pen; cleaned up local files", c.URL())
			return os.RemoveAll(dir)
		}
		if cleanupOnUnreachable {
			u.Note("could not reach the pen for %s (%v); cleaned up local files (check your home page to remove the server if it is still listed)", c.URL(), link.SingleLine(err.Error()))
			return os.RemoveAll(dir)
		}
		return link.Errorf("could not reach the pen (%v).\n  Remove the server on your home page instead, then delete %s", err, dir)
	}
	err = GiveBackWith(ctx, hc, c, mesh.TsnetNeedsLogin(node), u)
	node.Close()
	if err != nil {
		if cleanupOnUnreachable {
			u.Note("could not give back %s (%v); cleaned up local files", c.URL(), link.SingleLine(err.Error()))
			return os.RemoveAll(dir)
		}
		return link.Errorf("%v\n  Local files remain in %s; run 'hogman share stop %s --force' to remove them.", err, dir, c.Name)
	}
	return os.RemoveAll(dir)
}
