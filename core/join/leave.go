package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"hogman/join/internal/agent"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/nativehost"
	"hogman/join/internal/penapi"
	"hogman/join/internal/platform"
	"hogman/join/internal/share"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
	"hogman/join/internal/updater"
)

type leaveRisk int

const (
	leaveRiskNone leaveRisk = iota
	leaveRiskSoleOwnerLastDevice
	leaveRiskUnknown
)

// leaveRunner encapsulates dependencies for leave / leave-all / uninstall so
// unit tests can inject fakes locally and run in parallel without mutating
// package-level globals.
type leaveRunner struct {
	ui              *ui.UI
	configBase      func() string
	sharesBase      func() string
	leaveRisk       func(*state.AgentConfig) leaveRisk
	leaveOne        func(leaveTarget) error
	sweepStaleProxy func()
	onTailscaleApp  func(string) bool
}

func defaultLeaveRunner(u *ui.UI) *leaveRunner {
	if u == nil {
		u = ui.Default()
	}
	r := &leaveRunner{
		ui:         u,
		configBase: state.ConfigBase,
		sharesBase: state.SharesBase,
		leaveRisk:  assessLeaveRisk,
		sweepStaleProxy: func() {
			if runtime.GOOS != "darwin" {
				return
			}
			if msg := platform.ClearSystemProxy(nil, state.LoadInstalledPenConfigs(state.ConfigBase())); msg != "" {
				u.Note("%s", msg)
			}
		},
		onTailscaleApp: func(zone string) bool {
			ts, err := platform.FindTailscale()
			if err != nil {
				return false
			}
			st, err := ts.Status()
			return err == nil && st.OnNetwork(zone)
		},
	}
	r.leaveOne = r.leaveOneTarget
	return r
}

// leaveTarget is one pen this computer is in (a joined device, its shares, or
// both). host is the pen's public control host, when known.
type leaveTarget struct {
	zone string
	host string
	cfg  *state.AgentConfig // nil when only shares are on this pen
	// legacyTS: joined through this computer's Tailscale app (the old way),
	// so its ownership can't be checked through Hogman's own connection.
	legacyTS bool
}

func (r *leaveRunner) cfgBase() string {
	if r.configBase != nil {
		return r.configBase()
	}
	return state.ConfigBase()
}

func (r *leaveRunner) shBase() string {
	if r.sharesBase != nil {
		return r.sharesBase()
	}
	return state.SharesBase()
}

// localLeaveTargets lists every pen this computer has joined or shares into,
// from its own saved settings: no network needed.
func (r *leaveRunner) localLeaveTargets() []leaveTarget {
	byZone := map[string]*leaveTarget{}
	for _, p := range updater.LoadPenTargets(r.cfgBase()) {
		byZone[p.Zone] = &leaveTarget{zone: p.Zone, host: link.HostOf(p.Cfg.LoginServer), cfg: p.Cfg}
	}
	for _, dir := range state.AllSharesIn(r.shBase(), "") {
		c, err := state.LoadShare(dir)
		if err != nil || c.Zone == "" {
			continue
		}
		if t, ok := byZone[c.Zone]; ok {
			if t.host == "" {
				t.host = link.HostOf(c.LoginServer)
			}
			continue
		}
		byZone[c.Zone] = &leaveTarget{zone: c.Zone, host: link.HostOf(c.LoginServer)}
	}
	out := make([]leaveTarget, 0, len(byZone))
	for _, t := range byZone {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].zone < out[j].zone })
	return out
}

// leaveKey normalizes what someone typed after "leave": a join link (with or
// without its key), a control host, or a pen zone.
func leaveKey(arg string) string {
	arg = strings.TrimSpace(arg)
	if strings.Contains(arg, "://") {
		return link.HostOf(arg)
	}
	arg = strings.ToLower(arg)
	if i := strings.IndexAny(arg, "/#?"); i >= 0 {
		arg = arg[:i]
	}
	return strings.TrimSuffix(arg, ".")
}

// matchLeaveTargets picks the local pens a leave argument names: the full
// zone, the control host, or the pen's short name (the first label, as in
// "store-north" for store-north.pens.hogman.network).
func matchLeaveTargets(local []leaveTarget, key string) []leaveTarget {
	var out []leaveTarget
	for _, t := range local {
		short := !strings.Contains(key, ".") && strings.HasPrefix(t.zone, key+".")
		if key == t.zone || (t.host != "" && key == t.host) || short {
			out = append(out, t)
		}
	}
	return out
}

// leaveCmd takes this computer out of the one pen named (link with or without
// its key, control host or zone).
func (r *leaveRunner) leaveCmd(args []string, o options) error {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		local := r.localLeaveTargets()
		return errorf("leave which pen? Name it, for example:  hogman leave %s\n"+
			"  Pens on this computer: %s\n"+
			"  To leave every pen, run hogman leave-all (it asks first).",
			firstZoneOr(local, "home.example.pens.hogman.network"), zoneList(local))
	}
	local := r.localLeaveTargets()
	key := leaveKey(args[0])
	targets := matchLeaveTargets(local, key)
	if len(targets) > 1 {
		return errorf("%s matches more than one pen here (%s); give the full name", key, zoneList(targets))
	}
	if len(targets) == 0 {
		if !strings.Contains(key, ".") {
			return errorf("this computer isn't in a pen called %s (pens here: %s)", key, zoneList(local))
		}
		client, err := penapi.ControlClient(o.controlCA)
		if err != nil {
			return err
		}
		n, err := penapi.FetchNetwork(client, key)
		if err != nil {
			return errorf("this computer isn't in a pen called %s (pens here: %s)", key, zoneList(local))
		}
		if targets = matchLeaveTargets(local, n.Zone); len(targets) == 0 {
			if !r.onTailscaleApp(n.Zone) {
				return errorf("this computer isn't in %s (pens here: %s)", n.Zone, zoneList(local))
			}
			targets = []leaveTarget{{zone: n.Zone, host: key, legacyTS: true}}
		}
	}
	for _, t := range targets {
		if err := r.checkCanLeave(t, o); err != nil {
			return err
		}
		if err := r.leaveOne(t); err != nil {
			return err
		}
	}
	r.cleanupOrphanCanonicalBinary()
	return nil
}

// cleanupOrphanCanonicalBinary removes the shared <configBase>/bin/hogman binary
// and native-messaging registration once this computer has left its last pen and
// last share.
func (r *leaveRunner) cleanupOrphanCanonicalBinary() {
	if len(r.localLeaveTargets()) > 0 {
		return
	}
	cfgBase := r.cfgBase()
	nativehost.Remove(cfgBase)
	selfPath, _ := fsutil.ResolvedExePath()
	canon := state.CanonicalBinaryPath(cfgBase)
	nh := nativehost.BinaryPath(cfgBase)
	if fi, err := os.Lstat(nh); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fsutil.SameFilePath(nh, selfPath) {
			_ = os.Remove(nh)
		}
	}
	if !fsutil.SameFilePath(canon, selfPath) {
		_ = os.Remove(canon)
	}
	_ = os.Remove(filepath.Join(cfgBase, "bin"))
}

func (r *leaveRunner) leaveAllCmd(args []string, o options) error {
	_, err := r.leaveAll(args, o, "Leave all of these pens")
	return err
}

func (r *leaveRunner) leaveAll(args []string, o options, question string) (kept int, err error) {
	if len(args) != 0 {
		return 0, errorf("leave-all takes no pen name; to leave one pen: hogman leave '<pen>'")
	}
	local := r.localLeaveTargets()
	if len(local) == 0 {
		r.ui.Say("This computer isn't in any pen.")
		return 0, nil
	}
	go_, stay := r.planLeave(local, o)
	if len(go_) == 0 {
		return len(stay), errorf("nothing to leave")
	}
	if !o.yes && !r.ui.Confirm("\n"+question+"?") {
		return len(stay), errorf("nothing changed")
	}
	if err := r.leaveTargets(go_); err != nil {
		return len(stay), err
	}
	r.cleanupOrphanCanonicalBinary()
	return len(stay), nil
}

type keptPen struct {
	t   leaveTarget
	why string
}

func (r *leaveRunner) planLeave(local []leaveTarget, o options) (go_ []leaveTarget, stay []keptPen) {
	for _, t := range local {
		if err := r.checkCanLeave(t, o); err != nil {
			stay = append(stay, keptPen{t, err.Error()})
			continue
		}
		go_ = append(go_, t)
	}
	r.ui.Step("This computer is in %d pen(s)", len(local))
	for _, t := range go_ {
		r.ui.Note("will leave  %s", t.zone)
	}
	for _, k := range stay {
		r.ui.Note("will KEEP   %s:", k.t.zone)
		for _, line := range strings.Split(k.why, "\n") {
			r.ui.Note("    %s", strings.TrimSpace(line))
		}
	}
	return go_, stay
}

func (r *leaveRunner) leaveTargets(ts []leaveTarget) error {
	for _, t := range ts {
		if err := r.leaveOne(t); err != nil {
			return err
		}
	}
	if r.sweepStaleProxy != nil {
		r.sweepStaleProxy()
	}
	return nil
}

func firstZoneOr(ts []leaveTarget, def string) string {
	if len(ts) > 0 {
		return ts[0].zone
	}
	return def
}

func (r *leaveRunner) checkCanLeave(t leaveTarget, o options) error {
	var risk leaveRisk
	switch {
	case t.legacyTS:
		risk = leaveRiskUnknown
	case t.cfg == nil:
		return nil
	default:
		risk = r.leaveRisk(t.cfg)
	}
	var warning string
	switch risk {
	case leaveRiskNone:
		return nil
	case leaveRiskSoleOwnerLastDevice:
		warning = fmt.Sprintf(
			"This is your last device on %s and you're its only owner; nobody could manage it after this.\n"+
				"  To hand off first, make someone else an owner under Members on home.%s.",
			t.zone, t.zone)
		if !r.ui.IsTerminal() {
			if !o.force {
				return errorf("this is your last device on %s and you're its only owner; nobody could manage it after this.\n"+
					"  Make someone else an owner under Members on home.%s, run interactively to confirm, or pass --force.", t.zone, t.zone)
			}
			r.ui.Say("\n⚠ %s", warning)
			return nil
		}
		if !r.ui.TypedConfirm(t.zone, warning) {
			return errorf("the name didn't match, so %s was not left", t.zone)
		}
		return nil
	case leaveRiskUnknown:
		if !o.force {
			return errorf("couldn't reach %s to check whether you're its only owner, so this computer won't leave it yet.\n"+
				"  Try again when it's reachable. If the pen is gone for good, run it with --force.", t.zone)
		}
		warning = "Couldn't reach " + t.zone + " to check whether you're its only owner.\n" +
			"  If you are and this is your last device, you may have lost your last way to manage it."
		if !r.ui.IsTerminal() {
			r.ui.Say("\n⚠ %s", warning)
			return nil
		}
		if !r.ui.TypedConfirm(t.zone, warning) {
			return errorf("the name didn't match, so %s was not left", t.zone)
		}
		return nil
	}
	return nil
}

func assessLeaveRisk(cfg *state.AgentConfig) leaveRisk {
	if st, d := agent.VerifyEndpointDetail(state.StateDir(cfg.Zone), cfg); st == agent.EndpointDown && d.Verified && d.NeedsLogin {
		return leaveRiskNone
	}
	c, err := penapi.PenClient(cfg)
	if err != nil {
		return leaveRiskUnknown
	}
	var me penapi.MeView
	if _, err := penapi.HomeAPI(c, cfg.Zone, "GET", "/me", nil, &me); err != nil || me.Member.Handle == "" {
		return leaveRiskUnknown
	}
	return leaveRiskFromMe(me)
}

// leaveRiskFromMe decides from /api/me whether leaving this device would leave
// the pen without an owner. Fails closed on older registrars that omit is_owner.
func leaveRiskFromMe(me penapi.MeView) leaveRisk {
	if me.IsOwner == nil {
		return leaveRiskUnknown
	}
	if !*me.IsOwner {
		return leaveRiskNone
	}
	if me.Owners != nil && *me.Owners > 1 {
		return leaveRiskNone
	}
	for _, d := range me.Devices {
		if d.Kind == "personal" && d.RemovedAt == nil && d.ID != me.ThisDevice.ID {
			return leaveRiskNone
		}
	}
	return leaveRiskSoleOwnerLastDevice
}

func zoneList(ts []leaveTarget) string {
	if len(ts) == 0 {
		return "none"
	}
	z := make([]string, len(ts))
	for i, t := range ts {
		z[i] = t.zone
	}
	return strings.Join(z, ", ")
}

func (r *leaveRunner) leaveOneTarget(t leaveTarget) error {
	r.ui.Step("Leaving %s", t.zone)
	for _, dir := range state.AllSharesIn(r.shBase(), t.zone) {
		if c, err := state.LoadShare(dir); err == nil {
			if err := share.RemoveForLeave(dir, c, r.ui); err != nil {
				r.ui.Note("could not take down %s: %v", c.URL(), link.SingleLine(err.Error()))
			} else {
				r.ui.Note("took down %s", c.URL())
			}
		}
	}
	if t.cfg != nil {
		gone := removeOwnDevice(t.zone, r.ui)
		leaveAlongside(t.zone, gone, r.ui)
	}
	if ts, err := platform.FindTailscale(); err == nil {
		if st, err := ts.Status(); err == nil && st.OnNetwork(t.zone) {
			if err := ts.Logout(); err != nil {
				_ = ts.Down()
				r.ui.Note("disconnected, but could not log out (%v)", link.SingleLine(err.Error()))
				r.ui.Note("the network still lists this device until an admin removes it")
			} else {
				r.ui.Note("logged out of %s", t.zone)
			}
			r.ui.Note("to return to another Tailscale network: tailscale switch --list")
		}
		if t.host != "" {
			if removed := ts.RemoveProfiles(t.host, r.ui.Note); removed > 0 {
				r.ui.Note("removed the saved %s profile from Tailscale", t.zone)
			}
		}
	}
	_ = os.Remove(filepath.Join(r.shBase(), t.zone))
	r.ui.Say("\n✓ Left %s.", t.zone)
	return nil
}

func (r *leaveRunner) uninstallCmd(args []string, o options) error {
	if len(args) != 0 {
		return errorf("usage: hogman uninstall")
	}
	local := r.localLeaveTargets()
	go_, stay := r.planLeave(local, o)
	if len(stay) > 0 {
		names := make([]string, len(stay))
		for i, k := range stay {
			names[i] = k.t.zone
		}
		return errorf("Hogman can't be removed from this computer yet, so nothing was changed: %s stays.\n"+
			"  Make someone else an owner under Members on the pen's home page, or re-run and type each pen's name to confirm.",
			strings.Join(names, ", "))
	}
	question := "Leave these pens and remove Hogman from this computer?"
	if len(local) == 0 {
		question = "Remove Hogman's settings from this computer?"
	}
	if !o.yes && !r.ui.Confirm("\n"+question) {
		return errorf("nothing changed")
	}
	if err := r.leaveTargets(go_); err != nil {
		return err
	}
	r.ui.Step("Removing Hogman's settings from this computer")
	cfgBase := r.cfgBase()
	shBase := r.shBase()
	nativehost.Remove(cfgBase)
	for _, dir := range []string{cfgBase, shBase} {
		if err := os.RemoveAll(dir); err != nil {
			r.ui.Note("could not remove %s: %v", dir, err)
		} else {
			r.ui.Note("removed %s", dir)
		}
	}
	self, _ := os.Executable()
	home, _ := os.UserHomeDir()
	leftovers := leftoverHogmanBinaries(self, home)
	r.ui.Say("\n✓ Hogman is off this computer.")
	if len(leftovers) > 0 {
		if runtime.GOOS == "windows" {
			var parts []string
			for _, p := range leftovers {
				parts = append(parts, fmt.Sprintf(`"%s"`, p))
			}
			r.ui.Say("  Last step: delete the program itself:  del %s", strings.Join(parts, " "))
		} else {
			var parts []string
			for _, p := range leftovers {
				parts = append(parts, fmt.Sprintf("'%s'", p))
			}
			r.ui.Say("  Last step: delete the program itself:  rm %s", strings.Join(parts, " "))
		}
	}
	r.ui.Say("  If you added the Hogman browser extension, remove it from your browser's extensions page.")
	return nil
}

// leftoverHogmanBinaries returns the running executable plus any common home-dir
// copies (~/hogman, ~/hogman-join) that still exist on disk so `hogman uninstall`
// lists every leftover binary for the user to delete.
func leftoverHogmanBinaries(self, home string) []string {
	var out []string
	addUnique := func(p string) {
		if p == "" {
			return
		}
		for _, prev := range out {
			if fsutil.SameFilePath(prev, p) {
				return
			}
		}
		out = append(out, p)
	}
	if self != "" {
		addUnique(self)
	}
	if home != "" {
		candidates := []string{cliBinaryName(), state.LegacyBinaryName(runtime.GOOS)}
		for _, name := range candidates {
			p := filepath.Join(home, name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				addUnique(p)
			}
		}
	}
	return out
}
