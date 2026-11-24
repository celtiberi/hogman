package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type leaveRisk int

const (
	leaveRiskNone leaveRisk = iota
	leaveRiskSoleOwnerLastDevice
	leaveRiskUnknown
)

// Seams for tests: the network check, the [y/N] question and the per-pen
// leave steps.
var (
	leaveRiskFn    = assessLeaveRisk
	confirmFn      = confirm
	typedConfirmFn = typedConfirm
	leaveOneFn     = leaveOne
)

// leaveTarget is one pen this computer is in (a joined device, its shares, or
// both). host is the pen's public control host, when known.
type leaveTarget struct {
	zone string
	host string
	cfg  *agentConfig // nil when only shares are on this pen
	// legacyTS: joined through this computer's Tailscale app (the old way),
	// so its ownership can't be checked through Hogman's own connection.
	legacyTS bool
}

// hostOf returns the bare host name of a control URL ("" if it has none).
func hostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// localLeaveTargets lists every pen this computer has joined or shares into,
// from its own saved settings: no network needed.
func localLeaveTargets() []leaveTarget {
	byZone := map[string]*leaveTarget{}
	for _, p := range loadPenTargets(hogmanConfigBase()) {
		byZone[p.zone] = &leaveTarget{zone: p.zone, host: hostOf(p.cfg.LoginServer), cfg: p.cfg}
	}
	for _, dir := range allShares("") {
		c, err := loadShare(dir)
		if err != nil || c.Zone == "" {
			continue
		}
		if t, ok := byZone[c.Zone]; ok {
			if t.host == "" {
				t.host = hostOf(c.LoginServer)
			}
			continue
		}
		byZone[c.Zone] = &leaveTarget{zone: c.Zone, host: hostOf(c.LoginServer)}
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
		return hostOf(arg)
	}
	arg = strings.ToLower(arg)
	if i := strings.IndexAny(arg, "/#?"); i >= 0 {
		arg = arg[:i]
	}
	return strings.TrimSuffix(arg, ".")
}

// matchLeaveTargets picks the local pens a leave argument names: the full
// zone, the control host, or the pen's short name (the first label, as in
// "store-north" for store-north.pens.hogman.network). A short name shared by
// two pens (on different servers) matches both, and leaveCmd refuses it.
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
// its key, control host or zone). It never leaves more than that pen: leaving
// every pen is leave-all, which asks first.
func leaveCmd(args []string, o options) error {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		local := localLeaveTargets()
		return errorf("leave which pen? Name it, for example:  hogman leave %s\n"+
			"  Pens on this computer: %s\n"+
			"  To leave every pen, run hogman leave-all (it asks first).",
			firstZoneOr(local, "home.example.pens.hogman.network"), zoneList(local))
	}
	local := localLeaveTargets()
	key := leaveKey(args[0])
	targets := matchLeaveTargets(local, key)
	if len(targets) > 1 {
		return errorf("%s matches more than one pen here (%s); give the full name", key, zoneList(targets))
	}
	if len(targets) == 0 {
		// Not known here by that name. A full host name may be a pen joined
		// the old way, through this computer's Tailscale app: ask its server
		// which zone it is. A bare word is just not a pen here.
		if !strings.Contains(key, ".") {
			return errorf("this computer isn't in a pen called %s (pens here: %s)", key, zoneList(local))
		}
		client, err := controlClient(o.controlCA)
		if err != nil {
			return err
		}
		n, err := fetchNetwork(client, key)
		if err != nil {
			return errorf("this computer isn't in a pen called %s (pens here: %s)", key, zoneList(local))
		}
		if targets = matchLeaveTargets(local, n.Zone); len(targets) == 0 {
			if !onTailscaleAppFn(n.Zone) {
				return errorf("this computer isn't in %s (pens here: %s)", n.Zone, zoneList(local))
			}
			targets = []leaveTarget{{zone: n.Zone, host: key, legacyTS: true}}
		}
	}
	for _, t := range targets {
		if err := checkCanLeave(t, o); err != nil {
			return err
		}
		if err := leaveOneFn(t); err != nil {
			return err
		}
	}
	cleanupOrphanCanonicalBinary()
	return nil
}

// cleanupOrphanCanonicalBinary removes the shared <configBase>/bin/hogman binary
// and native-messaging registration once this computer has left its last pen and
// last share (keep-less-data).
func cleanupOrphanCanonicalBinary() {
	if len(localLeaveTargets()) > 0 {
		return
	}
	cfgBase := hogmanConfigBase()
	removeNativeHost(cfgBase)
	selfPath, _ := resolvedExePath()
	canon := canonicalBinaryPath(cfgBase)
	nh := nativeHostBinaryPath(cfgBase)
	if fi, err := os.Lstat(nh); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !sameFilePath(nh, selfPath) {
			_ = os.Remove(nh)
		}
	}
	if !sameFilePath(canon, selfPath) {
		_ = os.Remove(canon)
	}
	_ = os.Remove(filepath.Join(cfgBase, "bin"))
}

// leaveAllCmd takes this computer out of every pen it's in, after showing the
// list and asking. Pens this person owns are kept (see checkCanLeave). It
// reports how many pens were left in place.
func leaveAllCmd(args []string, o options) error {
	_, err := leaveAll(args, o, "Leave all of these pens")
	return err
}

func leaveAll(args []string, o options, question string) (kept int, err error) {
	if len(args) != 0 {
		return 0, errorf("leave-all takes no pen name; to leave one pen: hogman leave '<pen>'")
	}
	local := localLeaveTargets()
	if len(local) == 0 {
		say("This computer isn't in any pen.")
		return 0, nil
	}
	go_, stay := planLeave(local, o)
	if len(go_) == 0 {
		return len(stay), errorf("nothing to leave")
	}
	if !o.yes && !confirmFn("\n"+question+"?") {
		return len(stay), errorf("nothing changed")
	}
	if err := leaveTargets(go_); err != nil {
		return len(stay), err
	}
	cleanupOrphanCanonicalBinary()
	return len(stay), nil
}

// keptPen is a pen that stays, with why.
type keptPen struct {
	t   leaveTarget
	why string
}

// planLeave decides, once, which pens can be left (asking for --force typed
// names here and only here) and shows the plan.
func planLeave(local []leaveTarget, o options) (go_ []leaveTarget, stay []keptPen) {
	for _, t := range local {
		if err := checkCanLeave(t, o); err != nil {
			stay = append(stay, keptPen{t, err.Error()})
			continue
		}
		go_ = append(go_, t)
	}
	step("This computer is in %d pen(s)", len(local))
	for _, t := range go_ {
		note("will leave  %s", t.zone)
	}
	for _, k := range stay {
		note("will KEEP   %s:", k.t.zone)
		for _, line := range strings.Split(k.why, "\n") {
			note("    %s", strings.TrimSpace(line))
		}
	}
	return go_, stay
}

// leaveTargets leaves each pen, then clears any stale proxy setting.
func leaveTargets(ts []leaveTarget) error {
	for _, t := range ts {
		if err := leaveOneFn(t); err != nil {
			return err
		}
	}
	sweepStaleProxyFn()
	return nil
}

// sweepStaleProxyFn clears any automatic-proxy setting an old Hogman pen left
// behind (for example when an earlier leave's password prompt was cancelled),
// pointing it at the remaining pens or turning it off. macOS only: elsewhere
// hogman never changes the system proxy itself. A seam for tests.
var sweepStaleProxyFn = func() {
	if runtime.GOOS != "darwin" {
		return
	}
	if msg := clearSystemProxy(nil, loadInstalledPenConfigs(hogmanConfigBase())); msg != "" {
		note("%s", msg)
	}
}

func firstZoneOr(ts []leaveTarget, def string) string {
	if len(ts) > 0 {
		return ts[0].zone
	}
	return def
}

// checkCanLeave protects the one genuinely dangerous case: leaving when the
// caller is the sole owner on their last personal device (or when the pen
// cannot be reached to check). Another owner or another personal device lets
// the leave proceed without blocking (I-25).
//
// In an interactive terminal, sole-owner/last-device asks for typed pen-name
// confirmation right away without requiring --force. In non-interactive scripts
// (no terminal), --force prints the warning and proceeds; without --force it
// refuses.
func checkCanLeave(t leaveTarget, o options) error {
	var risk leaveRisk
	switch {
	case t.legacyTS:
		// joined through the Tailscale app: Hogman can't ask the pen as this
		// computer, so ownership is unknown.
		risk = leaveRiskUnknown
	case t.cfg == nil:
		return nil // only shares here: no device, no membership to lose
	default:
		risk = leaveRiskFn(t.cfg)
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
		if !isTerminalFn() {
			if !o.force {
				return errorf("this is your last device on %s and you're its only owner; nobody could manage it after this.\n"+
					"  Make someone else an owner under Members on home.%s, run interactively to confirm, or pass --force.", t.zone, t.zone)
			}
			say("\n⚠ %s", warning)
			return nil
		}
		if !typedConfirmFn(t.zone, warning) {
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
		if !isTerminalFn() {
			say("\n⚠ %s", warning)
			return nil
		}
		if !typedConfirmFn(t.zone, warning) {
			return errorf("the name didn't match, so %s was not left", t.zone)
		}
		return nil
	}
	return nil
}

// typedConfirm shows the warning and asks the person to type the pen's name.
func typedConfirm(zone, warning string) bool {
	if !isTerminalFn() {
		note("refusing: confirmation needs a terminal (pass --force in scripts)")
		return false
	}
	say("\n⚠ %s", warning)
	return askFn("  Type "+zone+" to leave anyway, or press Enter to cancel: ") == zone
}

// assessLeaveRisk asks the pen, as this computer, whether leaving would strand
// the pen with no owner left.
func assessLeaveRisk(cfg *agentConfig) leaveRisk {
	// Already removed from the pen (the agent proves it and the pen says log
	// in again): nothing left to protect.
	if state, d := verifyAgentEndpointDetail(stateDir(cfg.Zone), cfg); state == agentEndpointDown && d.verified && d.needsLogin {
		return leaveRiskNone
	}
	c, err := penClient(cfg)
	if err != nil {
		return leaveRiskUnknown
	}
	var me meView
	if _, err := homeAPI(c, cfg.Zone, "GET", "/me", nil, &me); err != nil || me.Member.Handle == "" {
		return leaveRiskUnknown
	}
	return leaveRiskFromMe(me)
}

// leaveRiskFromMe decides from /api/me whether leaving this device would leave
// the pen without an owner. Fails closed on older registrars that omit is_owner.
func leaveRiskFromMe(me meView) leaveRisk {
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

// onTailscaleAppFn: is this computer on zone through its Tailscale app? A
// seam for tests.
var onTailscaleAppFn = func(zone string) bool {
	ts, err := findTailscale()
	if err != nil {
		return false
	}
	st, err := ts.Status()
	return err == nil && st.OnNetwork(zone)
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

// leaveOne takes this computer out of one pen: its shares, its device, its
// background connection, its login item and its proxy setting.
func leaveOne(t leaveTarget) error {
	step("Leaving %s", t.zone)
	// Shares go first, while they can still give their names back.
	for _, dir := range allShares(t.zone) {
		if c, err := loadShare(dir); err == nil {
			if err := removeShareForLeave(dir, c); err != nil {
				note("could not take down %s: %v", c.url(), firstLine(err.Error()))
			} else {
				note("took down %s", c.url())
			}
		}
	}
	if t.cfg != nil {
		// This computer's own device, through its connection while it's still
		// up, so old devices don't pile up in "Your devices". Best effort: the
		// rest still happens if the pen can't be reached.
		gone := removeOwnDevice(t.zone)
		leaveAlongside(t.zone, gone)
	}
	if ts, err := findTailscale(); err == nil {
		if st, err := ts.Status(); err == nil && st.OnNetwork(t.zone) {
			if err := ts.Logout(); err != nil {
				_ = ts.Down()
				note("disconnected, but could not log out (%v)", firstLine(err.Error()))
				note("the network still lists this device until an admin removes it")
			} else {
				note("logged out of %s", t.zone)
			}
			note("to return to another Tailscale network: tailscale switch --list")
		}
		if t.host != "" {
			if removed := ts.RemoveProfiles(t.host); removed > 0 {
				note("removed the saved %s profile from Tailscale", t.zone)
			}
		}
	}
	_ = os.Remove(filepath.Join(sharesBase(), t.zone)) // only if now empty
	say("\n✓ Left %s.", t.zone)
	return nil
}

// uninstallCmd takes Hogman off this computer: every pen, then its settings.
// It's all or nothing. The plan is made once (any --force typed names are
// asked for there, once); if any pen would stay (one this person owns, or one
// that can't be checked), nothing changes. Otherwise it asks, even with no
// pens left, then leaves, clears a stale proxy setting and removes settings.
// The program file itself is left for the person to delete.
func uninstallCmd(args []string, o options) error {
	if len(args) != 0 {
		return errorf("usage: hogman uninstall")
	}
	local := localLeaveTargets()
	go_, stay := planLeave(local, o)
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
	if !o.yes && !confirmFn("\n"+question) {
		return errorf("nothing changed")
	}
	if err := leaveTargets(go_); err != nil {
		return err // a pen failed to leave: remove nothing
	}
	step("Removing Hogman's settings from this computer")
	removeNativeHost(hogmanConfigBase())
	for _, dir := range []string{hogmanConfigBase(), sharesBase()} {
		if err := os.RemoveAll(dir); err != nil {
			note("could not remove %s: %v", dir, err)
		} else {
			note("removed %s", dir)
		}
	}
	self, _ := os.Executable()
	say("\n✓ Hogman is off this computer.")
	if self != "" {
		if runtime.GOOS == "windows" {
			say("  Last step: delete the program itself:  del \"%s\"", self)
		} else {
			say("  Last step: delete the program itself:  rm '%s'", self)
		}
	}
	say("  If you added the Hogman browser extension, remove it from your browser's extensions page.")
	return nil
}
