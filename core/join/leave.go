package main

import (
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// leaveTarget is one pen this computer is in (a joined device, its shares, or
// both). host is the pen's public control host, when known.
type leaveTarget struct {
	zone string
	host string
	cfg  *agentConfig // nil when only shares are on this pen
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

// matchLeaveTargets picks the local pens a leave argument names.
func matchLeaveTargets(local []leaveTarget, key string) []leaveTarget {
	var out []leaveTarget
	for _, t := range local {
		if key == t.zone || (t.host != "" && key == t.host) {
			out = append(out, t)
		}
	}
	return out
}

// leaveCmd: "leave" alone leaves every pen on this computer; "leave X" leaves
// the pen X names (link, control host or zone). Everything is decided from
// this computer's saved settings, so a pen whose server is gone can still be
// left.
func leaveCmd(args []string, o options) error {
	local := localLeaveTargets()
	var targets []leaveTarget
	switch len(args) {
	case 0:
		if len(local) == 0 {
			say("This computer isn't in any pen. Nothing to do.")
			return nil
		}
		targets = local
	case 1:
		key := leaveKey(args[0])
		if key == "" {
			return errorf("leave what? Give a pen name like home.example.pens.hogman.network, or run hogman-join leave on its own to leave every pen")
		}
		targets = matchLeaveTargets(local, key)
		if len(targets) == 0 {
			// Not known here by that name: ask the server which zone it is.
			client, err := controlClient(o.controlCA)
			if err != nil {
				return err
			}
			n, err := fetchNetwork(client, key)
			if err != nil {
				return errorf("this computer isn't in a pen called %s (pens here: %s)", key, zoneList(local))
			}
			targets = matchLeaveTargets(local, n.Zone)
			if len(targets) == 0 {
				return errorf("this computer isn't in %s (pens here: %s)", n.Zone, zoneList(local))
			}
		}
	default:
		return errorf("usage: hogman-join leave ['<pen>']")
	}
	for _, t := range targets {
		if err := leaveOne(t); err != nil {
			return err
		}
	}
	return nil
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
	// Legacy private-CA cleanup goes before removing the device, so cancelling
	// an OS trust prompt leaves this computer still on the pen.
	rootFP := ""
	if t.cfg != nil {
		rootFP = t.cfg.RootFP
	}
	if removed, err := removeLegacyHogmanRoot(t.zone, rootFP); err != nil {
		return err
	} else if removed {
		note("removed the old %s certificate", t.zone)
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

// uninstallCmd leaves every pen, then removes what hogman-join keeps on this
// computer. The program file itself is left for the person to delete, since
// it may live anywhere and be in use.
func uninstallCmd(args []string, o options) error {
	if len(args) != 0 {
		return errorf("usage: hogman-join uninstall")
	}
	if err := leaveCmd(nil, o); err != nil {
		return err
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
		say("  Last step: delete the program itself:  rm '%s'", self)
	}
	say("  If you added the Hogman browser extension, remove it from your browser's extensions page.")
	return nil
}
