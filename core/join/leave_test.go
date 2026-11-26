package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLeaveKey(t *testing.T) {
	for in, want := range map[string]string{
		"https://qa.gate.example.network/join":         "qa.gate.example.network",
		"https://qa.gate.example.network/join#k=abc":   "qa.gate.example.network",
		"https://QA.gate.example.network:443/join?x=1": "qa.gate.example.network",
		"qa.pens.example.network":                      "qa.pens.example.network",
		"  QA.Pens.Example.Network. ":                  "qa.pens.example.network",
		"qa.gate.example.network/join#k=abc":           "qa.gate.example.network",
		"":                                             "",
	} {
		if got := leaveKey(in); got != want {
			t.Errorf("leaveKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchLeaveTargets(t *testing.T) {
	local := []leaveTarget{
		{zone: "a.pens.example.network", host: "a.gate.example.network"},
		{zone: "b.pens.example.network", host: "b.gate.example.network"},
	}
	for key, want := range map[string]string{
		"a.pens.example.network": "a.pens.example.network",
		"b.gate.example.network": "b.pens.example.network",
	} {
		got := matchLeaveTargets(local, key)
		if len(got) != 1 || got[0].zone != want {
			t.Errorf("match %q = %+v, want %s", key, got, want)
		}
	}
	if got := matchLeaveTargets(local, "c.pens.example.network"); len(got) != 0 {
		t.Errorf("unknown pen matched: %+v", got)
	}
}

// localLeaveTargets must find joined pens and share-only pens from saved
// settings alone, so leaving works when a pen's server is gone.
func TestLocalLeaveTargetsFromDisk(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if runtime.GOOS == "windows" {
		t.Setenv("AppData", filepath.Join(home, "AppData"))
	}
	write := func(path string, v any) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(v)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(stateDir("a.pens.example.network"), "config.json"),
		agentConfig{Zone: "a.pens.example.network", LoginServer: "https://a.gate.example.network"})
	write(filepath.Join(shareDir("a.pens.example.network", "blog"), "share.json"),
		shareConfig{Name: "blog", Zone: "a.pens.example.network", LoginServer: "https://a.gate.example.network"})
	write(filepath.Join(shareDir("s.pens.example.network", "cooler"), "share.json"),
		shareConfig{Name: "cooler", Zone: "s.pens.example.network", LoginServer: "https://s.gate.example.network"})

	got := localLeaveTargets()
	if len(got) != 2 {
		t.Fatalf("got %d targets, want 2: %+v", len(got), got)
	}
	if got[0].zone != "a.pens.example.network" || got[0].host != "a.gate.example.network" || got[0].cfg == nil {
		t.Errorf("joined pen = %+v", got[0])
	}
	if got[1].zone != "s.pens.example.network" || got[1].host != "s.gate.example.network" || got[1].cfg != nil {
		t.Errorf("share-only pen = %+v", got[1])
	}
	if m := matchLeaveTargets(got, leaveKey("https://s.gate.example.network/join")); len(m) != 1 {
		t.Errorf("a keyless link should match the share-only pen: %+v", m)
	}
}

// leaveFixture makes a throwaway home with three pens on disk: "own" (this
// person owns it), "mem" (a plain member) and "shr" (only a share here), and
// stubs the network check, the [y/N] answer and the leave steps.
type leaveFixture struct {
	home     string
	left     []string          // zones leaveOne was called for, in order
	asked    int               // how many times the [y/N] question was asked
	answer   bool              // what the person answers
	typed    map[string]string // what the person types when asked for a pen's name
	prompts  []string          // pens whose name was asked for (with a warning)
	swept    int               // how many times the stale-proxy sweep ran
	owners   map[string]bool   // pens where caller is sole owner on last personal device
	unknown  map[string]bool   // pens that can't be reached to ask
	terminal bool              // whether stdin is an interactive terminal
}

func newLeaveFixture(t *testing.T) *leaveFixture {
	t.Helper()
	f := &leaveFixture{home: t.TempDir(), owners: map[string]bool{"own.pens.example.network": true},
		unknown: map[string]bool{}, typed: map[string]string{}, terminal: true}
	t.Setenv("HOME", f.home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(f.home, ".config"))
	if runtime.GOOS == "windows" {
		t.Setenv("AppData", filepath.Join(f.home, "AppData"))
	}
	write := func(path string, v any) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(v)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"own", "mem"} {
		zone := p + ".pens.example.network"
		write(filepath.Join(stateDir(zone), "config.json"),
			agentConfig{Zone: zone, LoginServer: "https://" + p + ".gate.example.network"})
	}
	write(filepath.Join(shareDir("shr.pens.example.network", "cooler"), "share.json"),
		shareConfig{Name: "cooler", Zone: "shr.pens.example.network", LoginServer: "https://shr.gate.example.network"})

	oldRisk, oldConfirm, oldLeave, oldSweep, oldTTY := leaveRiskFn, confirmFn, leaveOneFn, sweepStaleProxyFn, isTerminalFn
	t.Cleanup(func() {
		leaveRiskFn, confirmFn, leaveOneFn, sweepStaleProxyFn, isTerminalFn = oldRisk, oldConfirm, oldLeave, oldSweep, oldTTY
	})
	sweepStaleProxyFn = func() { f.swept++ }
	isTerminalFn = func() bool { return f.terminal }
	leaveRiskFn = func(c *agentConfig) leaveRisk {
		if f.unknown[c.Zone] {
			return leaveRiskUnknown
		}
		if f.owners[c.Zone] {
			return leaveRiskSoleOwnerLastDevice
		}
		return leaveRiskNone
	}
	confirmFn = func(string) bool { f.asked++; return f.answer }
	oldTyped := typedConfirmFn
	t.Cleanup(func() { typedConfirmFn = oldTyped })
	typedConfirmFn = func(zone, warning string) bool {
		if warning == "" {
			t.Errorf("typed confirmation for %s came with no warning", zone)
		}
		f.prompts = append(f.prompts, zone)
		return f.typed[zone] == zone
	}
	leaveOneFn = func(lt leaveTarget) error { f.left = append(f.left, lt.zone); return nil }
	return f
}

func (f *leaveFixture) settingsExist() bool {
	_, err := os.Stat(hogmanConfigBase())
	return err == nil
}

// "leave" with no pen named must not leave anything, and must point to leave-all.
func TestLeaveWithoutPenLeavesNothing(t *testing.T) {
	f := newLeaveFixture(t)
	err := leaveCmd(nil, options{})
	if err == nil || !strings.Contains(err.Error(), "leave-all") {
		t.Fatalf("leave with no pen: err = %v, want a usage error naming leave-all", err)
	}
	if len(f.left) != 0 || f.asked != 0 {
		t.Fatalf("leave with no pen left %v (asked %d times); it must touch nothing", f.left, f.asked)
	}
}

func TestLeaveOnePenOnly(t *testing.T) {
	f := newLeaveFixture(t)
	if err := leaveCmd([]string{"mem.pens.example.network"}, options{}); err != nil {
		t.Fatal(err)
	}
	if len(f.left) != 1 || f.left[0] != "mem.pens.example.network" {
		t.Fatalf("left %v, want only mem", f.left)
	}
	// The keyless join link the maintainer typed works the same way.
	f.left = nil
	if err := leaveCmd([]string{"https://mem.gate.example.network/join"}, options{}); err != nil {
		t.Fatal(err)
	}
	if len(f.left) != 1 || f.left[0] != "mem.pens.example.network" {
		t.Fatalf("keyless link left %v, want only mem", f.left)
	}
}

// A sole owner on their last personal device is prompted interactively right
// away (no --force re-run needed), and refused without --force in non-interactive
// scripts (I-25).
func TestLeaveSoleOwnerInteractiveAndNonInteractive(t *testing.T) {
	// Interactive: prompts right away; wrong name or Enter refuses; exact name leaves.
	f := newLeaveFixture(t)
	for _, typed := range []string{"", "own", "OWN.pens.example.network", "own.pens.example.network "} {
		f.typed["own.pens.example.network"] = typed
		if err := leaveCmd([]string{"own.pens.example.network"}, options{yes: true}); err == nil {
			t.Fatalf("interactive typed %q: sole-owner leave went ahead; only the exact name may confirm", typed)
		}
	}
	if len(f.left) != 0 || len(f.prompts) != 4 {
		t.Fatalf("left=%v prompts=%d, want 0 left and 4 prompts", f.left, len(f.prompts))
	}
	f.typed["own.pens.example.network"] = "own.pens.example.network"
	if err := leaveCmd([]string{"own.pens.example.network"}, options{}); err != nil {
		t.Fatalf("interactive exact name without --force failed: %v", err)
	}
	if len(f.left) != 1 || f.left[0] != "own.pens.example.network" {
		t.Fatalf("left %v, want own after typing its name", f.left)
	}

	// Non-interactive (scripts/no TTY): refused without --force, allowed with --force.
	g := newLeaveFixture(t)
	g.terminal = false
	for _, arg := range []string{"own.pens.example.network", "https://own.gate.example.network/join#k=x"} {
		err := leaveCmd([]string{arg}, options{})
		if err == nil || !strings.Contains(err.Error(), "only owner") || !strings.Contains(err.Error(), "--force") {
			t.Fatalf("headless leave %s without --force: err = %v", arg, err)
		}
	}
	if len(g.left) != 0 || len(g.prompts) != 0 {
		t.Fatalf("headless without --force left %v, prompted %v", g.left, g.prompts)
	}
	if err := leaveCmd([]string{"own.pens.example.network"}, options{force: true}); err != nil {
		t.Fatalf("headless --force failed: %v", err)
	}
	if len(g.left) != 1 || g.left[0] != "own.pens.example.network" {
		t.Fatalf("headless --force left %v, want own", g.left)
	}
}

// If the pen can't be asked, refuse unless --force says it's gone for good.
func TestLeaveUnreachablePenNeedsForce(t *testing.T) {
	f := newLeaveFixture(t)
	f.unknown["mem.pens.example.network"] = true
	if err := leaveCmd([]string{"mem.pens.example.network"}, options{}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("unreachable pen: err = %v, want a refusal pointing to --force", err)
	}
	if len(f.left) != 0 {
		t.Fatalf("left %v without --force", f.left)
	}
	if err := leaveCmd([]string{"mem.pens.example.network"}, options{force: true}); err == nil {
		t.Fatal("--force without typing the name must refuse")
	}
	f.typed["mem.pens.example.network"] = "mem.pens.example.network"
	if err := leaveCmd([]string{"mem.pens.example.network"}, options{force: true}); err != nil {
		t.Fatal(err)
	}
	if len(f.left) != 1 {
		t.Fatalf("with --force and the typed name left %v, want mem", f.left)
	}
}

// leave-all asks first; "no" (or just Enter) changes nothing.
func TestLeaveAllAsksFirst(t *testing.T) {
	f := newLeaveFixture(t)
	f.answer = false
	if err := leaveAllCmd(nil, options{}); err == nil {
		t.Fatal("declined leave-all should report that nothing changed")
	}
	if f.asked != 1 || len(f.left) != 0 {
		t.Fatalf("declined: asked %d, left %v; want asked once and nothing left", f.asked, f.left)
	}
}

// leave-all leaves the pens it may, and keeps the one this person owns.
func TestLeaveAllKeepsOwnedPens(t *testing.T) {
	f := newLeaveFixture(t)
	f.answer = true
	if err := leaveAllCmd(nil, options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.left, ",") != "mem.pens.example.network,shr.pens.example.network" {
		t.Fatalf("left %v, want mem and shr (own kept)", f.left)
	}
	if err := leaveAllCmd([]string{"mem.pens.example.network"}, options{}); err == nil {
		t.Fatal("leave-all with a pen name should be refused")
	}
}

// uninstall asks first, and removes nothing when the answer is no.
func TestUninstallAsksFirst(t *testing.T) {
	f := newLeaveFixture(t)
	delete(f.owners, "own.pens.example.network")
	f.answer = false
	if err := uninstallCmd(nil, options{}); err == nil {
		t.Fatal("declined uninstall should report that nothing changed")
	}
	if f.asked != 1 || len(f.left) != 0 || !f.settingsExist() {
		t.Fatalf("declined: asked %d, left %v, settings exist %v", f.asked, f.left, f.settingsExist())
	}
}

// uninstall must not work at all while this person owns a pen here: it
// refuses before asking, leaves no pen (not even the ones it could), and
// removes no settings.
func TestUninstallRefusesWhenOwner(t *testing.T) {
	f := newLeaveFixture(t)
	f.answer = true
	for _, o := range []options{{}, {yes: true}} {
		err := uninstallCmd(nil, o)
		if err == nil || !strings.Contains(err.Error(), "own.pens.example.network") || !strings.Contains(err.Error(), "nothing was changed") {
			t.Fatalf("uninstall %+v as an owner: err = %v, want a refusal naming the owned pen", o, err)
		}
	}
	if f.asked != 0 || len(f.left) != 0 || !f.settingsExist() {
		t.Fatalf("owner uninstall: asked %d, left %v, settings exist %v; want nothing touched", f.asked, f.left, f.settingsExist())
	}
	// --force with a wrong (or no) typed name still changes nothing.
	f.typed["own.pens.example.network"] = "own"
	if err := uninstallCmd(nil, options{force: true, yes: true}); err == nil {
		t.Fatal("uninstall --force with the wrong name must refuse")
	}
	if len(f.left) != 0 || !f.settingsExist() {
		t.Fatalf("wrong name: left %v, settings exist %v; want nothing touched", f.left, f.settingsExist())
	}
}

// Interactive uninstall asks for the exact pen name without requiring --force,
// and still asks the [y/N] question for the whole removal (I-25).
func TestUninstallForceOwnerWithTypedName(t *testing.T) {
	f := newLeaveFixture(t)
	f.typed["own.pens.example.network"] = "own.pens.example.network"
	f.answer = true
	if err := uninstallCmd(nil, options{}); err != nil {
		t.Fatal(err)
	}
	if len(f.prompts) == 0 || f.asked != 1 || len(f.left) != 3 || f.settingsExist() {
		t.Fatalf("interactive uninstall: prompts %v, asked %d, left %v, settings exist %v", f.prompts, f.asked, f.left, f.settingsExist())
	}

	g := newLeaveFixture(t)
	g.typed["own.pens.example.network"] = "own.pens.example.network"
	g.answer = true
	if err := uninstallCmd(nil, options{force: true}); err != nil {
		t.Fatal(err)
	}
	if len(g.prompts) == 0 || g.asked != 1 || len(g.left) != 3 || g.settingsExist() {
		t.Fatalf("force uninstall: prompts %v, asked %d, left %v, settings exist %v", g.prompts, g.asked, g.left, g.settingsExist())
	}
}

// Same if a pen can't be checked (and --force doesn't apply to ownership).
func TestUninstallRefusesWhenAPenCantBeChecked(t *testing.T) {
	f := newLeaveFixture(t)
	delete(f.owners, "own.pens.example.network")
	f.unknown["mem.pens.example.network"] = true
	f.answer = true
	if err := uninstallCmd(nil, options{}); err == nil {
		t.Fatal("uninstall with an unreachable pen should refuse")
	}
	if f.asked != 0 || len(f.left) != 0 || !f.settingsExist() {
		t.Fatalf("asked %d, left %v, settings exist %v; want nothing touched", f.asked, f.left, f.settingsExist())
	}
}

func TestUninstallRemovesSettingsWhenAllLeft(t *testing.T) {
	f := newLeaveFixture(t)
	delete(f.owners, "own.pens.example.network")
	f.answer = true
	if err := uninstallCmd(nil, options{}); err != nil {
		t.Fatal(err)
	}
	if len(f.left) != 3 || f.settingsExist() {
		t.Fatalf("left %v, settings exist %v; want all three left and settings gone", f.left, f.settingsExist())
	}
}

// After leaving pens, leave-all (and so uninstall) sweeps a stale Hogman proxy
// setting; declining sweeps nothing.
func TestLeaveAllSweepsStaleProxy(t *testing.T) {
	f := newLeaveFixture(t)
	f.answer = false
	_ = leaveAllCmd(nil, options{})
	if f.swept != 0 {
		t.Fatalf("declined leave-all swept the proxy %d times", f.swept)
	}
	f.answer = true
	if err := leaveAllCmd(nil, options{}); err != nil {
		t.Fatal(err)
	}
	if f.swept != 1 {
		t.Fatalf("leave-all swept %d times, want 1", f.swept)
	}
}

// A PAC address an old Hogman pen left behind is reported as stale, not as
// someone else's proxy (which would also stop a later join from setting it).
func TestStaleHogmanPACIsNotAConflict(t *testing.T) {
	const stale = "http://127.0.0.1:25148/proxy.pac?v=f862f6b0"
	old := staleHogmanPAC
	t.Cleanup(func() { staleHogmanPAC = old })
	staleHogmanPAC = func(u string) bool { return u == stale }

	st := evaluateDarwinProxyState(scutilProxyInfo{PACOn: true, PACURL: stale}, "en0", false, nil)
	if st.OSProxyConflict || st.StalePAC != stale {
		t.Fatalf("stale Hogman PAC: conflict=%v stale=%q; want no conflict, stale reported", st.OSProxyConflict, st.StalePAC)
	}
	st = evaluateDarwinProxyState(scutilProxyInfo{PACOn: true, PACURL: "http://proxy.corp.example/wpad.dat"}, "en0", false, nil)
	if !st.OSProxyConflict || st.StalePAC != "" {
		t.Fatalf("company PAC: conflict=%v stale=%q; want a conflict", st.OSProxyConflict, st.StalePAC)
	}
}

// status mentions the optional extension host only when it's installed or a
// VPN override makes it useful: never a nag on a healthy computer.
func TestExtensionHostLine(t *testing.T) {
	for _, c := range []struct {
		installed, seen, vpn bool
		want                 string
	}{
		{false, false, false, ""},
		{false, false, true, "not installed"},
		{true, false, false, "installed (not yet"},
		{true, true, false, "active"},
		{true, true, true, "active"},
	} {
		got := extensionHostLine(c.installed, c.seen, c.vpn)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("installed=%v seen=%v vpn=%v: %q, want %q", c.installed, c.seen, c.vpn, got, c.want)
		}
	}
}

// leave accepts a pen's short name, and refuses one that matches two pens.
func TestLeaveShortName(t *testing.T) {
	f := newLeaveFixture(t)
	if err := leaveCmd([]string{"mem"}, options{}); err != nil {
		t.Fatal(err)
	}
	if len(f.left) != 1 || f.left[0] != "mem.pens.example.network" {
		t.Fatalf("short name left %v, want mem", f.left)
	}
	local := []leaveTarget{{zone: "mem.pens.a.network"}, {zone: "mem.pens.b.network"}}
	if got := matchLeaveTargets(local, "mem"); len(got) != 2 {
		t.Fatalf("ambiguous short name matched %v", got)
	}
	if got := matchLeaveTargets(local, "me"); len(got) != 0 {
		t.Fatalf("a prefix of a short name must not match: %v", got)
	}
}

// uninstall --force asks for each pen's name exactly once, and if a pen would
// stay, removes nothing (no second pass that could disagree with the first).
func TestUninstallForceAsksOnceAndNeverRemovesForAKeptPen(t *testing.T) {
	f := newLeaveFixture(t)
	f.answer = true
	f.typed["own.pens.example.network"] = "own.pens.example.network"
	if err := uninstallCmd(nil, options{force: true}); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, z := range f.prompts {
		if z == "own.pens.example.network" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("owned pen's name asked %d times, want once", n)
	}

	g := newLeaveFixture(t)
	g.answer = true
	g.typed["own.pens.example.network"] = "wrong"
	if err := uninstallCmd(nil, options{force: true}); err == nil {
		t.Fatal("uninstall went ahead with a kept pen")
	}
	if len(g.left) != 0 || g.asked != 0 || !g.settingsExist() {
		t.Fatalf("kept pen: left %v, asked %d, settings exist %v; want nothing touched", g.left, g.asked, g.settingsExist())
	}
}

// uninstall with no pens still asks first, and clears a stale proxy setting.
func TestUninstallWithNoPensAsksAndSweeps(t *testing.T) {
	f := newLeaveFixture(t)
	for _, d := range []string{hogmanConfigBase(), sharesBase()} {
		_ = os.RemoveAll(d)
	}
	if err := os.MkdirAll(hogmanConfigBase(), 0o700); err != nil {
		t.Fatal(err)
	}
	f.answer = false
	if err := uninstallCmd(nil, options{}); err == nil {
		t.Fatal("declined uninstall should report nothing changed")
	}
	if f.asked != 1 || f.swept != 0 || !f.settingsExist() {
		t.Fatalf("declined: asked %d, swept %d, settings exist %v", f.asked, f.swept, f.settingsExist())
	}
	f.answer = true
	if err := uninstallCmd(nil, options{}); err != nil {
		t.Fatal(err)
	}
	if f.swept != 1 || f.settingsExist() {
		t.Fatalf("accepted: swept %d, settings exist %v; want swept and removed", f.swept, f.settingsExist())
	}
}

// leaveRiskFromMe allows leaving whenever another owner or another personal
// device exists, and fails closed on older registrars that omit is_owner (I-25).
func TestLeaveRiskFromMe(t *testing.T) {
	yes, no := true, false
	one, two := 1, 2
	removedAt := int64(1700000000)

	// Missing is_owner (older registrar) -> unknown (fail closed).
	if got := leaveRiskFromMe(meView{}); got != leaveRiskUnknown {
		t.Fatalf("missing is_owner = %v, want leaveRiskUnknown", got)
	}
	// Non-owner -> safe.
	if got := leaveRiskFromMe(meView{IsOwner: &no}); got != leaveRiskNone {
		t.Fatalf("non-owner = %v, want leaveRiskNone", got)
	}
	// Owner with a second owner -> safe (even with only one device).
	meTwoOwners := meView{IsOwner: &yes, Owners: &two}
	meTwoOwners.ThisDevice.ID = 1
	meTwoOwners.Devices = []meDeviceView{{ID: 1, Kind: "personal"}}
	if got := leaveRiskFromMe(meTwoOwners); got != leaveRiskNone {
		t.Fatalf("owner with 2 owners = %v, want leaveRiskNone", got)
	}
	// Sole owner with another active personal device -> safe.
	meTwoDevs := meView{IsOwner: &yes, Owners: &one}
	meTwoDevs.ThisDevice.ID = 1
	meTwoDevs.Devices = []meDeviceView{
		{ID: 1, Kind: "personal"},
		{ID: 2, Kind: "personal"},
	}
	if got := leaveRiskFromMe(meTwoDevs); got != leaveRiskNone {
		t.Fatalf("sole owner with 2 personal devices = %v, want leaveRiskNone", got)
	}
	// Sole owner with only a server device or removed personal device -> risky!
	meOnlyServerAndRemoved := meView{IsOwner: &yes, Owners: &one}
	meOnlyServerAndRemoved.ThisDevice.ID = 1
	meOnlyServerAndRemoved.Devices = []meDeviceView{
		{ID: 1, Kind: "personal"},
		{ID: 2, Kind: "server"},
		{ID: 3, Kind: "personal", RemovedAt: &removedAt},
	}
	if got := leaveRiskFromMe(meOnlyServerAndRemoved); got != leaveRiskSoleOwnerLastDevice {
		t.Fatalf("sole owner with only server/removed other devices = %v, want leaveRiskSoleOwnerLastDevice", got)
	}
	// Older registrar returning is_owner=true without owners/devices -> fail closed as sole owner.
	if got := leaveRiskFromMe(meView{IsOwner: &yes}); got != leaveRiskSoleOwnerLastDevice {
		t.Fatalf("is_owner=true without owners/devices = %v, want leaveRiskSoleOwnerLastDevice", got)
	}
}

// A pen joined the old way (Tailscale app) can't be checked, so leaving it
// needs --force and the typed name.
func TestLegacyTailscalePenNeedsForce(t *testing.T) {
	f := newLeaveFixture(t)
	lt := leaveTarget{zone: "old.pens.example.network", legacyTS: true}
	if err := checkCanLeave(lt, options{}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("legacy pen without --force: %v", err)
	}
	f.typed["old.pens.example.network"] = "old.pens.example.network"
	if err := checkCanLeave(lt, options{force: true}); err != nil {
		t.Fatalf("legacy pen with --force and name: %v", err)
	}
}

// A bare word that isn't a pen here is refused without asking any server.
func TestLeaveBareTypoNoNetwork(t *testing.T) {
	newLeaveFixture(t)
	err := leaveCmd([]string{"typo"}, options{})
	if err == nil || !strings.Contains(err.Error(), "isn't in a pen called typo") {
		t.Fatalf("leave typo: %v", err)
	}
}

func TestLeftoverHogmanBinariesListsHomeCopies(t *testing.T) {
	home := t.TempDir()
	other := t.TempDir()
	self := filepath.Join(other, cliBinaryName())
	homeCopy := filepath.Join(home, cliBinaryName())
	legacyCopy := filepath.Join(home, legacyBinaryName(runtime.GOOS))
	for _, p := range []string{self, homeCopy, legacyCopy} {
		if err := os.WriteFile(p, []byte("bin"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got := leftoverHogmanBinaries(self, home)
	if len(got) != 3 {
		t.Fatalf("leftoverHogmanBinaries = %v, want 3 distinct binaries", got)
	}
	// When self IS ~/hogman, don't duplicate it.
	gotSame := leftoverHogmanBinaries(homeCopy, home)
	if len(gotSame) != 2 {
		t.Fatalf("leftoverHogmanBinaries(same) = %v, want 2 distinct binaries", gotSame)
	}
}
