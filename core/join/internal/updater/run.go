package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"hogman/join/internal/agent"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/nativehost"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
)

const Usage = `hogman update: update hogman from GitHub Releases (or a pen's server)

usage:
  hogman update ['<link|host>']

By default, resolves the latest immutable release on GitHub
(celtiberi/hogman), verifies the matching binary against
hogman-SHA256SUMS over HTTPS, updates this computer's joined pen agents
(restarting them if running), and updates cached share and browser-host
binaries. Works even when this computer is not on any pen yet.

Pass a pen's host/link or --pen ZONE to update from a pen's server instead
(for firewalled networks or private test pens).

options:
  --pen ZONE        update from one specific pen's server instead of GitHub Releases
  --dry-run         check checksums and show what would change without modifying files
  --no-service      keep restarted agents in the background rather than a login item
  --control-ca FILE extra certificate to trust for a custom server
`

func Run(args []string, o Options, u *ui.UI) error {
	if len(args) > 1 {
		return link.Errorf("usage: hogman update [--pen ZONE] [--dry-run] ['<link|host>']")
	}
	binName, err := PlatformBinaryName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	selfPath, err := fsutil.ResolvedExePath()
	if err != nil {
		return err
	}

	configBase := state.ConfigBase()
	plan, err := ResolvePlan(args, o.Pen, configBase, state.SharesBase())
	if err != nil {
		return err
	}

	binURL, wantHex, err := fetchUpdateTarget(plan, binName, o, u)
	if err != nil {
		return err
	}

	st := assessUpdateState(plan, configBase, selfPath, wantHex)
	if st.selfNeedsUpdate && st.pkgManaged && !o.DryRun {
		return link.Errorf("%s is managed by %s — upgrade with: %s\n"+
			"  (after upgrading, run '%s update' if any background agents need syncing)",
			selfPath, st.pkgMgr, st.pkgUpgradeCmd, o.binaryName())
	}

	if !st.anyUpdate() {
		u.Say("\n✓ %s is already up to date (%s).", o.binaryName(), wantHex)
		if !o.DryRun {
			WarnMissingSystemProxyServices(state.LoadInstalledPenConfigs(configBase), u)
		}
		return nil
	}

	if o.DryRun {
		printDryRun(plan, &st, selfPath, wantHex, u)
		return nil
	}

	if err := stageUpdatedBinaries(plan, &st, configBase, selfPath, binName, binURL, wantHex, o, u); err != nil {
		return err
	}
	if err := migrateTargets(plan, &st, configBase, selfPath, wantHex, o, u); err != nil {
		return err
	}

	if verLine := QueryBinaryVersionLine(selfPath); verLine != "" {
		u.Say("\n✓ Updated %s (SHA-256 %s).", verLine, wantHex)
	} else {
		u.Say("\n✓ Updated hogman (SHA-256 %s).", wantHex)
	}
	WarnMissingSystemProxyServices(state.LoadInstalledPenConfigs(configBase), u)
	return nil
}

func fetchUpdateTarget(plan *Plan, binName string, o Options, u *ui.UI) (binURL, wantHex string, err error) {
	metaClient, err := HTTPClient(o.ControlCA, plan.ControlCA, plan.Host, 30*time.Second)
	if err != nil {
		return "", "", err
	}
	var sumsURL string
	if plan.FromRelease {
		u.Step("Checking GitHub Releases for updates (%s)", binName)
		ver, tag, dlBase, err := FetchLatestReleaseTag(metaClient, plan.ReleaseBase)
		if err != nil {
			return "", "", err
		}
		u.Note("latest release: %s (%s)", ver, tag)
		sumsURL = dlBase + "/hogman-SHA256SUMS"
		binURL = dlBase + "/" + binName
	} else {
		u.Step("Checking %s for updates (%s)", plan.Host, binName)
		sumsURL = plan.BaseURL + "/join/dl/SHA256SUMS"
		binURL = plan.BaseURL + "/join/dl/" + binName
	}
	wantHex, err = FetchExpectedSHA256URL(metaClient, sumsURL, binName)
	if err != nil {
		return "", "", err
	}
	u.Note("expected SHA-256: %s", wantHex)
	return binURL, wantHex, nil
}

type updateAssessment struct {
	selfPath             string
	selfHash             string
	selfNeedsUpdate      bool
	pkgMgr               string
	pkgUpgradeCmd        string
	pkgManaged           bool
	instName             string
	oldInstName          string
	canonicalBin         string
	canonicalNeeded      bool
	canonicalNeedsUpdate bool
	nhBin                string
	nhNeedsUpdate        bool
	oldBinCanonical      string
	hasOldBinCanonical   bool
	anyLegacy            bool
	anyInterrupted       bool
	anyStaleAgent        bool
}

func (a *updateAssessment) legacyCopyIn(dir string) string {
	for _, name := range []string{a.instName, a.oldInstName} {
		p := filepath.Join(dir, name)
		if fsutil.SameFilePath(p, a.selfPath) || fsutil.SameFilePath(p, a.canonicalBin) {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (a *updateAssessment) anyUpdate() bool {
	return a.selfNeedsUpdate || a.canonicalNeedsUpdate || a.nhNeedsUpdate ||
		a.anyLegacy || a.anyInterrupted || a.anyStaleAgent
}

func assessUpdateState(plan *Plan, configBase, selfPath, wantHex string) updateAssessment {
	selfHash, _ := fsutil.FileSHA256(selfPath)
	pkgMgr, pkgUpgradeCmd, pkgManaged := DetectPackageManager(selfPath, runtime.GOOS)
	instName := state.InstalledBinaryName(runtime.GOOS)
	oldInstName := state.LegacyBinaryName(runtime.GOOS)
	canonicalBin := state.CanonicalBinaryPath(configBase)
	nhBin := nativehost.BinaryPath(configBase)

	canonicalNeeded := len(plan.Pens) > 0 || len(plan.Shares) > 0
	if _, err := os.Stat(canonicalBin); err == nil {
		canonicalNeeded = true
	}
	if _, err := os.Lstat(nhBin); err == nil {
		canonicalNeeded = true
	}
	canonicalNeedsUpdate := false
	if canonicalNeeded && !fsutil.SameFilePath(selfPath, canonicalBin) {
		h, _ := fsutil.FileSHA256(canonicalBin)
		canonicalNeedsUpdate = !DigestEqualHex(h, wantHex)
	}

	nhNeedsUpdate := false
	if !fsutil.SameFilePath(selfPath, nhBin) {
		if fi, err := os.Lstat(nhBin); err == nil {
			if runtime.GOOS != "windows" {
				nhNeedsUpdate = fi.Mode()&os.ModeSymlink == 0 || !fsutil.SameFilePath(canonicalBin, nhBin)
			} else {
				h, _ := fsutil.FileSHA256(nhBin)
				nhNeedsUpdate = !DigestEqualHex(h, wantHex)
			}
		}
	}

	oldBinCanonical := filepath.Join(configBase, "bin", oldInstName)
	hasOldBinCanonical := false
	if !fsutil.SameFilePath(oldBinCanonical, selfPath) && !fsutil.SameFilePath(oldBinCanonical, canonicalBin) {
		if _, err := os.Stat(oldBinCanonical); err == nil {
			hasOldBinCanonical = true
		}
	}

	st := updateAssessment{
		selfPath:             selfPath,
		selfHash:             selfHash,
		selfNeedsUpdate:      !DigestEqualHex(selfHash, wantHex),
		pkgMgr:               pkgMgr,
		pkgUpgradeCmd:        pkgUpgradeCmd,
		pkgManaged:           pkgManaged,
		instName:             instName,
		oldInstName:          oldInstName,
		canonicalBin:         canonicalBin,
		canonicalNeeded:      canonicalNeeded,
		canonicalNeedsUpdate: canonicalNeedsUpdate,
		nhBin:                nhBin,
		nhNeedsUpdate:        nhNeedsUpdate,
		oldBinCanonical:      oldBinCanonical,
		hasOldBinCanonical:   hasOldBinCanonical,
		anyLegacy:            hasOldBinCanonical,
	}

	for i := range plan.Pens {
		if st.legacyCopyIn(plan.Pens[i].Dir) != "" {
			st.anyLegacy = true
		}
		if interrupted, _ := state.ReadUpdatingMarker(plan.Pens[i].Dir); interrupted {
			st.anyInterrupted = true
		}
		if AgentRunningStaleBinary(&plan.Pens[i], wantHex) {
			st.anyStaleAgent = true
		}
	}
	for i := range plan.Shares {
		if st.legacyCopyIn(plan.Shares[i].Dir) != "" {
			st.anyLegacy = true
		}
		if interrupted, _ := state.ReadUpdatingMarker(plan.Shares[i].Dir); interrupted {
			st.anyInterrupted = true
		}
	}
	return st
}

func printDryRun(plan *Plan, st *updateAssessment, selfPath, wantHex string, u *ui.UI) {
	u.Step("Dry run: nothing changed. Would update to %s:", wantHex)
	if st.selfNeedsUpdate {
		if st.pkgManaged {
			u.Note("%s is managed by %s (upgrade with: %s)", selfPath, st.pkgMgr, st.pkgUpgradeCmd)
		} else {
			u.Note("%s (current %s)", selfPath, FormatDigest(st.selfHash))
		}
	}
	if st.canonicalNeedsUpdate {
		u.Note("%s", st.canonicalBin)
	}
	if st.nhNeedsUpdate {
		u.Note("%s", st.nhBin)
	}
	for i := range plan.Pens {
		if legacy := st.legacyCopyIn(plan.Pens[i].Dir); legacy != "" {
			u.Note("consolidate %s -> %s", legacy, st.canonicalBin)
		} else if AgentRunningStaleBinary(&plan.Pens[i], wantHex) {
			u.Note("restart stale %s agent onto %s", plan.Pens[i].Zone, st.canonicalBin)
		}
	}
	for i := range plan.Shares {
		if legacy := st.legacyCopyIn(plan.Shares[i].Dir); legacy != "" {
			u.Note("consolidate %s -> %s", legacy, st.canonicalBin)
		}
	}
	if st.hasOldBinCanonical {
		u.Note("consolidate %s -> %s", st.oldBinCanonical, st.canonicalBin)
	}
}

func stageUpdatedBinaries(plan *Plan, st *updateAssessment, configBase, selfPath, binName, binURL, wantHex string, o Options, u *ui.UI) error {
	if st.selfNeedsUpdate {
		if err := CheckDirWritable(filepath.Dir(selfPath)); err != nil {
			return link.Errorf("cannot update %s (%v). Move hogman to a writable folder or re-run with write permission", selfPath, err)
		}
	}
	if st.canonicalNeedsUpdate {
		if err := os.MkdirAll(filepath.Dir(st.canonicalBin), 0o700); err != nil {
			return link.Errorf("cannot prepare %s: %v", filepath.Dir(st.canonicalBin), err)
		}
		if err := CheckDirWritable(filepath.Dir(st.canonicalBin)); err != nil {
			return link.Errorf("cannot update %s (%v)", st.canonicalBin, err)
		}
	}
	if st.nhNeedsUpdate {
		if err := CheckDirWritable(filepath.Dir(st.nhBin)); err != nil {
			return link.Errorf("cannot update %s (%v)", st.nhBin, err)
		}
	}

	verifiedSrc := selfPath
	if st.selfNeedsUpdate {
		tmpDir, err := os.MkdirTemp("", "hogman-update-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpDir)
		dlClient, err := HTTPClient(o.ControlCA, plan.ControlCA, plan.Host, 5*time.Minute)
		if err != nil {
			return err
		}
		u.Step("Downloading and verifying %s", binName)
		verifiedSrc, err = DownloadVerifiedBinaryURL(dlClient, binURL, binName, wantHex, tmpDir)
		if err != nil {
			return err
		}
		u.Note("checksum verified (%s)", wantHex)
		if err := StageAndVerify(verifiedSrc, selfPath, wantHex); err != nil {
			return link.Errorf("could not replace %s: %v", selfPath, err)
		}
		u.Note("updated %s", selfPath)
	}

	if st.canonicalNeedsUpdate {
		if !plan.FromRelease {
			if otherPens := PensOutsidePlan(configBase, plan.Pens); len(otherPens) > 0 {
				curVer := QueryBinaryVersion(st.canonicalBin)
				newVer := QueryBinaryVersion(verifiedSrc)
				if cmp, ok := CompareReleaseVersions(newVer, curVer); ok && cmp < 0 {
					return link.Errorf("refusing to downgrade shared binary %s (%s -> %s) from %s while other pens (%s) share it.\n"+
						"  Run 'hogman update' (without --pen) to update all pens from GitHub Releases.",
						st.canonicalBin, curVer, newVer, plan.Host, strings.Join(otherPens, ", "))
				}
			}
		}
		if err := StageAndVerify(verifiedSrc, st.canonicalBin, wantHex); err != nil {
			return link.Errorf("could not update %s: %v", st.canonicalBin, err)
		}
		u.Note("updated %s", st.canonicalBin)
	}

	if st.nhNeedsUpdate {
		srcForNH := st.canonicalBin
		if !st.canonicalNeeded {
			srcForNH = verifiedSrc
		}
		if err := nativehost.InstallBinary(srcForNH, st.nhBin); err != nil {
			u.Note("could not update %s: %v", st.nhBin, err)
		} else {
			u.Note("updated %s", st.nhBin)
		}
	}
	return nil
}

func migrateTargets(plan *Plan, st *updateAssessment, configBase, selfPath, wantHex string, o Options, u *ui.UI) error {
	serviceBin := st.canonicalBin
	if fsutil.SameFilePath(selfPath, st.canonicalBin) || !st.canonicalNeeded {
		serviceBin = selfPath
	}
	ops := DefaultPenOps(u)
	ops.RunningStale = func(p *PenTarget) bool { return AgentRunningStaleBinary(p, wantHex) }
	shareOps := DefaultShareOps(u)
	forceAll := st.selfNeedsUpdate || st.canonicalNeedsUpdate || st.hasOldBinCanonical
	penResults := MigratePens(plan.Pens, serviceBin, selfPath, st.legacyCopyIn, forceAll, o, ops, u)
	var failedZones []string
	var failedShares []string
	for _, res := range penResults {
		if res.Err != nil {
			failedZones = append(failedZones, res.Zone)
		}
	}
	for i := range plan.Shares {
		s := &plan.Shares[i]
		legacy := st.legacyCopyIn(s.Dir)
		interrupted, _ := state.ReadUpdatingMarker(s.Dir)
		if !forceAll && legacy == "" && !interrupted {
			continue
		}
		if err := MigrateAndRestartShare(s, serviceBin, legacy, selfPath, o, shareOps, u); err != nil {
			u.Note("✗ share %s: %v", s.Cfg.FQDN(), err)
			failedShares = append(failedShares, s.Cfg.FQDN())
		} else {
			u.Note("✓ share %s migrated to %s", s.Cfg.FQDN(), serviceBin)
		}
	}
	if st.hasOldBinCanonical && len(failedZones) == 0 && len(failedShares) == 0 {
		if err := os.Remove(st.oldBinCanonical); err == nil {
			u.Note("consolidated %s -> %s", st.oldBinCanonical, st.canonicalBin)
		}
	}

	if skipped := PensOutsidePlan(configBase, plan.Pens); len(skipped) > 0 {
		u.Note("shared binary %s updated from %s; other pens (%s) will use it on next restart (run 'hogman update' to update and restart all pens from GitHub Releases)",
			st.canonicalBin, plan.Host, strings.Join(skipped, ", "))
	}

	if len(failedZones) > 0 || len(failedShares) > 0 {
		var parts []string
		if len(failedZones) > 0 {
			parts = append(parts, fmt.Sprintf("pen(s): %s (if gone, run 'hogman leave <pen>')", strings.Join(failedZones, ", ")))
		}
		if len(failedShares) > 0 {
			parts = append(parts, fmt.Sprintf("share(s): %s", strings.Join(failedShares, ", ")))
		}
		return link.Errorf("updated binary (%s), but %s did not come back online", wantHex, strings.Join(parts, "; "))
	}
	return nil
}

func WarnMissingSystemProxyServices(configs []*state.AgentConfig, u *ui.UI) {
	if len(configs) == 0 {
		return
	}
	sys := platform.DetectSystemProxyState(configs)
	if len(sys.MissingProxyServices) == 0 {
		return
	}
	if host := agent.PickPACHost(configs); host != nil {
		svcList := platform.FormatServiceList(sys.MissingProxyServices)
		u.Say("\n! Automatic proxy configuration is not set on: %s", svcList)
		u.Say("  In System Settings → Network → %s → Details… → Proxies, turn on \"Automatic proxy configuration\" and paste:", svcList)
		u.Say("    %s", host.PACURL())
	}
}

func FormatDigest(h string) string {
	if h == "" {
		return "missing"
	}
	return h
}
