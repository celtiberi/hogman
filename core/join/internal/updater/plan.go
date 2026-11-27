package updater

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"hogman/join/internal/link"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
)

type PenTarget struct {
	Zone string
	Dir  string
	Cfg  *state.AgentConfig
}

type ShareTargetDir struct {
	Zone string
	Name string
	Dir  string
	Cfg  *state.ShareConfig
}

type Plan struct {
	FromRelease bool
	ReleaseBase string
	BaseURL     string
	Host        string
	ControlCA   string
	Pens        []PenTarget
	Shares      []ShareTargetDir
}

func LoadPenTargets(configBase string) []PenTarget {
	scanned := state.ScanInstalledPens(configBase)
	var pens []PenTarget
	for _, p := range scanned.Pens {
		if p.Config.LoginServer != "" {
			pens = append(pens, PenTarget{Zone: p.Zone, Dir: p.Dir, Cfg: p.Config})
		}
	}
	return pens
}

func LoadLocalTargets(configBase, sharesDir string) ([]PenTarget, []ShareTargetDir) {
	pens := LoadPenTargets(configBase)
	var shares []ShareTargetDir
	if pattern, err := filepath.Glob(filepath.Join(sharesDir, "*", "*", "share.json")); err == nil {
		sort.Strings(pattern)
		for _, f := range pattern {
			dir := filepath.Dir(f)
			if c, err := state.LoadShare(dir); err == nil && c.LoginServer != "" &&
				c.Zone != "" && c.Name != "" &&
				c.Zone == filepath.Base(filepath.Dir(dir)) && c.Name == filepath.Base(dir) {
				shares = append(shares, ShareTargetDir{Zone: c.Zone, Name: c.Name, Dir: dir, Cfg: c})
			}
		}
	}
	return pens, shares
}

func ResolvePlan(args []string, pen string, configBase, sharesDir string) (*Plan, error) {
	allPens, allSharesList := LoadLocalTargets(configBase, sharesDir)
	penFilter := ""
	if strings.TrimSpace(pen) != "" {
		var err error
		penFilter, err = link.ValidatePenQuery(pen)
		if err != nil {
			return nil, err
		}
	}

	// Default (no explicit server/link and no --pen): update from immutable
	// GitHub Releases (works with 0, 1, or N pens and updates every local copy).
	if len(args) == 0 && penFilter == "" {
		relBase, relHost, err := EffectiveReleaseBase()
		if err != nil {
			return nil, err
		}
		return &Plan{
			FromRelease: true,
			ReleaseBase: relBase,
			Host:        relHost,
			Pens:        allPens,
			Shares:      allSharesList,
		}, nil
	}

	if len(args) == 1 {
		baseURL, host, err := ParseSourceURL(args[0])
		if err != nil {
			return nil, err
		}
		plan := &Plan{BaseURL: baseURL, Host: host}
		var matchedZones []string
		seenZone := map[string]bool{}
		for _, p := range allPens {
			if penFilter != "" && !link.PenMatchesQuery(p.Zone, p.Cfg.LoginServer, penFilter) {
				continue
			}
			if !seenZone[p.Zone] {
				seenZone[p.Zone] = true
				matchedZones = append(matchedZones, p.Zone)
			}
			if penFilter != "" && p.Cfg.LoginServer != baseURL {
				return nil, link.Errorf("%s uses %s, not %s", p.Zone, p.Cfg.LoginServer, baseURL)
			}
			if p.Cfg.LoginServer == baseURL {
				plan.Pens = append(plan.Pens, p)
				if plan.ControlCA == "" && p.Cfg.ControlCA != "" {
					plan.ControlCA = p.Cfg.ControlCA
				}
			}
		}
		for _, s := range allSharesList {
			if penFilter != "" && !link.PenMatchesQuery(s.Zone, s.Cfg.LoginServer, penFilter) {
				continue
			}
			if !seenZone[s.Zone] {
				seenZone[s.Zone] = true
				matchedZones = append(matchedZones, s.Zone)
			}
			if penFilter != "" && s.Cfg.LoginServer != baseURL {
				return nil, link.Errorf("%s uses %s, not %s", s.Zone, s.Cfg.LoginServer, baseURL)
			}
			if s.Cfg.LoginServer == baseURL {
				plan.Shares = append(plan.Shares, s)
				if plan.ControlCA == "" && s.Cfg.ControlCA != "" {
					plan.ControlCA = s.Cfg.ControlCA
				}
			}
		}
		if penFilter != "" && len(matchedZones) == 0 {
			return nil, link.Errorf("this computer is not on %s", penFilter)
		}
		if penFilter != "" && len(matchedZones) > 1 {
			sort.Strings(matchedZones)
			return nil, link.Errorf("%q matches more than one pen (%s); pass the full zone name with --pen", penFilter, strings.Join(matchedZones, ", "))
		}
		return plan, nil
	}

	type source struct {
		baseURL   string
		controlCA string
	}
	sources := map[string]source{}
	zonesSeen := map[string]struct{}{}
	var matchedPens []PenTarget
	var matchedShares []ShareTargetDir

	for _, p := range allPens {
		if penFilter != "" && !link.PenMatchesQuery(p.Zone, p.Cfg.LoginServer, penFilter) {
			continue
		}
		matchedPens = append(matchedPens, p)
		zonesSeen[p.Zone] = struct{}{}
		cur := sources[p.Cfg.LoginServer]
		cur.baseURL = p.Cfg.LoginServer
		if cur.controlCA == "" && p.Cfg.ControlCA != "" {
			cur.controlCA = p.Cfg.ControlCA
		}
		sources[p.Cfg.LoginServer] = cur
	}
	for _, s := range allSharesList {
		if penFilter != "" && !link.PenMatchesQuery(s.Zone, s.Cfg.LoginServer, penFilter) {
			continue
		}
		matchedShares = append(matchedShares, s)
		zonesSeen[s.Zone] = struct{}{}
		cur := sources[s.Cfg.LoginServer]
		cur.baseURL = s.Cfg.LoginServer
		if cur.controlCA == "" && s.Cfg.ControlCA != "" {
			cur.controlCA = s.Cfg.ControlCA
		}
		sources[s.Cfg.LoginServer] = cur
	}

	if len(sources) == 0 {
		if penFilter != "" {
			return nil, link.Errorf("this computer is not on %s", penFilter)
		}
		return nil, link.Errorf("this computer is not on any pen yet. Pass a link or host: hogman update 'https://<host>'")
	}
	if len(zonesSeen) > 1 && penFilter != "" {
		zones := make([]string, 0, len(zonesSeen))
		for z := range zonesSeen {
			zones = append(zones, z)
		}
		sort.Strings(zones)
		return nil, link.Errorf("%q matches more than one pen (%s); pass the full zone name with --pen", penFilter, strings.Join(zones, ", "))
	}
	if len(sources) > 1 {
		zones := make([]string, 0, len(zonesSeen))
		for z := range zonesSeen {
			zones = append(zones, z)
		}
		sort.Strings(zones)
		return nil, link.Errorf("this computer is on more than one pen (%s); pick one with --pen ZONE or pass a server address", strings.Join(zones, ", "))
	}

	var only source
	for _, s := range sources {
		only = s
	}
	baseURL, host, err := ParseSourceURL(only.baseURL)
	if err != nil {
		return nil, link.Errorf("saved server address %q is invalid: %v", only.baseURL, err)
	}
	return &Plan{
		BaseURL:   baseURL,
		Host:      host,
		ControlCA: only.controlCA,
		Pens:      matchedPens,
		Shares:    matchedShares,
	}, nil
}

func PensOutsidePlan(configBase string, inPlan []PenTarget) []string {
	planned := make(map[string]bool, len(inPlan))
	for _, p := range inPlan {
		planned[p.Zone] = true
	}
	var others []string
	for _, p := range LoadPenTargets(configBase) {
		if !planned[p.Zone] {
			others = append(others, p.Zone)
		}
	}
	return others
}

func FindLegacySameServerPens(configBase, newZone, loginServer string) []PenTarget {
	if loginServer == "" {
		return nil
	}
	var out []PenTarget
	for _, p := range LoadPenTargets(configBase) {
		if p.Zone != newZone && p.Cfg.LoginServer == loginServer {
			out = append(out, p)
		}
	}
	return out
}

type LegacyRetireOps struct {
	Stop   func(dir string, c *state.AgentConfig)
	Logout func(dir string)
}

func DefaultLegacyRetireOps() LegacyRetireOps {
	return LegacyRetireOps{
		Stop: platform.StopAgent,
		Logout: func(dir string) {
			if self, err := os.Executable(); err == nil && self != "" {
				_, _ = platform.Run(self, "__agent-logout", dir)
			}
		},
	}
}

func RetireLegacySameServerPens(oldPens []PenTarget, ops LegacyRetireOps, u *ui.UI) {
	if len(oldPens) == 0 {
		return
	}
	for _, old := range oldPens {
		u.Step("Retiring old %s pen setup", old.Zone)
		if ops.Stop != nil {
			ops.Stop(old.Dir, old.Cfg)
		}
		if ops.Logout != nil {
			ops.Logout(old.Dir)
		}
		if err := os.RemoveAll(old.Dir); err != nil {
			u.Note("could not remove old settings folder %s: %v", old.Dir, err)
		}
	}
}
