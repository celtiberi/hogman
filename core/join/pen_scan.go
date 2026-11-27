package main

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type installedPen struct {
	Zone   string
	Dir    string
	Config *agentConfig
}

type penScanResult struct {
	Pens    []installedPen
	Corrupt []string
}

// scanInstalledPens enumerates pen state directories under configBase in one
// pass, enforcing that each directory basename matches config.json's canonical
// zone and is a valid DNS zone name. Unreadable or mismatched config.json
// directories are reported in Corrupt so doctor/status can surface them.
func scanInstalledPens(configBase string) penScanResult {
	entries, err := os.ReadDir(configBase)
	if err != nil {
		return penScanResult{}
	}
	var res penScanResult
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		name := ent.Name()
		if name == "bin" || name == "shares" || strings.HasPrefix(name, ".") {
			continue
		}
		dir := filepath.Join(configBase, name)
		cfg, err := loadAgentConfig(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			res.Corrupt = append(res.Corrupt, name)
			continue
		}
		if cfg.Zone == "" || cfg.Zone != name || !validPACZone(cfg.Zone) {
			res.Corrupt = append(res.Corrupt, name)
			continue
		}
		res.Pens = append(res.Pens, installedPen{
			Zone:   cfg.Zone,
			Dir:    dir,
			Config: cfg,
		})
	}
	sort.Slice(res.Pens, func(i, j int) bool { return res.Pens[i].Zone < res.Pens[j].Zone })
	sort.Strings(res.Corrupt)
	return res
}
