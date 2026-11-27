package updater

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hogman/join/internal/agent"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/platform"
	"hogman/join/internal/share"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
)

// Options configures `hogman update`.
type Options struct {
	Pen        string
	ControlCA  string
	DryRun     bool
	NoService  bool
	BinaryName string
}

func (o Options) binaryName() string {
	if o.BinaryName != "" {
		return o.BinaryName
	}
	return "hogman"
}

// AgentRunning reports whether this pen's agent process is alive: either its
// local /status endpoint answers for this zone or its recorded agent.pid still
// refers to a live hogman process with a matching start time.
func AgentRunning(dir string, c *state.AgentConfig) bool {
	if _, err := agent.State(c); err == nil {
		return true
	}
	pid, _ := platform.ReadLiveHogmanPID(filepath.Join(dir, "agent.pid"))
	return pid > 0
}

// AgentRunningStaleBinary reports whether p's running agent is executing a
// different binary than wantHex (including older agents that don't report
// bin_sha256 yet), so `hogman update` self-heals stale agents even when the
// on-disk binaries are already up to date.
func AgentRunningStaleBinary(p *PenTarget, wantHex string) bool {
	if p == nil || p.Cfg == nil || wantHex == "" {
		return false
	}
	st, err := agent.State(p.Cfg)
	if err != nil {
		return false
	}
	return !DigestEqualHex(st.BinSHA256, wantHex)
}

type PenOps struct {
	IsRunning      func(dir string, c *state.AgentConfig) bool
	RunningStale   func(p *PenTarget) bool
	HasService     func(zone string) bool
	ProbeReachable func(p *PenTarget, o Options) error
	Stop           func(dir string, c *state.AgentConfig)
	StartNoWait    func(p *PenTarget, binPath string, hadService bool, o Options) error
	RestartNew     func(p *PenTarget, binPath string, hadService bool, o Options) error
	RestartOld     func(p *PenTarget, binPath string, hadService bool, o Options) error
	RewriteService func(binPath, dir string, c *state.AgentConfig) error
}

func DefaultPenOps(u *ui.UI) PenOps {
	return PenOps{
		IsRunning:      AgentRunning,
		HasService:     platform.ServiceConfigured,
		ProbeReachable: ProbePenLoginServer,
		Stop:           platform.StopAgent,
		StartNoWait: func(p *PenTarget, binPath string, hadService bool, o Options) error {
			return platform.StartExistingBinary(binPath, p.Dir, p.Cfg, o.NoService || !hadService, u.Note)
		},
		RestartNew: func(p *PenTarget, binPath string, hadService bool, o Options) error {
			return RestartPenAgent(p, binPath, hadService, o, u)
		},
		RestartOld: func(p *PenTarget, binPath string, hadService bool, o Options) error {
			return RestartOldPenAgent(p, binPath, hadService, o, u)
		},
		RewriteService: platform.RewriteAgentService,
	}
}

// ProbePenLoginServer does a quick (4s) pre-flight check against the pen's
// public control host so `hogman update` doesn't stall for 60s waiting on
// tsnet.Up for a pen that has been deleted, stopped, or put to sleep.
func ProbePenLoginServer(p *PenTarget, o Options) error {
	if p == nil || p.Cfg == nil || strings.TrimSpace(p.Cfg.LoginServer) == "" {
		return errors.New("missing server address")
	}
	baseURL, host, err := ParseSourceURL(p.Cfg.LoginServer)
	if err != nil {
		return err
	}
	c, err := HTTPClient(o.ControlCA, p.Cfg.ControlCA, host, 4*time.Second)
	if err != nil {
		return err
	}
	resp, err := c.Get(baseURL + "/hogman/v1/network")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return fmt.Errorf("pen server returned HTTP 503 (sleeping or stopped)")
	}
	return fmt.Errorf("pen server returned HTTP %d", resp.StatusCode)
}

func RestartPenAgent(p *PenTarget, binPath string, hadService bool, o Options, u *ui.UI) error {
	noService := o.NoService || !hadService
	logPath := filepath.Join(p.Dir, "agent.log")
	if err := platform.StartExistingBinary(binPath, p.Dir, p.Cfg, noService, u.Note); err != nil {
		return link.Errorf("updated %s, but its new agent could not start: %v.\n"+
			"  Log: %s\n"+
			"  To get back on: run 'hogman update' again, or re-run hogman with your link.",
			p.Zone, err, logPath)
	}
	if _, err := agent.WaitUp(p.Cfg, 60*time.Second); err != nil {
		return link.Errorf("updated %s, but its new agent did not come online: %v.\n"+
			"  Log: %s\n"+
			"  To get back on: fix what the log shows and run 'hogman agent %s', or re-run hogman with your link.",
			p.Zone, err, logPath, p.Dir)
	}
	u.Note("%s agent restarted", p.Zone)
	return nil
}

func RestartOldPenAgent(p *PenTarget, binPath string, hadService bool, o Options, u *ui.UI) error {
	noService := o.NoService || !hadService
	if err := platform.StartExistingBinary(binPath, p.Dir, p.Cfg, noService, u.Note); err != nil {
		return err
	}
	_, err := agent.WaitUp(p.Cfg, 30*time.Second)
	return err
}

type ShareOps struct {
	IsRunning      func(dir string) bool
	HasService     func(c *state.ShareConfig) bool
	Stop           func(dir string, c *state.ShareConfig)
	RestartNew     func(s *ShareTargetDir, binPath string, o Options) error
	RestartOld     func(s *ShareTargetDir, binPath string, o Options) error
	RewriteService func(binPath, dir string, c *state.ShareConfig) error
}

func DefaultShareOps(u *ui.UI) ShareOps {
	return ShareOps{
		IsRunning:  func(dir string) bool { return share.PID(dir) != 0 },
		HasService: platform.ShareServiceConfigured,
		Stop:       share.Stop,
		RestartNew: func(s *ShareTargetDir, binPath string, o Options) error {
			return RestartShareService(s, binPath, o, true, u)
		},
		RestartOld: func(s *ShareTargetDir, binPath string, o Options) error {
			return RestartShareService(s, binPath, o, false, u)
		},
		RewriteService: platform.RewriteShareService,
	}
}

func RestartShareService(s *ShareTargetDir, binPath string, o Options, updated bool, u *ui.UI) error {
	_ = os.Remove(filepath.Join(s.Dir, "status.json"))
	fsutil.RemovePIDFile(filepath.Join(s.Dir, "share.pid"))
	managed, pid, err := platform.StartShareServiceWithBinary(binPath, s.Dir, s.Cfg, o.NoService, u.Note)
	if err != nil {
		return err
	}
	// Never pass share.Stop as stopFn during update: a slow reconnect or transient
	// network hiccup must not unregister a previously working share's login service.
	if err := share.WaitBackground(s.Dir, s.Cfg, managed, pid, 90*time.Second, u, nil); err != nil {
		return err
	}
	if updated {
		u.Note("%s share restarted", s.Cfg.FQDN())
	} else {
		u.Note("restarted the previous %s share so it stays online", s.Cfg.FQDN())
	}
	return nil
}

// MigrateAndRestartPen atomically transitions a pen's agent service to
// canonicalBin (rewriting its LaunchAgent/systemd unit and waiting for it to
// come online) and removes any legacy per-pen duplicate copy only after success.
func MigrateAndRestartPen(p *PenTarget, canonicalBin, legacyBin, selfPath string, o Options, ops PenOps, u *ui.UI) error {
	running := ops.IsRunning(p.Dir, p.Cfg)
	hadService := ops.HasService(p.Cfg.Zone)
	interrupted, prevService := state.ReadUpdatingMarker(p.Dir)
	if interrupted {
		running = true
		if prevService {
			hadService = true
		}
	}
	removeLegacy := func() {
		if legacyBin != "" && !fsutil.SameFilePath(legacyBin, selfPath) && !fsutil.SameFilePath(legacyBin, canonicalBin) {
			if _, err := os.Stat(legacyBin); err == nil {
				if err := os.Remove(legacyBin); err == nil {
					u.Note("consolidated %s -> %s", legacyBin, canonicalBin)
				}
			}
		}
	}
	if running {
		if ops.ProbeReachable != nil {
			if perr := ops.ProbeReachable(p, o); perr != nil {
				ops.Stop(p.Dir, p.Cfg)
				state.ClearUpdatingMarker(p.Dir)
				if ops.StartNoWait != nil {
					if serr := ops.StartNoWait(p, canonicalBin, hadService, o); serr != nil {
						return link.Errorf("%s is unreachable (%v), and starting its new agent failed: %v.\n"+
							"  If this pen no longer exists, remove it with: hogman leave %s", p.Zone, perr, serr, p.Zone)
					}
					u.Note("started %s on %s without waiting for it to come online (server unreachable)", p.Zone, canonicalBin)
				} else if hadService && ops.RewriteService != nil {
					if rerr := ops.RewriteService(canonicalBin, p.Dir, p.Cfg); rerr != nil {
						return link.Errorf("%s is unreachable (%v), and updating its login item failed: %v.\n"+
							"  If this pen no longer exists, remove it with: hogman leave %s", p.Zone, perr, rerr, p.Zone)
					}
				}
				removeLegacy()
				return link.Errorf("%s is unreachable (%v); started %s without waiting for it to come online.\n"+
					"  If this pen no longer exists, remove it with: hogman leave %s", p.Zone, perr, canonicalBin, p.Zone)
			}
		}
		u.Step("Restarting %s agent", p.Zone)
		state.WriteUpdatingMarker(p.Dir, hadService)
		ops.Stop(p.Dir, p.Cfg)
		if err := ops.RestartNew(p, canonicalBin, hadService, o); err != nil {
			ops.Stop(p.Dir, p.Cfg)
			if legacyBin != "" && ops.RestartOld != nil {
				if _, serr := os.Stat(legacyBin); serr == nil {
					if rerr := ops.RestartOld(p, legacyBin, hadService, o); rerr == nil {
						state.ClearUpdatingMarker(p.Dir)
						u.Note("restarted the previous %s agent so you stay connected", p.Zone)
					}
				}
			}
			return link.Errorf("%v\n  If this pen no longer exists, remove it with: hogman leave %s", err, p.Zone)
		}
		state.ClearUpdatingMarker(p.Dir)
	} else if hadService && ops.RewriteService != nil {
		if err := ops.RewriteService(canonicalBin, p.Dir, p.Cfg); err != nil {
			return link.Errorf("could not update login item for %s: %v", p.Zone, err)
		}
	}
	removeLegacy()
	return nil
}

type PenMigrationResult struct {
	Zone string
	Err  error
}

// MigratePens migrates every pen in the plan, never stopping on the first pen
// that fails to come up so healthy pens still move to the new binary.
func MigratePens(pens []PenTarget, serviceBin, selfPath string, legacyCopyIn func(string) string, forceAll bool, o Options, ops PenOps, u *ui.UI) []PenMigrationResult {
	results := make([]PenMigrationResult, 0, len(pens))
	for i := range pens {
		p := &pens[i]
		legacy := ""
		if legacyCopyIn != nil {
			legacy = legacyCopyIn(p.Dir)
		}
		interrupted, _ := state.ReadUpdatingMarker(p.Dir)
		stale := ops.RunningStale != nil && ops.RunningStale(p)
		if !forceAll && legacy == "" && !interrupted && !stale {
			continue
		}
		err := MigrateAndRestartPen(p, serviceBin, legacy, selfPath, o, ops, u)
		if err != nil {
			u.Note("✗ %s: %v", p.Zone, err)
		} else {
			u.Note("✓ %s migrated to %s", p.Zone, serviceBin)
		}
		results = append(results, PenMigrationResult{Zone: p.Zone, Err: err})
	}
	return results
}

// MigrateAndRestartShare atomically transitions a managed share to canonicalBin
// and removes any legacy per-share duplicate copy only after it is healthy.
func MigrateAndRestartShare(s *ShareTargetDir, canonicalBin, legacyBin, selfPath string, o Options, ops ShareOps, u *ui.UI) error {
	running := ops.IsRunning(s.Dir)
	managed := ops.HasService(s.Cfg)
	interrupted, prevManaged := state.ReadUpdatingMarker(s.Dir)
	if interrupted && prevManaged {
		running = true
		managed = true
	}
	if running && managed {
		u.Step("Restarting %s share", s.Cfg.FQDN())
		state.WriteUpdatingMarker(s.Dir, true)
		ops.Stop(s.Dir, s.Cfg)
		if err := ops.RestartNew(s, canonicalBin, o); err != nil {
			ops.Stop(s.Dir, s.Cfg)
			if legacyBin != "" && ops.RestartOld != nil {
				if _, serr := os.Stat(legacyBin); serr == nil {
					if rerr := ops.RestartOld(s, legacyBin, o); rerr == nil {
						state.ClearUpdatingMarker(s.Dir)
					}
				}
			}
			return link.Errorf("updated share binary, but restarting %s failed (%v).\n"+
				"  To bring it back up: hogman share %s %s",
				s.Cfg.FQDN(), err, s.Cfg.Name, s.Cfg.Target)
		}
		state.ClearUpdatingMarker(s.Dir)
	} else if running {
		u.Note("share %s is still running the previous process; restart it when ready", s.Cfg.URL())
		return nil
	} else if managed && ops.RewriteService != nil {
		if err := ops.RewriteService(canonicalBin, s.Dir, s.Cfg); err != nil {
			return link.Errorf("could not update login item for share %s: %v", s.Cfg.FQDN(), err)
		}
	}
	if legacyBin != "" && !fsutil.SameFilePath(legacyBin, selfPath) && !fsutil.SameFilePath(legacyBin, canonicalBin) {
		if _, err := os.Stat(legacyBin); err == nil {
			if err := os.Remove(legacyBin); err == nil {
				u.Note("consolidated %s -> %s", legacyBin, canonicalBin)
			}
		}
	}
	return nil
}
