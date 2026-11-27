package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"hogman/join/internal/fsutil"
	"hogman/join/internal/state"
)

var knownHogmanBinaryNames = map[string]bool{
	"hogman":                   true,
	"hogman.exe":               true,
	"hogman-join":              true,
	"hogman-join.exe":          true,
	"hogman-darwin-arm64":      true,
	"hogman-darwin-x86_64":     true,
	"hogman-linux-x86_64":      true,
	"hogman-linux-aarch64":     true,
	"hogman-windows-amd64.exe": true,
	"hogman-windows-arm64.exe": true,
}

func cleanResolvedPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// Linux /proc/<pid>/exe appends " (deleted)" when a running binary was replaced.
	p = strings.TrimSuffix(p, " (deleted)")
	if realPath, err := filepath.EvalSymlinks(p); err == nil {
		p = realPath
	}
	return filepath.Clean(p)
}

func sameExePath(a, b string, caseInsensitive bool) bool {
	if a == "" || b == "" {
		return false
	}
	if caseInsensitive {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// ExeMatchesHogman reports whether gotExe belongs to our hogman executable
// (matching wantExe, canonicalBin, a replaced .old binary during Windows
// self-update, or a known hogman / legacy hogman-join release binary name).
func ExeMatchesHogman(gotExe, wantExe, canonicalBin string) bool {
	return exeMatchesHogmanForOS(gotExe, wantExe, canonicalBin, runtime.GOOS)
}

func exeMatchesHogmanForOS(gotExe, wantExe, canonicalBin, goos string) bool {
	got := cleanResolvedPath(gotExe)
	if got == "" {
		return false
	}
	ci := goos == "windows"
	gotBaseTrim := got
	if ci && strings.HasSuffix(strings.ToLower(gotBaseTrim), ".old") {
		gotBaseTrim = gotBaseTrim[:len(gotBaseTrim)-len(".old")]
	}
	for _, want := range []string{wantExe, canonicalBin} {
		w := cleanResolvedPath(want)
		if w == "" {
			continue
		}
		if sameExePath(got, w, ci) || (ci && sameExePath(gotBaseTrim, w, ci)) {
			return true
		}
	}
	// Extract filename using either separator so cross-OS unit tests work reliably.
	base := gotBaseTrim
	if idx := strings.LastIndexAny(base, `/\`); idx >= 0 {
		base = base[idx+1:]
	}
	return knownHogmanBinaryNames[strings.ToLower(base)]
}

// ProcessIsHogman reports whether pid refers to a live, accessible process
// running our hogman binary (or legacy hogman-join during migration).
// Access-denied, exited, zombie, or unrelated processes always return false.
func ProcessIsHogman(pid int, wantExe string) bool {
	if pid <= 0 {
		return false
	}
	gotExe, ok := processExePath(pid)
	if !ok || gotExe == "" {
		return false
	}
	if wantExe == "" {
		wantExe, _ = fsutil.ResolvedExePath()
	}
	canonicalBin := state.CanonicalBinaryPath(state.ConfigBase())
	return ExeMatchesHogman(gotExe, wantExe, canonicalBin)
}

// ProcessMatchesPIDRecord verifies that pid is a live hogman process and, when
// startTag is present, matches the recorded OS process start time (blocking
// cross-pen/cross-share PID reuse after reboot).
func ProcessMatchesPIDRecord(pid int, startTag, wantExe string) bool {
	if !ProcessIsHogman(pid, wantExe) {
		return false
	}
	if startTag != "" {
		gotTag := fsutil.ProcessStartTag(pid)
		if gotTag == "" || gotTag != startTag {
			return false
		}
	}
	return true
}

// ReadLiveHogmanPID inspects a PID file (agent.pid or share.pid) and returns
// (pid, false) only when the recorded PID is still a live hogman process with a
// matching start time. If the file exists but is corrupt, exited, inaccessible,
// or now belongs to another process, it returns (0, true).
func ReadLiveHogmanPID(path string) (pid int, stale bool) {
	if _, err := os.Stat(path); err != nil {
		return 0, false
	}
	n, startTag, ok := fsutil.ReadPIDFile(path)
	if !ok {
		return 0, true
	}
	if !ProcessMatchesPIDRecord(n, startTag, "") {
		return 0, true
	}
	return n, false
}

// StopPIDFile stops the live hogman process recorded in pidPath (verifying
// both executable identity and recorded start time) and removes pidPath. If
// pidPath exists but is stale or belongs to an unrelated process, it logs and
// removes the file without signalling any process.
func StopPIDFile(pidPath string, termTimeout time.Duration) {
	if _, err := os.Stat(pidPath); err != nil {
		return
	}
	pid, startTag, ok := fsutil.ReadPIDFile(pidPath)
	if ok && ProcessMatchesPIDRecord(pid, startTag, "") {
		StopProcessVerified(pid, startTag, termTimeout)
		_ = os.Remove(pidPath)
		return
	}
	fsutil.DaemonLogger().Info("stale pid file removed", "path", pidPath)
	_ = os.Remove(pidPath)
}
