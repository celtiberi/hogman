package platform

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
)

var verbose atomic.Bool

// SetVerbose toggles verbose command logging for Run.
func SetVerbose(v bool) { verbose.Store(v) }

// Verbose reports whether verbose command logging is enabled.
func Verbose() bool { return verbose.Load() }

func emitNote(note func(string, ...any), f string, a ...any) {
	if note != nil {
		note(f, a...)
	}
}

// RedactCommandArgs hides secret flag values (such as Tailscale --authkey)
// before logging a command line under --verbose.
func RedactCommandArgs(args []string) []string {
	out := make([]string, len(args))
	redactNext := false
	for i, a := range args {
		if redactNext {
			out[i] = "[redacted]"
			redactNext = false
			continue
		}
		lower := strings.ToLower(a)
		if lower == "--authkey" || lower == "-authkey" {
			out[i] = a
			redactNext = true
			continue
		}
		if eq := strings.IndexByte(lower, '='); eq > 0 {
			flag := lower[:eq]
			if flag == "--authkey" || flag == "-authkey" {
				out[i] = a[:eq+1] + "[redacted]"
				continue
			}
		}
		out[i] = a
	}
	return out
}

// Run executes a command unprivileged, returning trimmed combined output.
// Hogman never invokes sudo or prompts for the computer's administrator
// password (D-41).
func Run(name string, args ...string) (string, error) {
	if verbose.Load() {
		fmt.Fprintf(os.Stderr, "  $ %s %s\n", name, strings.Join(RedactCommandArgs(args), " "))
	}
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}
