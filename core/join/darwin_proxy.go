package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// darwinProxyAppleScript is a compile-time constant AppleScript invoked via
// `/usr/bin/osascript -e <script> -- <prompt> <op> ...`. Every runtime value
// (prompt, network service name, PAC URL) is passed as an explicit argv item
// and quoted with AppleScript's `quoted form of` — never interpolated into the
// script source.
const darwinProxyAppleScript = `on run argv
	set promptText to item 1 of argv
	set cmd to ""
	set i to 2
	set n to count of argv
	repeat while i <= n
		set op to item i of argv
		if op is "set" then
			set svc to item (i + 1) of argv
			set u to item (i + 2) of argv
			set part to "/usr/sbin/networksetup -setautoproxyurl " & quoted form of svc & " " & quoted form of u
			set i to i + 3
		else if op is "off" then
			set svc to item (i + 1) of argv
			set part to "/usr/sbin/networksetup -setautoproxystate " & quoted form of svc & " off"
			set i to i + 2
		else
			error "unknown proxy op"
		end if
		if cmd is "" then
			set cmd to part
		else
			set cmd to cmd & " && " & part
		end if
	end repeat
	if cmd is "" then
		return ""
	end if
	do shell script cmd with prompt promptText with administrator privileges
end run`

type darwinProxyOp struct {
	Action  string // "set" or "off"
	Service string
	URL     string // required for "set", must be empty for "off"
}

func validateDarwinProxyOp(op darwinProxyOp) error {
	if op.Service == "" || strings.ContainsAny(op.Service, "\x00\r\n") {
		return fmt.Errorf("invalid network service name %q", op.Service)
	}
	switch op.Action {
	case "set":
		if op.URL == "" || strings.ContainsAny(op.URL, "\x00\r\n \t") {
			return fmt.Errorf("invalid PAC URL %q", op.URL)
		}
		u, err := url.Parse(op.URL)
		if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "/proxy.pac" || u.User != nil {
			return fmt.Errorf("invalid local PAC URL %q", op.URL)
		}
		return nil
	case "off":
		if op.URL != "" {
			return fmt.Errorf("off op must not include a URL")
		}
		return nil
	default:
		return fmt.Errorf("unknown proxy action %q", op.Action)
	}
}

// buildDarwinOsascriptArgs validates all ops and returns the argv slice for
// `/usr/bin/osascript`. All dynamic values follow `--` as separate arguments.
func buildDarwinOsascriptArgs(prompt string, ops []darwinProxyOp) ([]string, error) {
	if prompt == "" || strings.ContainsAny(prompt, "\x00\r\n") {
		return nil, errors.New("invalid macOS admin dialog prompt")
	}
	if len(ops) == 0 {
		return nil, errors.New("no proxy operations to apply")
	}
	args := make([]string, 0, 4+len(ops)*3)
	args = append(args, "-e", darwinProxyAppleScript, "--", prompt)
	for _, op := range ops {
		if err := validateDarwinProxyOp(op); err != nil {
			return nil, err
		}
		args = append(args, op.Action, op.Service)
		if op.Action == "set" {
			args = append(args, op.URL)
		}
	}
	return args, nil
}

func isDarwinDialogCanceled(out string, err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(out + " " + err.Error())
	return strings.Contains(low, "(-128)") || strings.Contains(low, "user canceled") || strings.Contains(low, "user cancelled")
}

func buildDarwinSudoPrompt(why string) string {
	// sudo -p expands %-escapes (%u, %h, etc.), so escape any literal %.
	clean := strings.ReplaceAll(strings.TrimSpace(why), "%", "%%")
	clean = strings.TrimPrefix(clean, "to ")
	if clean == "" {
		return "Mac login password (nothing shows as you type): "
	}
	return fmt.Sprintf("Mac login password (lets Hogman %s; nothing shows as you type): ", clean)
}

type darwinProxyRunner struct {
	isRoot          func() bool
	sudoCached      func() bool
	hasGUI          func() bool
	stdinTTY        func() bool
	runOsascript    func(args []string) (string, error)
	runSudoAuth     func(sudoPrompt string) error
	runNetworksetup func(useSudo bool, args ...string) (string, error)
	note            func(format string, args ...any)
}

func runDarwinNetworksetupOps(ops []darwinProxyOp, useSudo bool, runNS func(useSudo bool, args ...string) (string, error)) error {
	for _, op := range ops {
		var args []string
		switch op.Action {
		case "set":
			args = []string{"-setautoproxyurl", op.Service, op.URL}
		case "off":
			args = []string{"-setautoproxystate", op.Service, "off"}
		default:
			return fmt.Errorf("unknown proxy action %q", op.Action)
		}
		if out, err := runNS(useSudo, args...); err != nil {
			msg := firstLine(out)
			if msg == "" {
				msg = err.Error()
			}
			return fmt.Errorf("%s (%s)", msg, op.Service)
		}
	}
	return nil
}

// applyDarwinProxyOps executes a batch of macOS automatic-proxy changes in one
// privileged step (D-40 / I-26):
//  1. Already root or cached sudo timestamp -> runs directly with no prompt.
//  2. Active macOS GUI session -> single native administrator dialog via
//     /usr/bin/osascript with static AppleScript and explicit argv.
//  3. No GUI session (SSH, headless) or non-cancel dialog error -> falls back
//     to terminal `sudo -v` with explicit password/no-echo guidance and
//     immediate confirmation once accepted.
//  4. Explicit dialog cancel -> returns a clear error immediately (non-zero,
//     never hangs).
func applyDarwinProxyOps(prompt, why string, ops []darwinProxyOp, r darwinProxyRunner) error {
	if len(ops) == 0 {
		return nil
	}
	osascriptArgs, err := buildDarwinOsascriptArgs(prompt, ops)
	if err != nil {
		return err
	}
	logNote := r.note
	if logNote == nil {
		logNote = func(string, ...any) {}
	}

	if r.isRoot != nil && r.isRoot() {
		return runDarwinNetworksetupOps(ops, false, r.runNetworksetup)
	}
	if r.sudoCached != nil && r.sudoCached() {
		return runDarwinNetworksetupOps(ops, true, r.runNetworksetup)
	}

	if r.hasGUI != nil && r.hasGUI() && r.runOsascript != nil {
		logNote("A macOS password prompt will open %s. Enter your Mac login password (or use Touch ID) — it goes to macOS, not to Hogman.", why)
		out, oerr := r.runOsascript(osascriptArgs)
		if oerr == nil {
			logNote("Got it — updated this Mac's automatic proxy setting.")
			return nil
		}
		if isDarwinDialogCanceled(out, oerr) {
			return errors.New("password prompt cancelled — automatic proxy was not changed")
		}
		// Non-cancel dialog error (e.g. headless / no user interaction allowed):
		// fall back to terminal sudo with clear guidance.
		logNote("macOS password dialog was unavailable (%s); falling back to Terminal password prompt.", firstLine(out))
	}

	if r.stdinTTY != nil && !r.stdinTTY() {
		return errors.New("no interactive terminal available for password prompt — automatic proxy was not changed")
	}
	logNote("Your Mac login password is needed %s. It goes to macOS, not to Hogman.", why)
	logNote("Nothing shows on screen as you type — that's normal in Terminal. Press Enter when done.")
	if r.runSudoAuth != nil {
		if err := r.runSudoAuth(buildDarwinSudoPrompt(why)); err != nil {
			return errors.New("password prompt cancelled or failed — automatic proxy was not changed")
		}
	}
	logNote("Got it, updating this Mac's automatic proxy setting…")
	return runDarwinNetworksetupOps(ops, true, r.runNetworksetup)
}
