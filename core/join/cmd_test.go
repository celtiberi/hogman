package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"hogman/join/internal/platform"
	"hogman/join/internal/state"
)

// extractPlistProgramArgs parses a generated macOS LaunchAgent plist and returns
// the exact ProgramArguments slice (excluding argv[0], the binary path).
func extractPlistProgramArgs(t *testing.T, plistXML string) []string {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(plistXML))
	inKey := false
	wantArray := false
	inArray := false
	var args []string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch el := tok.(type) {
		case xml.StartElement:
			switch el.Name.Local {
			case "key":
				inKey = true
			case "array":
				if wantArray {
					inArray = true
					wantArray = false
				}
			case "string":
				if inArray {
					var s string
					if err := dec.DecodeElement(&s, &el); err != nil {
						t.Fatal(err)
					}
					args = append(args, s)
				}
			}
		case xml.EndElement:
			if el.Name.Local == "key" {
				inKey = false
			}
			if el.Name.Local == "array" && inArray {
				inArray = false
			}
		case xml.CharData:
			if inKey && strings.TrimSpace(string(el)) == "ProgramArguments" {
				wantArray = true
			}
		}
	}
	if len(args) < 2 {
		t.Fatalf("failed to extract ProgramArguments from plist:\n%s", plistXML)
	}
	return args[1:]
}

// extractSystemdExecStartArgs extracts argv (excluding argv[0]) from a rendered
// systemd unit's ExecStart= line using systemd's double-quoted token format.
func extractSystemdExecStartArgs(t *testing.T, unit string) []string {
	t.Helper()
	for _, line := range strings.Split(unit, "\n") {
		rest, ok := strings.CutPrefix(line, "ExecStart=")
		if !ok {
			continue
		}
		var tokens []string
		for len(rest) > 0 {
			rest = strings.TrimLeft(rest, " ")
			if rest == "" {
				break
			}
			if rest[0] == '"' {
				rest = rest[1:]
				var b strings.Builder
				for i := 0; i < len(rest); i++ {
					if rest[i] == '\\' && i+1 < len(rest) {
						i++
						b.WriteByte(rest[i])
						continue
					}
					if rest[i] == '"' {
						rest = rest[i+1:]
						break
					}
					b.WriteByte(rest[i])
				}
				tokens = append(tokens, b.String())
			} else {
				sp := strings.IndexByte(rest, ' ')
				if sp < 0 {
					tokens = append(tokens, rest)
					rest = ""
				} else {
					tokens = append(tokens, rest[:sp])
					rest = rest[sp+1:]
				}
			}
		}
		if len(tokens) < 2 {
			t.Fatalf("unexpected ExecStart tokens %v from %q", tokens, line)
		}
		return tokens[1:]
	}
	t.Fatalf("no ExecStart= line in unit:\n%s", unit)
	return nil
}

// Golden compatibility test: already-installed macOS LaunchAgents, Linux
// systemd units, and internal logout invocations must keep routing byte-for-byte.
func TestCLIInstalledServiceGoldenCommands(t *testing.T) {
	agentDir := "/tmp/hogman state/bobo.pens.example.com"
	shareDirPath := "/tmp/hogman shares/bobo.pens.example.com/blog"
	bin := "/tmp/hogman bin/hogman"
	sc := &state.ShareConfig{Name: "blog", Zone: "bobo.pens.example.com"}

	agentPlist, err := platform.RenderLaunchPlist(platform.LaunchLabel("bobo.pens.example.com"), bin, agentDir, filepath.Join(agentDir, "agent.log"))
	if err != nil {
		t.Fatal(err)
	}
	sharePlist, err := platform.RenderShareLaunchPlist(sc, bin, shareDirPath)
	if err != nil {
		t.Fatal(err)
	}
	agentUnit := platform.RenderSystemdUnit("bobo.pens.example.com", bin, agentDir)
	shareUnit := platform.RenderShareSystemdUnit(sc, bin, shareDirPath)

	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"darwin agent plist", extractPlistProgramArgs(t, agentPlist), "agent:" + agentDir},
		{"linux agent unit", extractSystemdExecStartArgs(t, agentUnit), "agent:" + agentDir},
		{"darwin share plist", extractPlistProgramArgs(t, sharePlist), "share-run:" + shareDirPath},
		{"linux share unit", extractSystemdExecStartArgs(t, shareUnit), "share-run:" + shareDirPath},
		{"internal agent logout", []string{"__agent-logout", agentDir}, "logout:" + agentDir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			rc := runCLI(tc.argv, cliHandlers{
				agent:       func(dir string) error { got = "agent:" + dir; return nil },
				shareRun:    func(dir string) error { got = "share-run:" + dir; return nil },
				agentLogout: func(dir string) { got = "logout:" + dir },
			})
			if rc != 0 || got != tc.want {
				t.Fatalf("argv=%v -> rc=%d got=%q, want %q", tc.argv, rc, got, tc.want)
			}
		})
	}
}

// Golden tests for interspersed flag ordering across existing user habits.
func TestCLIInterspersedFlagsGolden(t *testing.T) {
	link := "https://bobo.gate.example.com/join#t=abc"
	t.Run("link before --no-open", func(t *testing.T) {
		var gotRaw string
		var gotO options
		rc := runCLI([]string{link, "--no-open", "--handle", "alice", "--dry-run"}, cliHandlers{
			join: func(raw string, o options) error { gotRaw, gotO = raw, o; return nil },
		})
		if rc != 0 || gotRaw != link || !gotO.noOpen || gotO.handle != "alice" || !gotO.dryRun {
			t.Fatalf("rc=%d raw=%q o=%+v", rc, gotRaw, gotO)
		}
	})
	t.Run("share flags after positional args", func(t *testing.T) {
		var gotName, gotTarget string
		var gotO options
		rc := runCLI([]string{"share", "x", "3000", "--background", "--pen", "bobo", "--note", "demo"}, cliHandlers{
			shareStart: func(name, target, _ string, o options) error { gotName, gotTarget, gotO = name, target, o; return nil },
		})
		if rc != 0 || gotName != "x" || gotTarget != "3000" || !gotO.background || gotO.pen != "bobo" || gotO.note != "demo" || !gotO.noteSet {
			t.Fatalf("rc=%d name=%q target=%q o=%+v", rc, gotName, gotTarget, gotO)
		}
	})
	t.Run("leave --force before and after pen", func(t *testing.T) {
		for _, argv := range [][]string{
			{"leave", "--force", "bobo"},
			{"leave", "bobo", "--force"},
			{"--no-open", "leave", "bobo", "--force"},
		} {
			var gotArgs []string
			var gotO options
			rc := runCLI(argv, cliHandlers{
				leave: func(args []string, o options) error { gotArgs, gotO = args, o; return nil },
			})
			if rc != 0 || len(gotArgs) != 1 || gotArgs[0] != "bobo" || !gotO.force {
				t.Fatalf("argv=%v -> rc=%d args=%v o=%+v", argv, rc, gotArgs, gotO)
			}
		}
	})
	t.Run("completion prints to stdout for all shells", func(t *testing.T) {
		for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
			var out, errOut bytes.Buffer
			rc := runCLI([]string{"completion", sh}, cliHandlers{out: &out, errOut: &errOut})
			if rc != 0 || out.Len() == 0 {
				t.Fatalf("completion %s: rc=%d len=%d err=%q", sh, rc, out.Len(), errOut.String())
			}
		}
	})
}

func TestCLIJoinInteractivePasteAndStdin(t *testing.T) {
	oldTTY, oldAsk := isTerminalFn, askFn
	t.Cleanup(func() { isTerminalFn, askFn = oldTTY, oldAsk })

	// Interactive TTY prompt when running `hogman join` with 0 args.
	isTerminalFn = func() bool { return true }
	askFn = func(prompt string) string {
		if !strings.Contains(prompt, "Paste your join link") {
			t.Errorf("unexpected prompt: %q", prompt)
		}
		return "https://bobo.gate.example.com/join#t=pasted"
	}
	var gotRaw string
	rc := runCLI([]string{"join", "--dry-run"}, cliHandlers{
		join: func(raw string, o options) error { gotRaw = raw; return nil },
	})
	if rc != 0 || gotRaw != "https://bobo.gate.example.com/join#t=pasted" {
		t.Fatalf("interactive join: rc=%d raw=%q", rc, gotRaw)
	}

	// Non-TTY with 0 args refuses with usage exit 2 and --link-stdin hint.
	isTerminalFn = func() bool { return false }
	var errOut bytes.Buffer
	rc = runCLI([]string{"join"}, cliHandlers{
		errOut: &errOut,
		join:   func(string, options) error { t.Fatal("join should not run"); return nil },
	})
	if rc != 2 || !strings.Contains(errOut.String(), "--link-stdin") {
		t.Fatalf("non-tty join: rc=%d err=%q", rc, errOut.String())
	}

	// --link-stdin reads from io.Reader cleanly.
	got, err := readJoinLinkInteractive(options{linkStdin: true}, strings.NewReader("  https://bobo.gate.example.com/join#k=xyz\n"))
	if err != nil || got != "https://bobo.gate.example.com/join#k=xyz" {
		t.Fatalf("readJoinLinkInteractive(--link-stdin) = (%q, %v)", got, err)
	}
}

func TestUnifiedPenResolver(t *testing.T) {
	oldTTY, oldAsk := isTerminalFn, askFn
	t.Cleanup(func() { isTerminalFn, askFn = oldTTY, oldAsk })
	isTerminalFn = func() bool { return false }

	pens := []penConn{
		{zone: "alpha.pens.example.com", loginServer: "https://alpha.gate.example.com"},
		{zone: "beta.pens.example.com", loginServer: "https://beta.gate.example.com"},
	}

	// Short name, full zone, and control host all resolve cleanly.
	for _, q := range []string{"alpha", "alpha.pens.example.com", "alpha.gate.example.com"} {
		p, err := resolvePenConn(pens, q)
		if err != nil || p.zone != "alpha.pens.example.com" {
			t.Fatalf("resolvePenConn(%q) = (%+v, %v)", q, p, err)
		}
	}

	// Partial prefix must NOT match.
	if _, err := resolvePenConn(pens, "alp"); err == nil {
		t.Fatal("partial prefix 'alp' must not match 'alpha'")
	}

	// HOGMAN_PEN env var works when --pen is empty, and --pen overrides HOGMAN_PEN.
	t.Setenv("HOGMAN_PEN", "beta")
	p, err := resolvePenConn(pens, "")
	if err != nil || p.zone != "beta.pens.example.com" {
		t.Fatalf("HOGMAN_PEN=beta -> (%+v, %v)", p, err)
	}
	p, err = resolvePenConn(pens, "alpha")
	if err != nil || p.zone != "alpha.pens.example.com" {
		t.Fatalf("--pen alpha over HOGMAN_PEN=beta -> (%+v, %v)", p, err)
	}
	t.Setenv("HOGMAN_PEN", "")

	// Ambiguous short name across two servers is refused with both full zones named.
	ambig := []penConn{
		{zone: "home.pens.a.example", loginServer: "https://home.gate.a.example"},
		{zone: "home.pens.b.example", loginServer: "https://home.gate.b.example"},
	}
	_, err = resolvePenConn(ambig, "home")
	if err == nil || !strings.Contains(err.Error(), "home.pens.a.example") || !strings.Contains(err.Error(), "home.pens.b.example") {
		t.Fatalf("ambiguous short name err = %v", err)
	}

	// 2+ pens on non-TTY refuses clearly mentioning --pen and HOGMAN_PEN.
	if _, err := resolvePenConn(pens, ""); err == nil || !strings.Contains(err.Error(), "HOGMAN_PEN") {
		t.Fatalf("non-tty multi-pen err = %v", err)
	}

	// 2+ pens on TTY opens numbered picker and selects chosen pen.
	isTerminalFn = func() bool { return true }
	askFn = func(string) string { return "2" }
	p, err = resolvePenConn(pens, "")
	if err != nil || p.zone != "beta.pens.example.com" {
		t.Fatalf("TTY picker choice 2 -> (%+v, %v)", p, err)
	}
	askFn = func(string) string { return "99" }
	if _, err := resolvePenConn(pens, ""); err == nil {
		t.Fatal("out-of-range TTY choice should error")
	}

	// `update --pen <short>` also supports short-name resolution and rejects ambiguous short names.
	root := t.TempDir()
	cfgBase := filepath.Join(root, "hogman")
	for _, z := range []struct{ zone, ls string }{
		{"work.pens.a.example", "https://work.gate.a.example"},
		{"work.pens.b.example", "https://work.gate.b.example"},
		{"solo.pens.a.example", "https://solo.gate.a.example"},
	} {
		d := filepath.Join(cfgBase, z.zone)
		_ = os.MkdirAll(d, 0o700)
		_ = (&state.AgentConfig{Zone: z.zone, LoginServer: z.ls}).Save(d)
	}
	plan, err := resolveUpdatePlan(nil, options{pen: "solo"}, cfgBase, filepath.Join(root, "shares"))
	if err != nil || plan.baseURL != "https://solo.gate.a.example" {
		t.Fatalf("update --pen solo: (%+v, %v)", plan, err)
	}
	if _, err := resolveUpdatePlan(nil, options{pen: "work"}, cfgBase, filepath.Join(root, "shares")); err == nil || !strings.Contains(err.Error(), "work.pens.a.example") {
		t.Fatalf("update --pen ambiguous work: %v", err)
	}
}

func TestSingleDashLongFlagsGolden(t *testing.T) {
	t.Run("legacy single-dash flags on join", func(t *testing.T) {
		var gotLink string
		var gotO options
		var out, errBuf bytes.Buffer
		h := cliHandlers{
			out:    &out,
			errOut: &errBuf,
			join:   func(raw string, o options) error { gotLink, gotO = raw, o; return nil },
		}
		rc := runCLI([]string{"-no-open", "-yes", "-dry-run", "-handle", "alice", "https://h.example/join#t=abc"}, h)
		if rc != 0 || gotLink != "https://h.example/join#t=abc" || !gotO.noOpen || !gotO.yes || !gotO.dryRun || gotO.handle != "alice" {
			t.Fatalf("rc=%d link=%q o=%+v err=%s", rc, gotLink, gotO, errBuf.String())
		}
	})

	t.Run("legacy single-dash equals form and subcommand flags", func(t *testing.T) {
		var gotPen string
		var gotForce bool
		var gotName string
		var errBuf bytes.Buffer
		h := cliHandlers{
			errOut: &errBuf,
			shareStop: func(name string, o options) error {
				gotName, gotPen, gotForce = name, o.pen, o.force
				return nil
			},
		}
		rc := runCLI([]string{"share", "stop", "blog", "-force", "-pen=bobo"}, h)
		if rc != 0 || gotName != "blog" || !gotForce || gotPen != "bobo" {
			t.Fatalf("rc=%d name=%q force=%v pen=%q err=%s", rc, gotName, gotForce, gotPen, errBuf.String())
		}
	})

	t.Run("legacy -version and -help", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if rc := runCLI([]string{"-version"}, cliHandlers{out: &out, errOut: &errBuf}); rc != 0 || !strings.Contains(out.String(), "hogman ") {
			t.Fatalf("-version: rc=%d out=%q err=%q", rc, out.String(), errBuf.String())
		}
		out.Reset()
		errBuf.Reset()
		if rc := runCLI([]string{"-help"}, cliHandlers{out: &out, errOut: &errBuf}); rc != 0 || !strings.Contains(out.String(), "Usage:") {
			t.Fatalf("-help: rc=%d out=%q err=%q", rc, out.String(), errBuf.String())
		}
	})

	t.Run("unknown single-dash flag still fails closed", func(t *testing.T) {
		var errBuf bytes.Buffer
		if rc := runCLI([]string{"-bogus"}, cliHandlers{errOut: &errBuf}); rc != 2 {
			t.Fatalf("unknown -bogus: rc=%d want 2 (err=%s)", rc, errBuf.String())
		}
	})

	t.Run("args after -- and flag values are not rewritten", func(t *testing.T) {
		var gotNote string
		var errBuf bytes.Buffer
		h := cliHandlers{
			errOut: &errBuf,
			shareStart: func(_, _, _ string, o options) error {
				gotNote = o.note
				return nil
			},
		}
		if rc := runCLI([]string{"share", "blog", "3000", "--note", "-yes"}, h); rc != 0 || gotNote != "-yes" {
			t.Fatalf("--note -yes: rc=%d note=%q err=%s", rc, gotNote, errBuf.String())
		}
		var gotLeave []string
		h2 := cliHandlers{
			errOut: &errBuf,
			leave:  func(args []string, _ options) error { gotLeave = args; return nil },
		}
		if rc := runCLI([]string{"leave", "--", "-no-open"}, h2); rc != 0 || len(gotLeave) != 1 || gotLeave[0] != "-no-open" {
			t.Fatalf("leave -- -no-open: rc=%d args=%v", rc, gotLeave)
		}
	})
}

func TestPenQueryValidationAndEnvNotice(t *testing.T) {
	pens := []penConn{
		{zone: "alpha.pens.example.com", loginServer: "https://alpha.gate.example.com"},
		{zone: "beta.pens.example.com", loginServer: "https://beta.gate.example.com"},
	}

	// Wildcards and path traversals must be rejected before any globbing.
	for _, bad := range []string{"*", "../..", "foo/bar", "a?b", "[a-z]", "bad pen", "..", "-leading"} {
		if _, err := resolvePenConn(pens, bad); err == nil {
			t.Errorf("resolvePenConn(%q) succeeded, want validation error", bad)
		}
		if _, err := resolveShareZoneFilter(nil, bad); err == nil {
			t.Errorf("resolveShareZoneFilter(%q) succeeded, want validation error", bad)
		}
		if _, err := resolveUpdatePlan(nil, options{pen: bad}, t.TempDir(), t.TempDir()); err == nil {
			t.Errorf("resolveUpdatePlan(--pen %q) succeeded, want validation error", bad)
		}
	}

	// HOGMAN_PEN with invalid traversal value is also rejected.
	t.Setenv("HOGMAN_PEN", "../..")
	if _, err := resolveShareZoneFilter(nil, ""); err == nil {
		t.Fatal("HOGMAN_PEN=../.. should fail validation")
	}

	// HOGMAN_PEN prints an explicit notice whenever it makes the choice.
	var notices []string
	oldNote := noteFn
	t.Cleanup(func() { noteFn = oldNote })
	noteFn = func(f string, a ...any) { notices = append(notices, fmt.Sprintf(f, a...)) }

	t.Setenv("HOGMAN_PEN", "beta")
	p, err := resolvePenConn(pens, "")
	if err != nil || p.zone != "beta.pens.example.com" {
		t.Fatalf("resolvePenConn with HOGMAN_PEN=beta: (%+v, %v)", p, err)
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "using pen beta.pens.example.com (from HOGMAN_PEN)") {
		t.Fatalf("expected HOGMAN_PEN notice, got %v", notices)
	}

	// Explicit --pen overrides HOGMAN_PEN and does not print the env notice.
	notices = nil
	if _, err := resolvePenConn(pens, "alpha"); err != nil {
		t.Fatalf("explicit --pen alpha failed: %v", err)
	}
	if len(notices) != 0 {
		t.Fatalf("explicit --pen should not print HOGMAN_PEN notice, got %v", notices)
	}
}

func TestLinkStdinWithArgErrorsAndDefaults(t *testing.T) {
	var errBuf bytes.Buffer
	h := cliHandlers{
		errOut: &errBuf,
		join:   func(string, options) error { t.Fatal("join should not run"); return nil },
	}
	for _, argv := range [][]string{
		{"join", "--link-stdin", "https://h.example/join#t=abc"},
		{"--link-stdin", "https://h.example/join#t=abc"},
	} {
		errBuf.Reset()
		if rc := runCLI(argv, h); rc != 2 || !strings.Contains(errBuf.String(), "--link-stdin") {
			t.Fatalf("%v: rc=%d err=%q; want exit 2 mentioning --link-stdin", argv, rc, errBuf.String())
		}
	}

	if cobra.MousetrapHelpText != "" {
		t.Fatalf("cobra.MousetrapHelpText = %q, want empty string", cobra.MousetrapHelpText)
	}

	var out bytes.Buffer
	if rc := runCLI([]string{"update", "--help"}, cliHandlers{out: &out, errOut: &errBuf}); rc != 0 {
		t.Fatalf("update --help rc=%d", rc)
	}
	if strings.Contains(out.String(), "HOGMAN_RELEASE_BASE") {
		t.Fatalf("update --help should not expose test-only HOGMAN_RELEASE_BASE:\n%s", out.String())
	}
}
