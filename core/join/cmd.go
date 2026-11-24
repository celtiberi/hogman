package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func init() {
	// Disable cobra's Windows Explorer mousetrap so non-console launches (such as
	// Windows Scheduled Tasks or autostart helpers) never pause 5s and exit.
	cobra.MousetrapHelpText = ""
}

func cliBinaryName() string { return "hogman" }

var singleDashLongFlagRE = regexp.MustCompile(`^-([a-z][a-z0-9-]+)(=.*)?$`)

// collectRegisteredLongFlags returns all registered long flag names across the
// command tree, mapping each flag name to whether it expects a separate value
// argument (true for non-bool flags).
func collectRegisteredLongFlags(cmd *cobra.Command, out map[string]bool) {
	record := func(f *pflag.Flag) {
		if len(f.Name) <= 1 {
			return
		}
		needsVal := f.Value.Type() != "bool"
		// If any command registers a flag as taking a value, preserve that.
		if prev, ok := out[f.Name]; !ok || needsVal {
			out[f.Name] = prev || needsVal
		}
	}
	cmd.Flags().VisitAll(record)
	cmd.PersistentFlags().VisitAll(record)
	for _, sub := range cmd.Commands() {
		collectRegisteredLongFlags(sub, out)
	}
}

// normalizeSingleDashFlags rewrites legacy Go-flag style single-dash long flags
// (e.g. -no-open, -force, -handle=alice, -version, -help) to --flag before "--"
// when the name is a registered long flag on the CLI. Unknown single-dash flags
// and arguments after "--" are left untouched so they still fail closed.
func normalizeSingleDashFlags(root *cobra.Command, args []string) []string {
	known := map[string]bool{"help": false, "version": false}
	collectRegisteredLongFlags(root, known)

	out := make([]string, len(args))
	copy(out, args)
	skipNext := false
	for i, a := range out {
		if skipNext {
			skipNext = false
			continue
		}
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "--") {
			name := strings.TrimPrefix(a, "--")
			if !strings.Contains(name, "=") && known[name] {
				skipNext = true
			}
			continue
		}
		if m := singleDashLongFlagRE.FindStringSubmatch(a); m != nil {
			name, eqVal := m[1], m[2]
			if needsVal, ok := known[name]; ok {
				out[i] = "--" + name + eqVal
				if eqVal == "" && needsVal {
					skipNext = true
				}
			}
		}
	}
	return out
}

// usageError marks CLI syntax / flag / argument errors that should exit with code 2.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usageErrorf(f string, a ...any) error { return &usageError{msg: fmt.Sprintf(f, a...)} }

// cliHandlers holds the execution callbacks invoked by the Cobra command tree.
// Production uses defaultCLIHandlers(); tests can substitute recorders to verify
// exact argument parsing, flag routing, and hidden service commands offline.
type cliHandlers struct {
	out          io.Writer
	errOut       io.Writer
	join         func(raw string, o options) error
	update       func(args []string, o options) error
	leave        func(args []string, o options) error
	leaveAll     func(args []string, o options) error
	uninstall    func(args []string, o options) error
	status       func(o options) error
	doctor       func(o options) error
	browserSetup func(args []string, o options) error
	shareStart   func(name, target, rawLink string, o options) error
	shareList    func(pen string, asJSON bool) error
	shareStop    func(name string, o options) error
	bridge       func(bo bridgeOptions) error
	agent        func(dir string) error
	agentLogout  func(dir string)
	shareRun     func(dir string) error
}

func defaultCLIHandlers() cliHandlers {
	return cliHandlers{
		out:          os.Stdout,
		errOut:       os.Stderr,
		join:         join,
		update:       updateCmd,
		leave:        leaveCmd,
		leaveAll:     leaveAllCmd,
		uninstall:    uninstallCmd,
		status:       statusCmd,
		doctor:       doctorCmd,
		browserSetup: browserSetupCmd,
		shareStart:   shareStart,
		shareList:    shareList,
		shareStop:    shareStop,
		bridge:       bridgeCmd,
		agent:        runAgent,
		agentLogout:  agentLogout,
		shareRun:     runShareProcess,
	}
}

func readJoinLinkInteractive(o options, stdin io.Reader) (string, error) {
	if o.linkStdin {
		b, err := io.ReadAll(io.LimitReader(stdin, 16*1024))
		if err != nil {
			return "", errorf("could not read join link from stdin: %v", err)
		}
		link := strings.TrimSpace(string(b))
		if link == "" {
			return "", errorf("no join link received on stdin")
		}
		return link, nil
	}
	if !isTerminalFn() {
		return "", usageErrorf("provide a join link in single quotes (hogman join '<link>') or pass --link-stdin")
	}
	link := strings.TrimSpace(askFn("  Paste your join link: "))
	if link == "" {
		return "", errorf("no join link entered")
	}
	return link, nil
}

func newRootCmd(h cliHandlers) *cobra.Command {
	if h.out == nil {
		h.out = os.Stdout
	}
	if h.errOut == nil {
		h.errOut = os.Stderr
	}

	var (
		o             options
		showVersion   bool
		goneTailscale bool
	)

	checkRemovedFlags := func() error {
		if goneTailscale {
			return usageErrorf("--tailscale no longer exists: every computer joins through Hogman's own connection,\n" +
				"  which carries HTTPS to the pen and nothing else. Run the same command without it.\n" +
				"  Why: https://hogman.network/docs/faq.html#not")
		}
		return nil
	}

	addJoinFlags := func(cmd *cobra.Command) {
		cmd.Flags().StringVar(&o.handle, "handle", "", "the name you want on the network (invite links only; asked if missing)")
		cmd.Flags().StringVar(&o.hostname, "hostname", "", "what this device is called on the network (default: this computer's name)")
		cmd.Flags().BoolVar(&o.noService, "no-service", false, "don't register a login item, just run in the background")
		cmd.Flags().BoolVar(&o.noSystemProxy, "no-system-proxy", false, "don't change this computer's automatic proxy setting")
		cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "check the link and the network, then stop without changing anything")
		cmd.Flags().BoolVar(&o.linkStdin, "link-stdin", false, "read the join link from standard input instead of an argument")
	}

	binName := cliBinaryName()
	root := &cobra.Command{
		Use:   binName + " [options] '<link>'",
		Short: "Join this device to a Hogman private network",
		Long: binName + ": join this device to a Hogman private network\n\n" +
			"Quote the link when passing it as an argument: it contains '#' and '&'.\n" +
			"Or run '" + binName + " join' with no arguments to paste it interactively.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return checkRemovedFlags()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Fprintf(h.out, "%s %s %s/%s\n", binName, version, runtime.GOOS, runtime.GOARCH)
				return nil
			}
			if len(args) == 0 {
				if o.linkStdin {
					raw, err := readJoinLinkInteractive(o, os.Stdin)
					if err != nil {
						return err
					}
					return h.join(raw, o)
				}
				_ = cmd.Help()
				return &usageError{msg: ""}
			}
			if len(args) == 1 {
				trimmed := trimMatchingQuotes(args[0])
				if strings.Contains(trimmed, "://") {
					if o.linkStdin {
						return usageErrorf("cannot pass both a join link argument and --link-stdin")
					}
					return h.join(args[0], o)
				}
				return usageErrorf("unknown command %q (run 'hogman --help' for usage)", args[0])
			}
			return usageErrorf("unexpected arguments %q (run 'hogman --help' for usage)", strings.Join(args, " "))
		},
	}
	root.SetOut(h.out)
	root.SetErr(h.errOut)

	// Harmless global flags accepted across subcommands (preserves test harnesses
	// and scripts that prefix --no-open, --verbose, --yes, or --control-ca).
	pf := root.PersistentFlags()
	pf.BoolVar(&verbose, "verbose", false, "show the commands being run")
	pf.BoolVar(&o.noOpen, "no-open", false, "don't open the portal in a browser at the end")
	pf.BoolVar(&o.yes, "yes", false, "answer prompts automatically where supported")
	pf.StringVar(&o.controlCA, "control-ca", "", "extra certificate to trust for the public control server (test networks only)")
	pf.BoolVar(&o.alongside, "alongside", false, "")
	_ = pf.MarkHidden("alongside")
	pf.BoolVar(&goneTailscale, "tailscale", false, "")
	_ = pf.MarkHidden("tailscale")

	addJoinFlags(root)
	root.Flags().BoolVar(&showVersion, "version", false, "print version and platform")

	// Explicit `join` subcommand (supports interactive paste when run with 0 args on a TTY).
	joinCmd := &cobra.Command{
		Use:   "join ['<link>']",
		Short: "Join a Hogman pen (or paste a join link interactively)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				if o.linkStdin {
					return usageErrorf("cannot pass both a join link argument and --link-stdin")
				}
				return h.join(args[0], o)
			}
			raw, err := readJoinLinkInteractive(o, os.Stdin)
			if err != nil {
				return err
			}
			return h.join(raw, o)
		},
	}
	addJoinFlags(joinCmd)

	// `update`
	updateC := &cobra.Command{
		Use:   "update ['<link|host>']",
		Short: "Update hogman from GitHub Releases (or a pen's server)",
		Long:  updateUsage,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.update(args, o)
		},
	}
	updateC.Flags().StringVar(&o.pen, "pen", "", "update from one specific pen's server instead of GitHub Releases")
	updateC.Flags().BoolVar(&o.dryRun, "dry-run", false, "check checksums and show what would change without modifying files")
	updateC.Flags().BoolVar(&o.noService, "no-service", false, "keep restarted agents in the background rather than a login item")

	// `leave`
	leaveC := &cobra.Command{
		Use:   "leave <pen>",
		Short: "Take this computer out of one pen (link, host, zone, or short name)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.leave(args, o)
		},
	}
	leaveC.Flags().BoolVar(&o.force, "force", false, "override owner/unreachable check (requires typing the exact pen name)")

	// `leave-all`
	leaveAllC := &cobra.Command{
		Use:   "leave-all",
		Short: "Take this computer out of every pen (asks first)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.leaveAll(args, o)
		},
	}
	leaveAllC.Flags().BoolVar(&o.force, "force", false, "override owner/unreachable checks (requires typing each pen name)")

	// `uninstall`
	uninstallC := &cobra.Command{
		Use:   "uninstall",
		Short: "Leave every pen and remove Hogman's settings (asks first)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.uninstall(args, o)
		},
	}
	uninstallC.Flags().BoolVar(&o.force, "force", false, "override owner/unreachable checks (requires typing each pen name)")

	// `status`
	statusC := &cobra.Command{
		Use:   "status",
		Short: "Show installed pens, browser extension host, and VPN proxy state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.status(o)
		},
	}
	statusC.Flags().BoolVar(&o.jsonOut, "json", false, "output status as JSON")

	// `doctor`
	doctorC := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose pens, shares, browser extension, and proxy health",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.doctor(o)
		},
	}
	doctorC.Flags().BoolVar(&o.jsonOut, "json", false, "output diagnostics as JSON")

	// `browser-setup`
	browserSetupC := &cobra.Command{
		Use:   "browser-setup",
		Short: "Register the browser extension native messaging host (no sudo)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.browserSetup(args, o)
		},
	}
	browserSetupC.Flags().StringVar(&o.chromeID, "chrome-id", "", "optional unpacked Chrome extension ID (32 letters a-p)")
	browserSetupC.Flags().StringVar(&o.firefoxID, "firefox-id", "", "optional Firefox Gecko extension ID")

	// `share` (parent command + `list` + `stop`)
	shareC := &cobra.Command{
		Use:   "share <name> <target> ['<server link>']",
		Short: "Put a port, local URL, or folder on the pen over HTTPS",
		Long:  shareUsage,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 && len(args) != 3 {
				return usageErrorf("usage: hogman share <name> <target> ['<server link>']\n  (run 'hogman share --help' for more)")
			}
			o.noteSet = cmd.Flags().Changed("note")
			link := ""
			if len(args) == 3 {
				if o.linkStdin {
					return usageErrorf("cannot pass both a share link argument and --link-stdin")
				}
				link = args[2]
			} else if o.linkStdin {
				raw, err := readJoinLinkInteractive(o, os.Stdin)
				if err != nil {
					return err
				}
				link = raw
			}
			return h.shareStart(args[0], args[1], link, o)
		},
	}
	shareC.Flags().StringVar(&o.note, "note", "", "short one-line description shown on the pen's home page (--note \"\" clears it)")
	shareC.Flags().BoolVar(&o.background, "background", false, "keep running in the background and start automatically after a restart")
	shareC.Flags().BoolVar(&o.noService, "no-service", false, "with --background, don't register a login item, just run in the background")
	shareC.Flags().StringVar(&o.pen, "pen", "", "which pen, if this computer is on more than one (short name or full zone; or set HOGMAN_PEN)")
	shareC.Flags().StringVar(&o.stateDir, "state-dir", "", "store share state in this directory instead of the default config folder (for containers)")
	shareC.Flags().BoolVar(&o.enrollOnly, "enroll-only", false, "enroll the share, claim its name and certificate, then exit 0 (for one-shot container setup)")
	shareC.Flags().BoolVar(&o.linkStdin, "link-stdin", false, "read the server share link from standard input instead of an argument")
	shareC.Flags().StringVar(&o.upstreamHost, "upstream-host", "", "optional Host header to send to a unix:// upstream (default: <name>.<zone>)")

	shareListC := &cobra.Command{
		Use:   "list",
		Short: "List what this computer shares",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.shareList(o.pen, o.jsonOut)
		},
	}
	shareListC.Flags().StringVar(&o.pen, "pen", "", "filter shares to one pen (short name or full zone; or set HOGMAN_PEN)")
	shareListC.Flags().BoolVar(&o.jsonOut, "json", false, "output shares as JSON")

	shareStopC := &cobra.Command{
		Use:   "stop <name>",
		Short: "Take a share down and give its name back",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.shareStop(args[0], o)
		},
	}
	shareStopC.Flags().StringVar(&o.pen, "pen", "", "which pen, if the same name is shared on more than one pen")
	shareStopC.Flags().BoolVar(&o.force, "force", false, "remove local files even if the pen cannot be reached")

	shareC.AddCommand(shareListC, shareStopC)

	// `bridge` (Unix socket <-> loopback TCP bridge for sealed container deployments)
	var bo bridgeOptions
	bridgeC := &cobra.Command{
		Use:   "bridge",
		Short: "Bridge a Unix domain socket to a loopback TCP port (for sealed containers)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.bridge(bo)
		},
	}
	bridgeC.Flags().StringVar(&bo.listenUnix, "listen-unix", "", "absolute filesystem path for the listening Unix domain socket")
	bridgeC.Flags().StringVar(&bo.forwardTCP, "forward-tcp", "", "loopback TCP target to forward connections to (e.g. 127.0.0.1:8080)")
	bridgeC.Flags().StringVar(&bo.checkUnix, "check", "", "healthcheck mode: verify the given Unix socket is accepting connections and exit 0")
	bridgeC.Flags().IntVar(&bo.maxConns, "max-conns", 256, "maximum concurrent forwarded connections")

	// `version`
	versionC := &cobra.Command{
		Use:   "version",
		Short: "Print version and platform",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(h.out, "hogman %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}

	// `completion` (opt-in stdout only; never edits shell rc files)
	completionC := &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Print a shell completion script to stdout",
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(h.out, true)
			case "zsh":
				return root.GenZshCompletion(h.out)
			case "fish":
				return root.GenFishCompletion(h.out, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(h.out)
			}
			return usageErrorf("unsupported shell %q", args[0])
		},
	}

	// Hidden internal service commands: argument shapes MUST stay byte-for-byte
	// compatible with already-installed launchd plists, systemd units, and tasks.
	agentC := &cobra.Command{
		Use:    "agent <dir>",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.agent(args[0])
		},
	}
	agentLogoutC := &cobra.Command{
		Use:    "__agent-logout <dir>",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h.agentLogout(args[0])
			return nil
		},
	}
	shareRunC := &cobra.Command{
		Use:    "__share-run <dir>",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.shareRun(args[0])
		},
	}

	root.AddCommand(
		joinCmd,
		updateC,
		leaveC,
		leaveAllC,
		uninstallC,
		statusC,
		doctorC,
		browserSetupC,
		shareC,
		bridgeC,
		versionC,
		completionC,
		agentC,
		agentLogoutC,
		shareRunC,
	)
	return root
}

// runCLI executes the CLI with args and handlers, returning the process exit code.
func runCLI(args []string, h cliHandlers) int {
	if h.errOut == nil {
		h.errOut = os.Stderr
	}
	root := newRootCmd(h)
	root.SetArgs(normalizeSingleDashFlags(root, args))
	err := root.Execute()
	if err == nil {
		return 0
	}
	// Hidden __share-run keeps its exact exit-code contract for launchd/systemd.
	if len(args) >= 1 && args[0] == "__share-run" {
		if isPermanentShareError(err) {
			fmt.Fprintf(h.errOut, "%s (permanent failure; stopping automatic restarts)\n", err.Error())
		} else {
			fmt.Fprintln(h.errOut, err.Error())
		}
		return shareExitCode(err)
	}
	if len(args) >= 1 && args[0] == "agent" {
		fmt.Fprintln(h.errOut, err.Error())
		return 1
	}
	var ue *usageError
	if errors.As(err, &ue) {
		if ue.msg != "" {
			fmt.Fprintf(h.errOut, "\n✗ %s\n", ue.msg)
		}
		return 2
	}
	var u *userError
	if errors.As(err, &u) {
		fmt.Fprintf(h.errOut, "\n✗ %s\n", u.msg)
		return 1
	}
	// Cobra/pflag flag or argument validation errors exit 2.
	msg := err.Error()
	if strings.HasPrefix(msg, "unknown flag:") ||
		strings.HasPrefix(msg, "unknown shorthand flag:") ||
		strings.HasPrefix(msg, "flag needs an argument:") ||
		strings.HasPrefix(msg, "invalid argument ") ||
		strings.HasPrefix(msg, "accepts ") ||
		strings.HasPrefix(msg, "requires ") ||
		strings.HasPrefix(msg, "unknown command ") {
		fmt.Fprintf(h.errOut, "\n✗ %s\n", msg)
		return 2
	}
	fmt.Fprintf(h.errOut, "\n✗ unexpected error: %v\n", err)
	return 1
}
