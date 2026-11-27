package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"hogman/join/internal/agent"
	"hogman/join/internal/bridge"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/platform"
	"hogman/join/internal/share"
	"hogman/join/internal/ui"
	"hogman/join/internal/updater"
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

// cliHandlers holds the execution callbacks invoked by the Cobra command tree.
// Production uses defaultCLIHandlers(); tests can substitute recorders and a
// local *ui.UI to run CLI tests in parallel with no global state mutation.
type cliHandlers struct {
	ui            *ui.UI
	out           io.Writer
	errOut        io.Writer
	join          func(raw string, o options) error
	update        func(args []string, o options) error
	leave         func(args []string, o options) error
	leaveAll      func(args []string, o options) error
	uninstall     func(args []string, o options) error
	status        func(o options) error
	doctor        func(o options) error
	browserSetup  func(args []string, o options) error
	shareStart    func(name, target, rawLink string, o options) error
	shareList     func(pen string, asJSON bool) error
	shareStop     func(name string, o options) error
	bridge        func(bo bridge.Options) error
	agent         func(dir string) error
	agentLogout   func(dir string)
	shareRun      func(dir string) error
	startDetached func(kind, dir string) error
}

func (h cliHandlers) activeUI() *ui.UI {
	if h.ui != nil {
		return h.ui
	}
	return &ui.UI{Out: h.out, Err: h.errOut}
}

func defaultCLIHandlers() cliHandlers {
	u := ui.Default()
	ensureBin := func(configBase string) (string, error) {
		return updater.EnsureCanonicalBinary(configBase, version, u.Note)
	}
	return cliHandlers{
		ui:     u,
		out:    os.Stdout,
		errOut: os.Stderr,
		join:   func(raw string, o options) error { return join(raw, o, u) },
		update: func(args []string, o options) error {
			return updater.Run(args, updater.Options{
				Pen:        o.pen,
				ControlCA:  o.controlCA,
				DryRun:     o.dryRun,
				NoService:  o.noService,
				BinaryName: cliBinaryName(),
			}, u)
		},
		leave:        func(args []string, o options) error { return defaultLeaveRunner(u).leaveCmd(args, o) },
		leaveAll:     func(args []string, o options) error { return defaultLeaveRunner(u).leaveAllCmd(args, o) },
		uninstall:    func(args []string, o options) error { return defaultLeaveRunner(u).uninstallCmd(args, o) },
		status:       func(o options) error { return statusCmd(o, u) },
		doctor:       func(o options) error { return doctorCmd(o, u) },
		browserSetup: func(args []string, o options) error { return browserSetupCmd(args, o, u) },
		shareStart: func(name, target, rawLink string, o options) error {
			return share.Start(name, target, rawLink, share.StartOptions{
				Pen:             o.pen,
				ControlCA:       o.controlCA,
				Note:            o.note,
				NoteSet:         o.noteSet,
				PrivateName:     o.privateName,
				Background:      o.background,
				Foreground:      o.foreground,
				NoService:       o.noService,
				StateDir:        o.stateDir,
				EnrollOnly:      o.enrollOnly,
				UpstreamHost:    o.upstreamHost,
				IdentityHeaders: o.identityHeaders,
			}, u, ensureBin)
		},
		shareList:   func(pen string, asJSON bool) error { return share.List(pen, asJSON, u) },
		shareStop:   func(name string, o options) error { return share.StopCmd(name, o.pen, o.force, u) },
		bridge:      bridge.RunCommand,
		agent:       agent.Run,
		agentLogout: agent.Logout,
		shareRun:    func(dir string) error { return share.RunProcess(dir, u) },
		startDetached: func(kind, dir string) error {
			exe, err := fsutil.ResolvedExePath()
			if err != nil {
				return err
			}
			switch kind {
			case "agent":
				return platform.StartDetached(exe, dir)
			case "share":
				_, err := platform.SpawnDetached(filepath.Join(dir, "share.log"), exe, "__share-run", dir)
				return err
			default:
				return usageErrorf("unknown detached target %q", kind)
			}
		},
	}
}

func newRootCmd(h cliHandlers) *cobra.Command {
	if h.out == nil {
		if h.ui != nil && h.ui.Out != nil {
			h.out = h.ui.Out
		} else {
			h.out = os.Stdout
		}
	}
	if h.errOut == nil {
		if h.ui != nil && h.ui.Err != nil {
			h.errOut = h.ui.Err
		} else {
			h.errOut = os.Stderr
		}
	}
	u := h.activeUI()

	var (
		o             options
		showVersion   bool
		verboseFlag   bool
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
			platform.SetVerbose(verboseFlag)
			return checkRemovedFlags()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Fprintf(h.out, "%s %s %s/%s\n", binName, version, runtime.GOOS, runtime.GOARCH)
				return nil
			}
			if len(args) == 0 {
				if o.linkStdin {
					raw, err := u.ReadJoinLink(true, nil)
					if err != nil {
						return err
					}
					return h.join(raw, o)
				}
				_ = cmd.Help()
				return &link.UsageError{}
			}
			if len(args) == 1 {
				trimmed := link.TrimMatchingQuotes(args[0])
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
	pf.BoolVar(&verboseFlag, "verbose", false, "show the commands being run")
	pf.BoolVar(&o.noOpen, "no-open", false, "don't open the portal in a browser at the end")
	pf.BoolVar(&o.yes, "yes", false, "answer prompts automatically where supported")
	pf.StringVar(&o.controlCA, "control-ca", "", "extra certificate to trust for the public control server (test networks only)")
	pf.BoolVar(&o.alongside, "alongside", false, "")
	_ = pf.MarkHidden("alongside")
	pf.BoolVar(&goneTailscale, "tailscale", false, "")
	_ = pf.MarkHidden("tailscale")

	addJoinFlags(root, &o)
	root.Flags().BoolVar(&showVersion, "version", false, "print version and platform")

	root.AddCommand(
		newJoinCmd(h, u, &o),
		newUpdateCmd(h, &o),
		newLeaveCmd(h, &o),
		newLeaveAllCmd(h, &o),
		newUninstallCmd(h, &o),
		newStatusCmd(h, &o),
		newDoctorCmd(h, &o),
		newBrowserSetupCmd(h, &o),
		newShareCmd(h, u, &o),
		newBridgeCmd(h),
		newVersionCmd(h),
		newCompletionCmd(root, h),
	)
	root.AddCommand(newInternalServiceCmds(h)...)
	return root
}

// runCLI executes the CLI with args and handlers, returning the process exit code.
func runCLI(args []string, h cliHandlers) int {
	if h.errOut == nil {
		if h.ui != nil && h.ui.Err != nil {
			h.errOut = h.ui.Err
		} else {
			h.errOut = os.Stderr
		}
	}
	root := newRootCmd(h)
	root.SetArgs(normalizeSingleDashFlags(root, args))
	err := root.Execute()
	if err == nil {
		return 0
	}
	// Hidden __share-run keeps its exact exit-code contract for launchd/systemd.
	if len(args) >= 1 && args[0] == "__share-run" {
		if share.IsPermanent(err) {
			fmt.Fprintf(h.errOut, "%s (permanent failure; stopping automatic restarts)\n", err.Error())
		} else {
			fmt.Fprintln(h.errOut, err.Error())
		}
		return share.ExitCode(err)
	}
	if len(args) >= 1 && args[0] == "agent" {
		fmt.Fprintln(h.errOut, err.Error())
		return 1
	}
	var ue *link.UsageError
	if errors.As(err, &ue) {
		if ue.Msg != "" {
			fmt.Fprintf(h.errOut, "\n✗ %s\n", ue.Msg)
		}
		return 2
	}
	var u *link.UserError
	if errors.As(err, &u) {
		fmt.Fprintf(h.errOut, "\n✗ %s\n", u.Msg)
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
