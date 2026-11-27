package main

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"hogman/join/internal/bridge"
	"hogman/join/internal/link"
	"hogman/join/internal/share"
	"hogman/join/internal/ui"
)

func newShareCmd(h cliHandlers, u *ui.UI, o *options) *cobra.Command {
	shareC := &cobra.Command{
		Use:   "share <name> <target> ['<server link>']",
		Short: "Put a port, local URL, or folder on the pen over HTTPS",
		Long:  share.Usage,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.noteSet = cmd.Flags().Changed("note")
			if o.privateName {
				if len(args) == 3 {
					return usageErrorf("cannot pass both a share name (%q) and --private-name; use: hogman share --private-name %s '<server link>' [--note %q]", args[0], args[1], args[0])
				}
				if len(args) != 1 && len(args) != 2 {
					return usageErrorf("usage: hogman share --private-name <target> ['<server link>'] [--note \"Label\"]\n  (run 'hogman share --help' for more)")
				}
				if len(args) == 2 && !strings.Contains(link.TrimMatchingQuotes(args[1]), "://") {
					return usageErrorf("cannot pass both a share name (%q) and --private-name; use: hogman share --private-name %s [--note %q]", args[0], args[1], args[0])
				}
				rawLink := ""
				if len(args) == 2 {
					if o.linkStdin {
						return usageErrorf("cannot pass both a share link argument and --link-stdin")
					}
					rawLink = args[1]
				} else if o.linkStdin {
					raw, err := u.ReadJoinLink(true, nil)
					if err != nil {
						return err
					}
					rawLink = raw
				}
				return h.shareStart("", args[0], rawLink, *o)
			}
			if len(args) != 2 && len(args) != 3 {
				return usageErrorf("usage: hogman share <name> <target> ['<server link>']\n  (run 'hogman share --help' for more)")
			}
			rawLink := ""
			if len(args) == 3 {
				if o.linkStdin {
					return usageErrorf("cannot pass both a share link argument and --link-stdin")
				}
				rawLink = args[2]
			} else if o.linkStdin {
				raw, err := u.ReadJoinLink(true, nil)
				if err != nil {
					return err
				}
				rawLink = raw
			}
			return h.shareStart(args[0], args[1], rawLink, *o)
		},
	}
	shareC.Flags().BoolVar(&o.privateName, "private-name", false, "use a random hostname so the friendly name stays inside the pen (pair with --note \"Label\" for the portal directory). Does not hide the pen name, site count, or issuance/renewal timing in certificate logs, and does not change certificate caps.")
	shareC.Flags().StringVar(&o.note, "note", "", "short one-line description shown on the pen's home page (--note \"\" clears it)")
	shareC.Flags().BoolVar(&o.foreground, "foreground", false, "stay attached to this terminal (Ctrl-C to stop) instead of running in the background")
	shareC.Flags().BoolVar(&o.background, "background", false, "run in the background and start at login (default; kept for older scripts)")
	shareC.Flags().BoolVar(&o.noService, "no-service", false, "don't register a login item, just run in the background")
	shareC.Flags().StringVar(&o.pen, "pen", "", "which pen, if this computer is on more than one (short name or full zone; or set HOGMAN_PEN)")
	shareC.Flags().StringVar(&o.stateDir, "state-dir", "", "store share state in this directory instead of the default config folder (for containers)")
	shareC.Flags().BoolVar(&o.enrollOnly, "enroll-only", false, "enroll the share, claim its name and certificate, then exit 0 (for one-shot container setup)")
	shareC.Flags().BoolVar(&o.linkStdin, "link-stdin", false, "read the server share link from standard input instead of an argument")
	shareC.Flags().StringVar(&o.upstreamHost, "upstream-host", "", "optional Host header to send to a unix:// upstream (default: <name>.<zone>)")
	shareC.Flags().BoolVar(&o.identityHeaders, "identity-headers", false, "pass verified X-Hogman-* caller identity headers to a local upstream target (off by default; use sealed unix:// mode for automatic sign-in)")

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
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return share.StopUsageError(o.pen, u)
			}
			if len(args) > 1 {
				return usageErrorf("usage: hogman share stop <name> [--pen ZONE] [--force]")
			}
			return h.shareStop(args[0], *o)
		},
	}
	shareStopC.Flags().StringVar(&o.pen, "pen", "", "which pen, if the same name is shared on more than one pen")
	shareStopC.Flags().BoolVar(&o.force, "force", false, "remove local files even if the pen cannot be reached")

	shareC.AddCommand(shareListC, shareStopC)
	return shareC
}

func newBridgeCmd(h cliHandlers) *cobra.Command {
	var bo bridge.Options
	cmd := &cobra.Command{
		Use:   "bridge",
		Short: "Bridge a Unix domain socket to a loopback TCP port (for sealed containers)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.bridge(bo)
		},
	}
	cmd.Flags().StringVar(&bo.ListenUnix, "listen-unix", "", "absolute filesystem path for the listening Unix domain socket")
	cmd.Flags().StringVar(&bo.ForwardTCP, "forward-tcp", "", "loopback TCP target to forward connections to (e.g. 127.0.0.1:8080)")
	cmd.Flags().StringVar(&bo.CheckUnix, "check", "", "healthcheck mode: verify the given Unix socket is accepting connections and exit 0")
	cmd.Flags().IntVar(&bo.MaxConns, "max-conns", 256, "maximum concurrent forwarded connections")
	return cmd
}

func newVersionCmd(h cliHandlers) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and platform",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(h.out, "hogman %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}

func newCompletionCmd(root *cobra.Command, h cliHandlers) *cobra.Command {
	return &cobra.Command{
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
}

// Hidden internal service commands: argument shapes MUST stay byte-for-byte
// compatible with already-installed launchd plists, systemd units, and tasks.
func newInternalServiceCmds(h cliHandlers) []*cobra.Command {
	return []*cobra.Command{
		{
			Use:    "agent <dir>",
			Hidden: true,
			Args:   cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return h.agent(args[0])
			},
		},
		{
			Use:    "__agent-logout <dir>",
			Hidden: true,
			Args:   cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				h.agentLogout(args[0])
				return nil
			},
		},
		{
			Use:    "__share-run <dir>",
			Hidden: true,
			Args:   cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return h.shareRun(args[0])
			},
		},
	}
}
