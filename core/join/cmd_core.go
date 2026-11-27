package main

import (
	"github.com/spf13/cobra"

	"hogman/join/internal/ui"
	"hogman/join/internal/updater"
)

func addJoinFlags(cmd *cobra.Command, o *options) {
	cmd.Flags().StringVar(&o.handle, "handle", "", "the name you want on the network (invite links only; asked if missing)")
	cmd.Flags().StringVar(&o.hostname, "hostname", "", "what this device is called on the network (default: this computer's name)")
	cmd.Flags().BoolVar(&o.noService, "no-service", false, "don't register a login item, just run in the background")
	cmd.Flags().BoolVar(&o.noSystemProxy, "no-system-proxy", false, "skip automatic proxy checks and setup instructions")
	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "check the link and the network, then stop without changing anything")
	cmd.Flags().BoolVar(&o.linkStdin, "link-stdin", false, "read the join link from standard input instead of an argument")
}

func newJoinCmd(h cliHandlers, u *ui.UI, o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "join ['<link>']",
		Short: "Join a Hogman pen (or paste a join link interactively)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				if o.linkStdin {
					return usageErrorf("cannot pass both a join link argument and --link-stdin")
				}
				return h.join(args[0], *o)
			}
			raw, err := u.ReadJoinLink(o.linkStdin, nil)
			if err != nil {
				return err
			}
			return h.join(raw, *o)
		},
	}
	addJoinFlags(cmd, o)
	return cmd
}

func newUpdateCmd(h cliHandlers, o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update ['<link|host>']",
		Short: "Update hogman from GitHub Releases (or a pen's server)",
		Long:  updater.Usage,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.update(args, *o)
		},
	}
	cmd.Flags().StringVar(&o.pen, "pen", "", "update from one specific pen's server instead of GitHub Releases")
	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "check checksums and show what would change without modifying files")
	cmd.Flags().BoolVar(&o.noService, "no-service", false, "keep restarted agents in the background rather than a login item")
	return cmd
}

func newLeaveCmd(h cliHandlers, o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "leave <pen>",
		Short: "Take this computer out of one pen (link, host, zone, or short name)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.leave(args, *o)
		},
	}
	cmd.Flags().BoolVar(&o.force, "force", false, "override owner/unreachable check (requires typing the exact pen name)")
	return cmd
}

func newLeaveAllCmd(h cliHandlers, o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "leave-all",
		Short: "Take this computer out of every pen (asks first)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.leaveAll(args, *o)
		},
	}
	cmd.Flags().BoolVar(&o.force, "force", false, "override owner/unreachable checks (requires typing each pen name)")
	return cmd
}

func newUninstallCmd(h cliHandlers, o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Leave every pen and remove Hogman's settings (asks first)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.uninstall(args, *o)
		},
	}
	cmd.Flags().BoolVar(&o.force, "force", false, "override owner/unreachable checks (requires typing each pen name)")
	return cmd
}

func newStatusCmd(h cliHandlers, o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show installed pens, browser extension host, and VPN proxy state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.status(*o)
		},
	}
	cmd.Flags().BoolVar(&o.jsonOut, "json", false, "output status as JSON")
	return cmd
}

func newDoctorCmd(h cliHandlers, o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose pens, shares, browser extension, and proxy health",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.doctor(*o)
		},
	}
	cmd.Flags().BoolVar(&o.jsonOut, "json", false, "output diagnostics as JSON")
	return cmd
}

func newBrowserSetupCmd(h cliHandlers, o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "browser-setup",
		Short: "Register the browser extension native messaging host (no sudo)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.browserSetup(args, *o)
		},
	}
	cmd.Flags().StringVar(&o.chromeID, "chrome-id", "", "optional unpacked Chrome extension ID (32 letters a-p)")
	cmd.Flags().StringVar(&o.firefoxID, "firefox-id", "", "optional Firefox Gecko extension ID")
	return cmd
}
