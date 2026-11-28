// Command hogman puts a device on a Hogman network in one step:
//
//	hogman 'https://bobo.gate.example.com/join#t=...'
//
// It verifies the network over this computer's built-in trusted certificates,
// redeems the invite (or uses the device key in the link), joins side by side
// with a local proxy for pen names only, and checks the portal loads over HTTPS.
package main

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"hogman/join/internal/link"
	"hogman/join/internal/nativehost"
	"hogman/join/internal/penapi"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
	"hogman/join/internal/updater"
)

var version = "dev"

func errorf(f string, a ...any) error      { return link.Errorf(f, a...) }
func usageErrorf(f string, a ...any) error { return link.UsageErrorf(f, a...) }

type options struct {
	handle, hostname, controlCA string
	yes, dryRun, noOpen         bool
	jsonOut                     bool // status/share list/doctor: machine-readable JSON on stdout
	linkStdin                   bool // join: read join link from stdin
	force                       bool // leave/uninstall/share stop: override checks or clean up unreachable pen
	alongside                   bool // accepted for old scripts; it's the only way now
	noService, noSystemProxy    bool
	pen                         string // share/update: which pen
	background                  bool   // share: explicit --background (now the default; kept for scripts)
	foreground                  bool   // share: stay attached to the terminal (Ctrl-C to stop)
	note                        string // share: one-line note for the pen directory
	noteSet                     bool
	privateName                 bool   // share: allocate a random private hostname on the registrar
	stateDir                    string // share: explicit state directory (container/sidecar deployments)
	enrollOnly                  bool   // share: enroll state into --state-dir and exit 0
	upstreamHost                string // share: optional Host header override for unix:// upstreams
	identityHeaders             bool   // share: pass verified X-Hogman-* caller identity headers to local upstreams
	chromeID                    string // browser-setup: optional unpacked Chrome extension ID
	firefoxID                   string // browser-setup: optional Firefox Gecko extension ID
}

func main() {
	if nativehost.IsBinary(os.Args[0]) {
		os.Exit(nativehost.RunMain())
	}
	os.Exit(runCLI(os.Args[1:], defaultCLIHandlers()))
}

func join(raw string, o options, u *ui.UI) error {
	l, err := link.Parse(raw)
	if err != nil {
		return errorf("%v", err)
	}
	if l.ForShare {
		return errorf("that's a server link: it's for putting something in the pen, not for joining a computer.\n" +
			"  Use it with share, for example: hogman share blog 8080 '<this link>'")
	}
	client, err := penapi.ControlClient(o.controlCA)
	if err != nil {
		return err
	}

	u.Step("Checking the network at %s", l.Host)
	n, err := penapi.FetchNetwork(client, l.Host)
	if err != nil {
		return err
	}
	u.Note("network: %s", n.Zone)

	// One way in (D-11): the agent, which runs as this user and carries HTTPS to
	// the pen's names and nothing else. Joining through this computer's
	// Tailscale app was removed: it put every program on the pen and gave the
	// pen's control server this computer's DNS, a choice that should never be
	// one member's to make for the whole pen.
	if ts, err := platform.FindTailscale(); err == nil {
		if st, err := ts.Status(); err == nil && st.BackendState == "Running" && st.OnNetwork(n.Zone) {
			return errorf("this computer is on %s through its Tailscale app, which Hogman no longer uses.\n"+
				"  First get a fresh one-time link: open %s, press Add a device, copy the link.\n"+
				"  Then run hogman leave %s, and join with the fresh link.", n.Zone, n.Portal, n.Zone)
		}
	}
	return joinAlongside(l, n, client, o, "the pen's own small connection: HTTPS to the pen and nothing else", u)
}

func orAsk(h string) string {
	if h == "" {
		return "will ask"
	}
	return h
}

func redeemWithHandle(c *http.Client, l *link.Link, o options, u *ui.UI) (*penapi.Enrolment, error) {
	handle := strings.ToLower(strings.TrimSpace(o.handle))
	for attempt := 0; ; attempt++ {
		if handle == "" {
			if !u.IsTerminal() {
				return nil, errorf("choose a name with --handle (lowercase letters, digits, dashes)")
			}
			handle = strings.ToLower(u.Ask("  Choose your name on the network (lowercase letters, digits, dashes): "))
		}
		if !link.HandleRE.MatchString(handle) {
			if o.handle != "" || !u.IsTerminal() {
				return nil, errorf("%q is not a valid name: 2-32 lowercase letters, digits or dashes, starting with a letter", handle)
			}
			u.Note("that is not a valid name")
			handle = ""
			continue
		}
		en, err := penapi.Redeem(c, l.Host, l.InviteToken, handle)
		var re *penapi.RedeemError
		if errors.As(err, &re) && re.Status == 409 && o.handle == "" && u.IsTerminal() && attempt < 5 {
			u.Note("%s", re.Msg)
			handle = ""
			continue
		}
		if errors.As(err, &re) {
			return nil, errorf("the invite was not accepted: %s", re.Msg)
		}
		return en, err
	}
}

func ensureCanonicalBinary(configBase string) (string, error) {
	return updater.EnsureCanonicalBinary(configBase, version, ui.Default().Note)
}

func installedBinary(_ string) (string, error) {
	return ensureCanonicalBinary(state.ConfigBase())
}
