package share

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"hogman/join/internal/link"
	"hogman/join/internal/penapi"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
)

// PenConn describes a locally joined pen reachable through its loopback proxy.
type PenConn struct {
	Zone        string
	Proxy       string
	ControlCA   string
	LoginServer string
}

// MyPens finds the pens this computer is on in the default config directory.
func MyPens() []PenConn {
	return MyPensIn(state.ConfigBase())
}

// MyPensIn finds the pens installed under configBase.
func MyPensIn(configBase string) []PenConn {
	scanned := state.ScanInstalledPens(configBase)
	out := make([]PenConn, 0, len(scanned.Pens))
	for _, p := range scanned.Pens {
		out = append(out, PenConn{
			Zone:        p.Zone,
			Proxy:       p.Config.ProxyURL(),
			ControlCA:   p.Config.ControlCA,
			LoginServer: p.Config.LoginServer,
		})
	}
	return out
}

// MemberClient talks to the pen's home page as this computer's member.
func (p *PenConn) MemberClient() (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	if p.Proxy != "" {
		pu, err := url.Parse(p.Proxy)
		if err != nil || pu == nil || pu.Host == "" {
			return nil, link.Errorf("invalid local proxy URL %q", p.Proxy)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	pool, err := penapi.TestACMECAPool()
	if err != nil {
		return nil, err
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	return &http.Client{Timeout: 20 * time.Second, Transport: tr}, nil
}

// EffectivePenQuery returns the validated --pen flag value, falling back to
// HOGMAN_PEN when --pen is empty, and reports whether HOGMAN_PEN supplied it.
func EffectivePenQuery(flagVal string) (query string, fromEnv bool, err error) {
	if raw := strings.TrimSpace(flagVal); raw != "" {
		q, err := link.ValidatePenQuery(raw)
		return q, false, err
	}
	if raw := strings.TrimSpace(os.Getenv("HOGMAN_PEN")); raw != "" {
		q, err := link.ValidatePenQuery(raw)
		return q, true, err
	}
	return "", false, nil
}

// ResolvePenConn picks a single joined pen using --pen, HOGMAN_PEN, sole pen,
// or an interactive TTY picker when multiple pens are installed.
func ResolvePenConn(pens []PenConn, want string, u *ui.UI) (*PenConn, error) {
	sorted := make([]PenConn, len(pens))
	copy(sorted, pens)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Zone < sorted[j].Zone })

	query, fromEnv, err := EffectivePenQuery(want)
	if err != nil {
		return nil, err
	}
	if query != "" {
		var matches []PenConn
		for _, p := range sorted {
			if link.PenMatchesQuery(p.Zone, p.LoginServer, query) {
				matches = append(matches, p)
			}
		}
		switch len(matches) {
		case 1:
			if fromEnv {
				u.Note("using pen %s (from HOGMAN_PEN)", matches[0].Zone)
			}
			return &matches[0], nil
		case 0:
			if len(sorted) == 0 {
				return nil, link.Errorf("this computer is not on %s (no pens installed)", query)
			}
			zs := make([]string, len(sorted))
			for i, p := range sorted {
				zs[i] = p.Zone
			}
			return nil, link.Errorf("this computer is not on %s (installed pens: %s)", query, strings.Join(zs, ", "))
		default:
			zs := make([]string, len(matches))
			for i, p := range matches {
				zs[i] = p.Zone
			}
			return nil, link.Errorf("%q matches more than one pen (%s); pass the full zone name with --pen", query, strings.Join(zs, ", "))
		}
	}

	switch len(sorted) {
	case 0:
		return nil, link.Errorf("this computer is not on a pen yet. Join first (hogman '<link>'),\n  or share with a server link: hogman share <name> <target> '<server link>'")
	case 1:
		return &sorted[0], nil
	}

	if u.IsTerminal() {
		u.Say("This computer is on more than one pen:")
		for i, p := range sorted {
			u.Say("  %d) %s", i+1, p.Zone)
		}
		ans := strings.TrimSpace(u.Ask(fmt.Sprintf("  Choose a pen [1-%d]: ", len(sorted))))
		idx, err := strconv.Atoi(ans)
		if err != nil || idx < 1 || idx > len(sorted) {
			return nil, link.Errorf("cancelled: choose a number between 1 and %d (or pass --pen <name>)", len(sorted))
		}
		return &sorted[idx-1], nil
	}

	zs := make([]string, len(sorted))
	for i, p := range sorted {
		zs[i] = p.Zone
	}
	return nil, link.Errorf("this computer is on several pens (%s); pick one with --pen <name> or set HOGMAN_PEN", strings.Join(zs, ", "))
}

// ResolveZoneFilter resolves an optional --pen / HOGMAN_PEN query against
// installed share zones (returning "" when no filter is active).
func ResolveZoneFilter(dirs []string, want string, u *ui.UI) (string, error) {
	return ResolveZoneFilterIn(state.ConfigBase(), dirs, want, u)
}

func ResolveZoneFilterIn(configBase string, dirs []string, want string, u *ui.UI) (string, error) {
	query, fromEnv, err := EffectivePenQuery(want)
	if err != nil {
		return "", err
	}
	if query == "" {
		return "", nil
	}
	zoneHost := map[string]string{}
	for _, d := range dirs {
		if c, err := state.LoadShare(d); err == nil && c.Zone != "" {
			zoneHost[c.Zone] = c.LoginServer
		}
	}
	for _, p := range MyPensIn(configBase) {
		if _, ok := zoneHost[p.Zone]; !ok {
			zoneHost[p.Zone] = p.LoginServer
		}
	}
	var matches []string
	for z, ls := range zoneHost {
		if link.PenMatchesQuery(z, ls, query) {
			matches = append(matches, z)
		}
	}
	sort.Strings(matches)
	switch len(matches) {
	case 1:
		if fromEnv {
			u.Note("using pen %s (from HOGMAN_PEN)", matches[0])
		}
		return matches[0], nil
	case 0:
		if fromEnv {
			u.Note("using pen %s (from HOGMAN_PEN)", query)
		}
		// Fall back to validated lowercased DNS query so callers print "shares nothing on <q>".
		return query, nil
	default:
		return "", link.Errorf("%q matches more than one pen (%s); pass the full zone name with --pen", query, strings.Join(matches, ", "))
	}
}
