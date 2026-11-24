package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Seams for unit tests of interactive TTY pen picking and link prompting.
var (
	isTerminalFn = isTerminal
	askFn        = ask
)

// penMatchesQuery reports whether a pen (zone + optional control host) matches
// a user query: exact full zone, exact control host, or exact short name (first
// DNS label before '.', never a partial prefix).
func penMatchesQuery(zone, loginServer, query string) bool {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(query)), ".")
	if q == "" {
		return false
	}
	z := strings.ToLower(zone)
	if q == z {
		return true
	}
	if h := hostOf(loginServer); h != "" && q == h {
		return true
	}
	if !strings.Contains(q, ".") {
		if first, _, ok := strings.Cut(z, "."); ok && first == q {
			return true
		}
	}
	return false
}

// effectivePenQuery returns the explicit --pen flag value, falling back to
// HOGMAN_PEN when --pen is empty.
func effectivePenQuery(flagVal string) string {
	if q := strings.TrimSpace(flagVal); q != "" {
		return q
	}
	return strings.TrimSpace(os.Getenv("HOGMAN_PEN"))
}

// resolvePenConn picks a single joined pen using --pen, HOGMAN_PEN, sole pen,
// or an interactive TTY picker when multiple pens are installed.
func resolvePenConn(pens []penConn, want string) (*penConn, error) {
	sorted := make([]penConn, len(pens))
	copy(sorted, pens)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].zone < sorted[j].zone })

	query := effectivePenQuery(want)
	if query != "" {
		var matches []penConn
		for _, p := range sorted {
			if penMatchesQuery(p.zone, p.loginServer, query) {
				matches = append(matches, p)
			}
		}
		switch len(matches) {
		case 1:
			return &matches[0], nil
		case 0:
			if len(sorted) == 0 {
				return nil, errorf("this computer is not on %s (no pens installed)", query)
			}
			zs := make([]string, len(sorted))
			for i, p := range sorted {
				zs[i] = p.zone
			}
			return nil, errorf("this computer is not on %s (installed pens: %s)", query, strings.Join(zs, ", "))
		default:
			zs := make([]string, len(matches))
			for i, p := range matches {
				zs[i] = p.zone
			}
			return nil, errorf("%q matches more than one pen (%s); pass the full zone name with --pen", query, strings.Join(zs, ", "))
		}
	}

	switch len(sorted) {
	case 0:
		return nil, errorf("this computer is not on a pen yet. Join first (hogman-join '<link>'),\n  or share with a server link: hogman-join share <name> <target> '<server link>'")
	case 1:
		return &sorted[0], nil
	}

	// Multiple pens installed and no --pen / HOGMAN_PEN set.
	if isTerminalFn() {
		say("This computer is on more than one pen:")
		for i, p := range sorted {
			say("  %d) %s", i+1, p.zone)
		}
		ans := strings.TrimSpace(askFn(fmt.Sprintf("  Choose a pen [1-%d]: ", len(sorted))))
		idx, err := strconv.Atoi(ans)
		if err != nil || idx < 1 || idx > len(sorted) {
			return nil, errorf("cancelled: choose a number between 1 and %d (or pass --pen <name>)", len(sorted))
		}
		return &sorted[idx-1], nil
	}

	zs := make([]string, len(sorted))
	for i, p := range sorted {
		zs[i] = p.zone
	}
	return nil, errorf("this computer is on several pens (%s); pick one with --pen <name> or set HOGMAN_PEN", strings.Join(zs, ", "))
}

// resolveShareZoneFilter resolves an optional --pen / HOGMAN_PEN query against
// installed share zones (returning "" when no filter is active).
func resolveShareZoneFilter(dirs []string, want string) (string, error) {
	query := effectivePenQuery(want)
	if query == "" {
		return "", nil
	}
	zoneHost := map[string]string{}
	for _, d := range dirs {
		if c, err := loadShare(d); err == nil && c.Zone != "" {
			zoneHost[c.Zone] = c.LoginServer
		}
	}
	for _, p := range myPens() {
		if _, ok := zoneHost[p.zone]; !ok {
			zoneHost[p.zone] = p.loginServer
		}
	}
	var matches []string
	for z, ls := range zoneHost {
		if penMatchesQuery(z, ls, query) {
			matches = append(matches, z)
		}
	}
	sort.Strings(matches)
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		// Fall back to literal lowercased query so callers print "shares nothing on <q>".
		return strings.TrimSuffix(strings.ToLower(query), "."), nil
	default:
		return "", errorf("%q matches more than one pen (%s); pass the full zone name with --pen", query, strings.Join(matches, ", "))
	}
}
