package main

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"

	"hogman/join/internal/state"
)

// parseAutoProxyOutput parses the output of `networksetup -getautoproxyurl`.
func parseAutoProxyOutput(out string) (url string, enabled bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "URL:"):
			u := strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
			if u != "(null)" {
				url = u
			}
		case strings.HasPrefix(line, "Enabled:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "Enabled:"))
			enabled = strings.EqualFold(v, "Yes")
		}
	}
	return url, enabled
}

// shouldLeaveAutoProxy reports whether an existing system PAC setting should be
// left untouched so corporate proxies or unknown local proxies are not overwritten.
func shouldLeaveAutoProxy(curURL string, enabled bool, known []*state.AgentConfig) bool {
	return enabled && curURL != "" && !isOurPAC(curURL, known)
}

// isOurPAC: a running pen's rules file, or one a removed pen left behind.
func isOurPAC(curURL string, known []*state.AgentConfig) bool {
	return state.IsHogmanPACURL(curURL, known) || staleHogmanPAC(curURL)
}

func xmlEscape(s string) (string, error) {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return "", err
	}
	return b.String(), nil
}

func launchLabel(zone string) string { return "network.hogman." + zone }

func unitName(zone string) string { return "hogman-" + zone + ".service" }

func shareLaunchLabel(c *state.ShareConfig) string { return "network.hogman.share." + c.FQDN() }

func shareUnitName(c *state.ShareConfig) string { return "hogman-share-" + c.FQDN() + ".service" }

// renderLaunchPlist builds a macOS LaunchAgent plist for a pen agent.
func renderLaunchPlist(label, bin, dir, logPath string) (string, error) {
	return renderLaunchPlistArgs(label, bin, []string{"agent", dir}, logPath, false)
}

func renderShareLaunchPlist(c *state.ShareConfig, bin, dir string) (string, error) {
	return renderLaunchPlistArgs(shareLaunchLabel(c), bin, []string{"__share-run", dir}, filepath.Join(dir, "share.log"), true)
}

// renderLaunchPlistArgs builds a macOS LaunchAgent plist with XML-escaped strings.
// When stopOnZeroExit is true, launchd stops relaunching on exit 0 and backs
// off restarts by 30s on transient non-zero failures.
func renderLaunchPlistArgs(label, bin string, args []string, logPath string, stopOnZeroExit bool) (string, error) {
	el, err := xmlEscape(label)
	if err != nil {
		return "", err
	}
	eb, err := xmlEscape(bin)
	if err != nil {
		return "", err
	}
	ep, err := xmlEscape(logPath)
	if err != nil {
		return "", err
	}
	var prog strings.Builder
	prog.WriteString("<string>")
	prog.WriteString(eb)
	prog.WriteString("</string>")
	for _, a := range args {
		ea, err := xmlEscape(a)
		if err != nil {
			return "", err
		}
		prog.WriteString("<string>")
		prog.WriteString(ea)
		prog.WriteString("</string>")
	}
	keepAlive := "<key>KeepAlive</key><true/>"
	if stopOnZeroExit {
		keepAlive = "<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n  <key>ThrottleInterval</key><integer>30</integer>"
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array>%s</array>
  <key>RunAtLoad</key><true/>
  %s
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, el, prog.String(), keepAlive, ep, ep), nil
}

func systemdQuote(s string) string {
	// Strip CR/LF so a path cannot inject new unit directives, and escape
	// systemd specifiers (%), environment expansion ($), backslashes, and quotes.
	r := strings.NewReplacer("\r", "", "\n", "", "%", "%%", "$", "$$", `\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

func systemdSingleLine(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// renderSystemdUnit builds a systemd user service unit with quoted ExecStart paths.
func renderSystemdUnit(zone, bin, dir string) string {
	return fmt.Sprintf(`[Unit]
Description=Hogman pen connection (%s)
After=network-online.target

[Service]
ExecStart=%s agent %s
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`, systemdSingleLine(zone), systemdQuote(bin), systemdQuote(dir))
}

// renderShareSystemdUnit builds a systemd user service unit for a persistent share.
func renderShareSystemdUnit(c *state.ShareConfig, bin, dir string) string {
	return fmt.Sprintf(`[Unit]
Description=Hogman share (%s)
After=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
ExecStart=%s __share-run %s
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
`, systemdSingleLine(c.FQDN()), systemdQuote(bin), systemdQuote(dir))
}
