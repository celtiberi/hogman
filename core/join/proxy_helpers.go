package main

import (
	"encoding/xml"
	"fmt"
	"strings"
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
// left untouched so corporate proxies or another pen's PAC are not overwritten.
func shouldLeaveAutoProxy(curURL string, enabled bool, wantURL string) bool {
	return enabled && curURL != "" && curURL != wantURL
}

func xmlEscape(s string) (string, error) {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return "", err
	}
	return b.String(), nil
}

// renderLaunchPlist builds a macOS LaunchAgent plist with XML-escaped strings.
func renderLaunchPlist(label, bin, dir, logPath string) (string, error) {
	el, err := xmlEscape(label)
	if err != nil {
		return "", err
	}
	eb, err := xmlEscape(bin)
	if err != nil {
		return "", err
	}
	ed, err := xmlEscape(dir)
	if err != nil {
		return "", err
	}
	ep, err := xmlEscape(logPath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array><string>%s</string><string>agent</string><string>%s</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, el, eb, ed, ep, ep), nil
}

func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
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
`, zone, systemdQuote(bin), systemdQuote(dir))
}
