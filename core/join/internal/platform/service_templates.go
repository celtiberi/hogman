package platform

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"

	"hogman/join/internal/state"
)

func xmlEscape(s string) (string, error) {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return "", err
	}
	return b.String(), nil
}

func LaunchLabel(zone string) string { return "network.hogman." + zone }

func UnitName(zone string) string { return "hogman-" + zone + ".service" }

func ShareLaunchLabel(c *state.ShareConfig) string { return "network.hogman.share." + c.FQDN() }

func ShareUnitName(c *state.ShareConfig) string { return "hogman-share-" + c.FQDN() + ".service" }

func WindowsRunValueName(zone string) string { return "Hogman." + zone }

func WindowsShareRunValueName(c *state.ShareConfig) string { return "Hogman.share." + c.FQDN() }

func winQuoteArg(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("empty Windows command argument")
	}
	if strings.ContainsAny(s, "\r\n\x00\"") {
		return "", fmt.Errorf("Windows command argument contains disallowed control or quote characters")
	}
	// Per Win32 CommandLineToArgvW rules, backslashes immediately preceding the
	// closing double-quote must be doubled so the closing quote is not escaped.
	trailingBS := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		trailingBS++
	}
	if trailingBS > 0 {
		s += strings.Repeat(`\`, trailingBS)
	}
	return `"` + s + `"`, nil
}

// RenderWindowsRunCommand builds the HKCU\...\Run command line for starting a
// pen agent or share cleanly in the background at user login without leaving a
// console window open.
func RenderWindowsRunCommand(bin, kind, dir string) (string, error) {
	if kind != "agent" && kind != "share" {
		return "", fmt.Errorf("invalid Windows autostart target kind %q", kind)
	}
	qBin, err := winQuoteArg(bin)
	if err != nil {
		return "", fmt.Errorf("binary path: %w", err)
	}
	qDir, err := winQuoteArg(dir)
	if err != nil {
		return "", fmt.Errorf("state dir: %w", err)
	}
	return fmt.Sprintf("%s __start-detached %s %s", qBin, kind, qDir), nil
}

// RenderLaunchPlist builds a macOS LaunchAgent plist for a pen agent.
func RenderLaunchPlist(label, bin, dir, logPath string) (string, error) {
	return renderLaunchPlistArgs(label, bin, []string{"agent", dir}, logPath, false)
}

// RenderShareLaunchPlist builds a macOS LaunchAgent plist for a managed share.
func RenderShareLaunchPlist(c *state.ShareConfig, bin, dir string) (string, error) {
	return renderLaunchPlistArgs(ShareLaunchLabel(c), bin, []string{"__share-run", dir}, filepath.Join(dir, "share.log"), true)
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

// RenderSystemdUnit builds a systemd user service unit with quoted ExecStart paths.
func RenderSystemdUnit(zone, bin, dir string) string {
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

// RenderShareSystemdUnit builds a systemd user service unit for a persistent share.
func RenderShareSystemdUnit(c *state.ShareConfig, bin, dir string) string {
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
