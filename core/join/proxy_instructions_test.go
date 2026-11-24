package main

import (
	"strings"
	"testing"
)

func TestFormatBrowserProxyInstructionsByOS(t *testing.T) {
	pac := "http://127.0.0.1:18123/proxy.pac"

	mac := formatBrowserProxyInstructions("darwin", pac, "acme.pens.example", []string{"acme.pens.example"})
	for _, want := range []string{
		"never asks for your Mac password",
		"System Settings → Network → Wi-Fi (or Ethernet) → Details… → Proxies",
		"Automatic proxy configuration",
		pac,
		"https://home.acme.pens.example",
		"signed Mac app",
	} {
		if !strings.Contains(mac, want) {
			t.Fatalf("darwin instructions missing %q:\n%s", want, mac)
		}
	}
	if strings.Contains(mac, "even with a VPN on") {
		t.Fatalf("darwin instructions should not make untested VPN claims:\n%s", mac)
	}
	if strings.Contains(mac, "?v=") {
		t.Fatalf("manual PAC URL must stay stable without ?v=: %s", mac)
	}

	lin := formatBrowserProxyInstructions("linux", pac, "acme.pens.example", []string{"acme.pens.example", "ops.pens.example"})
	for _, want := range []string{
		"Firefox: Settings → Network Settings",
		"GNOME",
		pac,
		"covers all 2 pens: acme.pens.example, ops.pens.example",
	} {
		if !strings.Contains(lin, want) {
			t.Fatalf("linux instructions missing %q:\n%s", want, lin)
		}
	}

	win := formatBrowserProxyInstructions("windows", pac, "acme.pens.example", []string{"acme.pens.example"})
	for _, want := range []string{
		"Settings → Network & Internet → Proxy",
		"Use setup script",
		pac,
	} {
		if !strings.Contains(win, want) {
			t.Fatalf("windows instructions missing %q:\n%s", want, win)
		}
	}
}
