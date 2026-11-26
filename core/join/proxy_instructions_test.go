package main

import (
	"slices"
	"strings"
	"testing"
)

func TestParseNetworkServiceOrderHardwareFilter(t *testing.T) {
	raw := `An asterisk (*) denotes that a network service is disabled.
(1) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(3) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)

(4) ProtonVPN
(Hardware Port: ch.protonvpn.mac, Device: )

(*) Disabled Ethernet
(Hardware Port: Ethernet, Device: en1)

(5) Corporate Tunnel
(Hardware Port: VPN, Device: utun4)
`
	got := hardwareServiceNamesFromOrder(raw)
	want := []string{"Wi-Fi", "USB 10/100/1000 LAN"}
	if !slices.Equal(got, want) {
		t.Fatalf("hardwareServiceNamesFromOrder = %v, want %v", got, want)
	}
}

func TestFormatServiceList(t *testing.T) {
	if got := formatServiceList(nil); got != "Wi-Fi (or Ethernet)" {
		t.Fatalf("0 services = %q", got)
	}
	if got := formatServiceList([]string{"Wi-Fi"}); got != "Wi-Fi" {
		t.Fatalf("1 service = %q", got)
	}
	if got := formatServiceList([]string{"Wi-Fi", "USB 10/100/1000 LAN"}); got != "Wi-Fi and USB 10/100/1000 LAN" {
		t.Fatalf("2 services = %q", got)
	}
	if got := formatServiceList([]string{"Wi-Fi", "USB 10/100/1000 LAN", "iPhone USB"}); got != "Wi-Fi, USB 10/100/1000 LAN, and iPhone USB" {
		t.Fatalf("3 services = %q", got)
	}
}

func TestFormatBrowserProxyInstructionsByOS(t *testing.T) {
	pac := "http://127.0.0.1:18123/proxy.pac"

	macMulti := formatBrowserProxyInstructions("darwin", pac, "acme.pens.example", []string{"acme.pens.example"}, []string{"Wi-Fi", "USB 10/100/1000 LAN"})
	const extLead = "Using Chrome, Brave, Edge, Arc, or Vivaldi? Install the Hogman browser extension, then open its popup and turn on acme.pens.example. No proxy settings needed."
	if !strings.HasPrefix(macMulti, extLead) {
		t.Fatalf("darwin instructions should open with extension lead:\n%s", macMulti)
	}
	if strings.Contains(macMulti, "nothing else to set") {
		t.Fatalf("darwin instructions must not claim nothing else to set (empty allowlist requires popup toggle):\n%s", macMulti)
	}
	for _, want := range []string{
		chromeExtensionStoreURL,
		"Firefox: coming soon",
		"Other browsers (Safari, or no extension)",
		"never asks for your Mac password",
		"System Settings → Network → Wi-Fi and USB 10/100/1000 LAN → Details… → Proxies (set it on each one)",
		"Automatic proxy configuration",
		pac,
		"https://home.acme.pens.example",
	} {
		if !strings.Contains(macMulti, want) {
			t.Fatalf("darwin multi-service instructions missing %q:\n%s", want, macMulti)
		}
	}
	if strings.Contains(macMulti, "Tip:") {
		t.Fatalf("darwin instructions should drop trailing Tip line:\n%s", macMulti)
	}
	if strings.Contains(macMulti, "automatic soon") || strings.Contains(macMulti, "signed Mac app") {
		t.Fatalf("darwin instructions contain stale or unbuilt promises:\n%s", macMulti)
	}
	if strings.Contains(macMulti, "even with a VPN on") {
		t.Fatalf("darwin instructions should not make untested VPN claims:\n%s", macMulti)
	}
	if strings.Contains(macMulti, "?v=") {
		t.Fatalf("manual PAC URL must stay stable without ?v=: %s", macMulti)
	}

	macSingle := formatBrowserProxyInstructions("darwin", pac, "acme.pens.example", []string{"acme.pens.example"}, []string{"Wi-Fi"})
	if !strings.Contains(macSingle, "System Settings → Network → Wi-Fi → Details… → Proxies\n") {
		t.Fatalf("darwin single-service instructions should name Wi-Fi cleanly:\n%s", macSingle)
	}

	macFallback := formatBrowserProxyInstructions("darwin", pac, "acme.pens.example", []string{"acme.pens.example"}, nil)
	if !strings.Contains(macFallback, "System Settings → Network → Wi-Fi (or Ethernet) → Details… → Proxies\n") {
		t.Fatalf("darwin fallback instructions unexpected:\n%s", macFallback)
	}

	lin := formatBrowserProxyInstructions("linux", pac, "acme.pens.example", []string{"acme.pens.example", "ops.pens.example"}, nil)
	if !strings.HasPrefix(lin, extLead) || strings.Contains(lin, "Tip:") {
		t.Fatalf("linux instructions should open with extension lead and drop Tip:\n%s", lin)
	}
	for _, want := range []string{
		"Other browsers (or no extension)",
		"Firefox: Settings → Network Settings",
		"GNOME",
		pac,
		"covers all 2 pens: acme.pens.example, ops.pens.example",
	} {
		if !strings.Contains(lin, want) {
			t.Fatalf("linux instructions missing %q:\n%s", want, lin)
		}
	}

	win := formatBrowserProxyInstructions("windows", pac, "acme.pens.example", []string{"acme.pens.example"}, nil)
	if !strings.HasPrefix(win, extLead) || strings.Contains(win, "Tip:") {
		t.Fatalf("windows instructions should open with extension lead and drop Tip:\n%s", win)
	}
	for _, want := range []string{
		"Other browsers (or no extension)",
		"Settings → Network & Internet → Proxy",
		"Use setup script",
		pac,
	} {
		if !strings.Contains(win, want) {
			t.Fatalf("windows instructions missing %q:\n%s", want, win)
		}
	}
}

func TestFormatDarwinProxySummaryFlagsMissingServices(t *testing.T) {
	pac := "http://127.0.0.1:18123/proxy.pac"

	allSet := formatDarwinProxySummary([]string{"Wi-Fi"}, nil, pac, pac, "acme.pens.example", []string{"acme.pens.example"})
	if strings.Contains(allSet, "not set on") {
		t.Fatalf("unexpected missing-service warning when all set:\n%s", allSet)
	}

	partial := formatDarwinProxySummary([]string{"Wi-Fi"}, []string{"USB 10/100/1000 LAN"}, pac, pac, "acme.pens.example", []string{"acme.pens.example"})
	for _, want := range []string{
		"already configured on Wi-Fi",
		"Automatic proxy configuration is not set on USB 10/100/1000 LAN yet",
		"System Settings → Network → USB 10/100/1000 LAN → Details… → Proxies",
		pac,
	} {
		if !strings.Contains(partial, want) {
			t.Fatalf("partial summary missing %q:\n%s", want, partial)
		}
	}
}
