package main

import (
	"fmt"
	"strings"
)

// formatBrowserProxyInstructions returns plain, OS-specific one-time automatic
// proxy setup instructions using the stable, unversioned local PAC URL
// (http://127.0.0.1:<port>/proxy.pac). Hogman never asks for a Mac/system
// password to change proxy settings.
func formatBrowserProxyInstructions(goos, pacURL, zone string, zones []string) string {
	portal := "https://home." + zone
	multiNote := ""
	if len(zones) > 1 {
		multiNote = fmt.Sprintf("\n    (This same URL covers all %d pens: %s.)", len(zones), strings.Join(zones, ", "))
	}
	switch goos {
	case "darwin":
		return fmt.Sprintf(
			"Hogman never asks for your Mac password — set the automatic proxy URL once in System Settings:\n"+
				"    1. Open System Settings → Network → Wi-Fi (or Ethernet) → Details… → Proxies\n"+
				"    2. Turn on \"Automatic proxy configuration\" and paste:\n"+
				"         %s\n"+
				"    3. Click OK, then open %s%s\n"+
				"    (Using Firefox? Settings → Network Settings → Automatic proxy configuration URL works inside Firefox too.)\n"+
				"    We're working on a signed Mac app and Chrome/Firefox extensions so this will be automatic soon.",
			pacURL, portal, multiNote,
		)
	case "windows":
		return fmt.Sprintf(
			"Hogman never asks for administrator access — set the automatic proxy URL once in Windows Settings:\n"+
				"    1. Open Settings → Network & Internet → Proxy → \"Use setup script\" → Set up\n"+
				"    2. Turn on \"Use setup script\" and paste:\n"+
				"         %s\n"+
				"    3. Click Save, then open %s%s\n"+
				"    We're working on Chrome/Firefox extensions so this will be automatic soon.",
			pacURL, portal, multiNote,
		)
	default: // linux and other unix desktops
		return fmt.Sprintf(
			"Hogman never asks for your password — set your browser's automatic proxy URL once:\n"+
				"    • Firefox: Settings → Network Settings → Automatic proxy configuration URL → %s\n"+
				"    • System / Chrome (GNOME): Settings → Network → Network Proxy → Automatic → %s\n"+
				"    Then open %s%s\n"+
				"    We're working on Chrome/Firefox extensions so this will be automatic soon.",
			pacURL, pacURL, portal, multiNote,
		)
	}
}
