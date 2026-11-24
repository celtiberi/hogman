package main

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestBuildDarwinOsascriptArgs(t *testing.T) {
	ops := []darwinProxyOp{
		{Action: "set", Service: "Wi-Fi 'Home' $(id)", URL: "http://127.0.0.1:18123/proxy.pac?v=1"},
		{Action: "off", Service: "USB 10/100/1000 LAN"},
	}
	prompt := "Hogman needs to set this Mac's automatic proxy to reach your pen"
	args, err := buildDarwinOsascriptArgs(prompt, ops)
	if err != nil {
		t.Fatalf("buildDarwinOsascriptArgs error: %v", err)
	}
	want := []string{
		"-e", darwinProxyAppleScript, "--",
		prompt,
		"set", "Wi-Fi 'Home' $(id)", "http://127.0.0.1:18123/proxy.pac?v=1",
		"off", "USB 10/100/1000 LAN",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("argv mismatch:\ngot:  %#v\nwant: %#v", args, want)
	}
	// Script source must stay static and never contain runtime service names or URLs.
	if strings.Contains(args[1], "Wi-Fi") || strings.Contains(args[1], "18123") {
		t.Fatal("AppleScript source must not interpolate runtime arguments")
	}
	if !strings.Contains(args[1], "/usr/sbin/networksetup") || !strings.Contains(args[1], "quoted form of") {
		t.Fatal("AppleScript must use absolute /usr/sbin/networksetup and quoted form of")
	}

	// Reject bad URLs, newline injection, and unknown actions.
	for _, badOp := range []darwinProxyOp{
		{Action: "set", Service: "Wi-Fi", URL: "https://evil.example/proxy.pac"},
		{Action: "set", Service: "Wi-Fi", URL: "http://127.0.0.1:18123/other"},
		{Action: "set", Service: "Wi-Fi\nEvil", URL: "http://127.0.0.1:18123/proxy.pac"},
		{Action: "off", Service: "Wi-Fi", URL: "http://127.0.0.1:18123/proxy.pac"},
		{Action: "rm", Service: "Wi-Fi"},
	} {
		if _, err := buildDarwinOsascriptArgs(prompt, []darwinProxyOp{badOp}); err == nil {
			t.Fatalf("expected error for invalid op %+v", badOp)
		}
	}
}

func TestApplyDarwinProxyOpsGUIBatchAndCancel(t *testing.T) {
	ops := []darwinProxyOp{
		{Action: "set", Service: "Wi-Fi", URL: "http://127.0.0.1:18123/proxy.pac?v=1"},
		{Action: "set", Service: "Ethernet", URL: "http://127.0.0.1:18123/proxy.pac?v=1"},
	}
	prompt := "Hogman needs to set this Mac's automatic proxy to reach your pen"
	why := "to point this Mac's automatic proxy at the pen"

	// 1. GUI session runs ONE osascript call for multiple services and prints confirmation.
	var osaCalls int
	var sudoCalls int
	var notes []string
	r := darwinProxyRunner{
		isRoot:     func() bool { return false },
		sudoCached: func() bool { return false },
		hasGUI:     func() bool { return true },
		stdinTTY:   func() bool { return true },
		runOsascript: func(args []string) (string, error) {
			osaCalls++
			if len(args) != 10 {
				t.Fatalf("expected 10 osascript args for 2 batched set ops, got %d: %#v", len(args), args)
			}
			return "", nil
		},
		runSudoAuth: func(string) error { sudoCalls++; return nil },
		runNetworksetup: func(bool, ...string) (string, error) {
			t.Fatal("networksetup should not be called directly when osascript succeeds")
			return "", nil
		},
		note: func(format string, a ...any) { notes = append(notes, fmt.Sprintf(format, a...)) },
	}
	if err := applyDarwinProxyOps(prompt, why, ops, r); err != nil {
		t.Fatalf("GUI apply failed: %v", err)
	}
	if osaCalls != 1 || sudoCalls != 0 {
		t.Fatalf("expected 1 osascript call and 0 sudo calls, got osa=%d sudo=%d", osaCalls, sudoCalls)
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "macOS password prompt") || !strings.Contains(joined, "Got it") {
		t.Fatalf("expected pre-prompt and confirmation notes, got:\n%s", joined)
	}

	// 2. Dialog cancel returns clear error immediately (does not hang or invoke sudo).
	r.runOsascript = func([]string) (string, error) {
		return "execution error: User canceled. (-128)", errors.New("exit status 1")
	}
	err := applyDarwinProxyOps(prompt, why, ops, r)
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("expected clear cancel error, got: %v", err)
	}
	if sudoCalls != 0 {
		t.Fatalf("cancel must not invoke terminal sudo, got sudoCalls=%d", sudoCalls)
	}
}

func TestApplyDarwinProxyOpsSudoFallbackPaths(t *testing.T) {
	ops := []darwinProxyOp{
		{Action: "set", Service: "Wi-Fi", URL: "http://127.0.0.1:18123/proxy.pac?v=1"},
		{Action: "off", Service: "Thunderbolt Bridge"},
	}
	prompt := "Hogman needs to update this Mac's automatic proxy setting"
	why := "to update this Mac's automatic proxy setting"

	// 1. No GUI session (SSH) -> Option A wording, single sudo -v -p with reason, immediate "Got it" confirmation, then batched networksetup calls.
	var notes []string
	var authCalls int
	var gotPrompt string
	var nsCalls [][]string
	r := darwinProxyRunner{
		isRoot:     func() bool { return false },
		sudoCached: func() bool { return false },
		hasGUI:     func() bool { return false },
		stdinTTY:   func() bool { return true },
		runSudoAuth: func(p string) error {
			authCalls++
			gotPrompt = p
			return nil
		},
		runNetworksetup: func(useSudo bool, args ...string) (string, error) {
			if !useSudo {
				t.Fatal("expected sudo=true on non-root fallback")
			}
			nsCalls = append(nsCalls, args)
			return "", nil
		},
		note: func(format string, a ...any) { notes = append(notes, fmt.Sprintf(format, a...)) },
	}
	if err := applyDarwinProxyOps(prompt, why, ops, r); err != nil {
		t.Fatalf("SSH sudo fallback failed: %v", err)
	}
	if authCalls != 1 || len(nsCalls) != 2 {
		t.Fatalf("expected 1 sudo auth and 2 networksetup calls, got auth=%d ns=%d", authCalls, len(nsCalls))
	}
	if !strings.Contains(gotPrompt, "Mac login password") || !strings.Contains(gotPrompt, "nothing shows as you type") {
		t.Fatalf("sudo -p prompt missing reason/no-echo hint: %q", gotPrompt)
	}
	if escaped := buildDarwinSudoPrompt("to set 100% proxy"); !strings.Contains(escaped, "100%%") {
		t.Fatalf("buildDarwinSudoPrompt did not escape %%: %q", escaped)
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "Nothing shows on screen as you type") || !strings.Contains(joined, "Got it, updating") {
		t.Fatalf("expected Option A guidance + confirmation, got:\n%s", joined)
	}

	// 2. Non-cancel osascript error (e.g. -1713 no user interaction) falls back to terminal sudo.
	authCalls = 0
	nsCalls = nil
	r.hasGUI = func() bool { return true }
	r.runOsascript = func([]string) (string, error) {
		return "execution error: No user interaction allowed. (-1713)", errors.New("exit status 1")
	}
	if err := applyDarwinProxyOps(prompt, why, ops, r); err != nil {
		t.Fatalf("non-cancel osascript fallback failed: %v", err)
	}
	if authCalls != 1 || len(nsCalls) != 2 {
		t.Fatalf("expected sudo fallback after -1713, got auth=%d ns=%d", authCalls, len(nsCalls))
	}

	// 3. No GUI and no TTY -> refuses cleanly instead of hanging on sudo.
	r.hasGUI = func() bool { return false }
	r.stdinTTY = func() bool { return false }
	if err := applyDarwinProxyOps(prompt, why, ops, r); err == nil || !strings.Contains(err.Error(), "no interactive terminal") {
		t.Fatalf("expected no-TTY error, got: %v", err)
	}

	// 4. Cached sudo runs directly with zero prompts.
	notes = nil
	nsCalls = nil
	r.sudoCached = func() bool { return true }
	if err := applyDarwinProxyOps(prompt, why, ops, r); err != nil {
		t.Fatalf("cached sudo failed: %v", err)
	}
	if len(notes) != 0 || len(nsCalls) != 2 {
		t.Fatalf("cached sudo should run silently with 2 networksetup calls, got notes=%v ns=%d", notes, len(nsCalls))
	}
}
