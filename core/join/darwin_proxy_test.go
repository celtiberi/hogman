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

func TestDarwinProxyCopyVariants(t *testing.T) {
	for _, mode := range []string{"set", "update", "remove"} {
		c := darwinProxyCopyFor(mode)
		if strings.Contains(c.SudoPrompt, "%") {
			t.Fatalf("%s sudo prompt must not contain raw %%: %q", mode, c.SudoPrompt)
		}
		if len(c.SudoPrompt) >= 80 {
			t.Fatalf("%s sudo prompt too long (%d chars): %q", mode, len(c.SudoPrompt), c.SudoPrompt)
		}
		if c.DialogPrompt == "" || c.DialogDone == "" || c.SudoAccepted == "" || c.CanceledMsg == "" {
			t.Fatalf("%s copy has empty fields: %+v", mode, c)
		}
	}
	if got := escapeSudoPrompt("100% done"); got != "100%% done" {
		t.Fatalf("escapeSudoPrompt = %q, want 100%%%% done", got)
	}
}

func TestApplyDarwinProxyOpsGUIBatchAndCancel(t *testing.T) {
	ops := []darwinProxyOp{
		{Action: "set", Service: "Wi-Fi", URL: "http://127.0.0.1:18123/proxy.pac?v=1"},
		{Action: "set", Service: "Ethernet", URL: "http://127.0.0.1:18123/proxy.pac?v=1"},
	}
	cp := darwinProxyCopyFor("set")

	// 1. GUI session runs ONE osascript call for multiple services and prints DialogDone.
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
	if err := applyDarwinProxyOps(cp, ops, r); err != nil {
		t.Fatalf("GUI apply failed: %v", err)
	}
	if osaCalls != 1 || sudoCalls != 0 {
		t.Fatalf("expected 1 osascript call and 0 sudo calls, got osa=%d sudo=%d", osaCalls, sudoCalls)
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "Mac login password") || !strings.Contains(joined, "✓ Mac automatic proxy set") {
		t.Fatalf("expected pre-dialog and DialogDone notes, got:\n%s", joined)
	}

	// 2. Dialog cancel returns clear error immediately (does not hang or invoke sudo).
	r.runOsascript = func([]string) (string, error) {
		return "execution error: User canceled. (-128)", errors.New("exit status 1")
	}
	err := applyDarwinProxyOps(cp, ops, r)
	if err == nil || !strings.Contains(err.Error(), "Cancelled") {
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
	cp := darwinProxyCopyFor("update")

	// 1. No GUI session (SSH) -> Option A wording, single sudo -v -p with reason,
	//    immediate "✓ Password accepted" printed BEFORE networksetup calls.
	var events []string
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
			events = append(events, "sudo-auth")
			return nil
		},
		runNetworksetup: func(useSudo bool, args ...string) (string, error) {
			if !useSudo {
				t.Fatal("expected sudo=true on non-root fallback")
			}
			events = append(events, "networksetup")
			nsCalls = append(nsCalls, args)
			return "", nil
		},
		note: func(format string, a ...any) { events = append(events, "note:"+fmt.Sprintf(format, a...)) },
	}
	if err := applyDarwinProxyOps(cp, ops, r); err != nil {
		t.Fatalf("SSH sudo fallback failed: %v", err)
	}
	if authCalls != 1 || len(nsCalls) != 2 {
		t.Fatalf("expected 1 sudo auth and 2 networksetup calls, got auth=%d ns=%d", authCalls, len(nsCalls))
	}
	if gotPrompt != cp.SudoPrompt {
		t.Fatalf("sudo -p prompt = %q, want %q", gotPrompt, cp.SudoPrompt)
	}
	// Verify ordering: sudo-auth -> note:✓ Password accepted -> networksetup.
	joined := strings.Join(events, "\n")
	if !strings.Contains(joined, "Nothing appears as you type") {
		t.Fatalf("missing no-echo guidance:\n%s", joined)
	}
	idxAuth, idxAcc, idxNS := -1, -1, -1
	for i, ev := range events {
		switch {
		case ev == "sudo-auth" && idxAuth < 0:
			idxAuth = i
		case strings.Contains(ev, "✓ Password accepted") && idxAcc < 0:
			idxAcc = i
		case ev == "networksetup" && idxNS < 0:
			idxNS = i
		}
	}
	if !(idxAuth >= 0 && idxAcc > idxAuth && idxNS > idxAcc) {
		t.Fatalf("expected sudo-auth -> ✓ Password accepted -> networksetup order, got %v", events)
	}

	// 2. Non-cancel osascript error (e.g. -1713 no user interaction) falls back to terminal sudo.
	authCalls = 0
	nsCalls = nil
	r.hasGUI = func() bool { return true }
	r.runOsascript = func([]string) (string, error) {
		return "execution error: No user interaction allowed. (-1713)", errors.New("exit status 1")
	}
	if err := applyDarwinProxyOps(cp, ops, r); err != nil {
		t.Fatalf("non-cancel osascript fallback failed: %v", err)
	}
	if authCalls != 1 || len(nsCalls) != 2 {
		t.Fatalf("expected sudo fallback after -1713, got auth=%d ns=%d", authCalls, len(nsCalls))
	}

	// 3. No GUI and no TTY -> refuses cleanly instead of hanging on sudo.
	r.hasGUI = func() bool { return false }
	r.stdinTTY = func() bool { return false }
	if err := applyDarwinProxyOps(cp, ops, r); err == nil || !strings.Contains(err.Error(), "no interactive terminal") {
		t.Fatalf("expected no-TTY error, got: %v", err)
	}

	// 4. Cached sudo runs directly with zero prompts.
	events = nil
	nsCalls = nil
	r.sudoCached = func() bool { return true }
	if err := applyDarwinProxyOps(cp, ops, r); err != nil {
		t.Fatalf("cached sudo failed: %v", err)
	}
	if len(events) != 2 || len(nsCalls) != 2 {
		t.Fatalf("cached sudo should run silently with 2 networksetup calls, got events=%v ns=%d", events, len(nsCalls))
	}
}
