package main

import (
	"os"
	"os/exec"
	"strings"
)

const (
	darwinOsascriptPath    = "/usr/bin/osascript"
	darwinNetworksetupPath = "/usr/sbin/networksetup"
	darwinLaunchctlPath    = "/bin/launchctl"
)

func darwinHasGUISession() bool {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" || os.Getenv("SSH_CLIENT") != "" {
		return false
	}
	if info, err := os.Stat(darwinOsascriptPath); err != nil || info.IsDir() {
		return false
	}
	out, err := exec.Command(darwinLaunchctlPath, "managername").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "Aqua"
}

func darwinSudoCached() bool {
	sudo := sudoPath()
	if sudo == "" {
		return false
	}
	return exec.Command(sudo, "-n", "true").Run() == nil
}

func darwinRunSudoAuth(sudoPrompt string) error {
	sudo := sudoPath()
	if sudo == "" {
		return exec.ErrNotFound
	}
	cmd := exec.Command(sudo, "-v", "-p", sudoPrompt)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func defaultDarwinProxyRunner() darwinProxyRunner {
	return darwinProxyRunner{
		isRoot:     isRoot,
		sudoCached: darwinSudoCached,
		hasGUI:     darwinHasGUISession,
		stdinTTY:   func() bool { return isTerminalFn() },
		runOsascript: func(args []string) (string, error) {
			return run(false, darwinOsascriptPath, args...)
		},
		runSudoAuth: darwinRunSudoAuth,
		runNetworksetup: func(useSudo bool, args ...string) (string, error) {
			if useSudo && !isRoot() {
				if sudo := sudoPath(); sudo != "" {
					sudoArgs := append([]string{"-n", darwinNetworksetupPath}, args...)
					return run(false, sudo, sudoArgs...)
				}
			}
			return run(false, darwinNetworksetupPath, args...)
		},
		note: note,
	}
}
