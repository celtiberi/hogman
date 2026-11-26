//go:build !windows

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestStopProcessHelper(t *testing.T) {
	mode := os.Getenv("GO_TEST_STOP_PROCESS_MODE")
	if mode == "" {
		return
	}
	if mode == "ignore-term" {
		signal.Ignore(syscall.SIGTERM)
	}
	time.Sleep(30 * time.Second)
}

func TestStopProcessGracefulAndForcedKill(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        string
		termTimeout time.Duration
	}{
		{name: "graceful SIGTERM", mode: "default", termTimeout: 2 * time.Second},
		{name: "escalates to SIGKILL when SIGTERM ignored", mode: "ignore-term", termTimeout: 250 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestStopProcessHelper$")
			cmd.Env = append(os.Environ(), "GO_TEST_STOP_PROCESS_MODE="+tc.mode)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			// Brief pause so the child reaches signal.Ignore before SIGTERM arrives.
			if tc.mode == "ignore-term" {
				time.Sleep(150 * time.Millisecond)
			}
			stopProcess(cmd.Process.Pid, tc.termTimeout)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatalf("process %d did not exit after stopProcess", cmd.Process.Pid)
			}
			if processAlive(cmd.Process.Pid) {
				t.Fatalf("process %d still reported alive", cmd.Process.Pid)
			}
		})
	}
}
