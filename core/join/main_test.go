package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates HOME / XDG_CONFIG_HOME / AppData / USERPROFILE for every
// test in package main so no test can ever overwrite a developer's real
// Hogman config, LaunchAgents/systemd units, or canonical managed binary.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "hogman-join-test-home-*")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("HOME", tmp)
	_ = os.Setenv("USERPROFILE", tmp)
	_ = os.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, ".config"))
	_ = os.Setenv("AppData", filepath.Join(tmp, "AppData", "Roaming"))
	_ = os.Setenv("LOCALAPPDATA", filepath.Join(tmp, "AppData", "Local"))
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}
