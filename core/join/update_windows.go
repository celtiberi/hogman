package main

import "hogman/join/internal/state"

func serviceConfigured(string) bool { return false }

func startExistingBinary(bin, dir string, _ *state.AgentConfig, _ bool) error {
	return startDetached(bin, dir)
}

func rewriteAgentService(string, string, *state.AgentConfig) error { return nil }
func rewriteShareService(string, string, *state.ShareConfig) error { return nil }
