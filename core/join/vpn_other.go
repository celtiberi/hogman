//go:build !darwin

package main

import "hogman/join/internal/state"

func detectSystemProxyState(_ []*state.AgentConfig) systemProxyState {
	return systemProxyState{}
}
