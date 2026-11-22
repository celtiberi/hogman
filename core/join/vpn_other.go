//go:build !darwin

package main

func detectSystemProxyState(_ []*agentConfig) systemProxyState {
	return systemProxyState{}
}
