//go:build !darwin

package platform

import "hogman/join/internal/state"

func DetectSystemProxyState(_ []*state.AgentConfig) SystemProxyState {
	return SystemProxyState{}
}
