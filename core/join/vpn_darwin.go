//go:build darwin

package main

import (
	"os/exec"
	"strings"

	"hogman/join/internal/state"
)

func detectSystemProxyState(known []*state.AgentConfig) systemProxyState {
	proxyOut, err := exec.Command("/usr/sbin/scutil", "--proxy").Output()
	if err != nil {
		return systemProxyState{}
	}
	proxy := parseScutilProxy(string(proxyOut))

	cmd := exec.Command("/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader("show State:/Network/Global/IPv4\n")
	ipv4Out, _ := cmd.Output()
	primaryIface := parseScutilPrimaryInterface(string(ipv4Out))

	serviceHasHogmanPAC := false
	var missing []string
	seen := map[string]bool{}
	for _, svc := range hardwareNetworkServices() {
		seen[svc] = true
		cur, enabled := autoProxyState(svc)
		if enabled && state.IsHogmanPACURL(cur, known) {
			serviceHasHogmanPAC = true
		} else if len(known) > 0 && !shouldLeaveAutoProxy(cur, enabled, known) {
			missing = append(missing, svc)
		}
	}
	if !serviceHasHogmanPAC {
		for _, svc := range networkServices() {
			if seen[svc] {
				continue
			}
			cur, enabled := autoProxyState(svc)
			if enabled && state.IsHogmanPACURL(cur, known) {
				serviceHasHogmanPAC = true
				break
			}
		}
	}
	st := evaluateDarwinProxyState(proxy, primaryIface, serviceHasHogmanPAC, known)
	st.MissingProxyServices = missing
	return st
}
