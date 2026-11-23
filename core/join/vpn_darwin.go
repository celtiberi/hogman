//go:build darwin

package main

import (
	"os/exec"
	"strings"
)

func detectSystemProxyState(known []*agentConfig) systemProxyState {
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
	for _, svc := range networkServices() {
		cur, enabled := autoProxyState(svc)
		if enabled && isHogmanPACURL(cur, known) {
			serviceHasHogmanPAC = true
			break
		}
	}
	return evaluateDarwinProxyState(proxy, primaryIface, serviceHasHogmanPAC, known)
}
