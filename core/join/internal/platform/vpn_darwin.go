//go:build darwin

package platform

import (
	"os/exec"
	"strings"

	"hogman/join/internal/state"
)

func DetectSystemProxyState(known []*state.AgentConfig) SystemProxyState {
	proxyOut, err := exec.Command("/usr/sbin/scutil", "--proxy").Output()
	if err != nil {
		return SystemProxyState{}
	}
	proxy := ParseScutilProxy(string(proxyOut))

	cmd := exec.Command("/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader("show State:/Network/Global/IPv4\n")
	ipv4Out, _ := cmd.Output()
	primaryIface := ParseScutilPrimaryInterface(string(ipv4Out))

	serviceHasHogmanPAC := false
	var missing []string
	seen := map[string]bool{}
	for _, svc := range hardwareNetworkServices() {
		seen[svc] = true
		cur, enabled := autoProxyState(svc)
		if enabled && state.IsHogmanPACURL(cur, known) {
			serviceHasHogmanPAC = true
		} else if len(known) > 0 && !ShouldLeaveAutoProxy(cur, enabled, known) {
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
	st := EvaluateDarwinProxyState(proxy, primaryIface, serviceHasHogmanPAC, known)
	st.MissingProxyServices = missing
	return st
}
