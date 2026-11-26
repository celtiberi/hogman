package main

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type agentEndpointState int

const (
	agentEndpointDown agentEndpointState = iota
	agentEndpointUp
	agentEndpointSquatted
)

type agentEndpointDetail struct {
	reason     string
	needsLogin bool
	verified   bool // true only when status.token HMAC proof matched
}

// loopbackStatusTransport disables keep-alive pooling so frequent 1-second
// loopback /status probes never accumulate idle sockets or readLoop/writeLoop
// goroutines in hogman-native-host or hogman agent.
var loopbackStatusTransport = &http.Transport{
	Proxy:             nil,
	DisableKeepAlives: true,
}

type agentProbeResult struct {
	state    agentEndpointState
	status   *agentStatus
	verified bool
	err      error
}

// probeAgentStatus performs the single authenticated challenge-response probe
// against a pen agent's loopback /status endpoint. It fails closed whenever
// status.token is missing, the response is non-200 or malformed, the zone
// mismatches, or the HMAC proof does not match.
func probeAgentStatus(dir string, cfg *agentConfig, timeout time.Duration) agentProbeResult {
	tokBytes, tokErr := os.ReadFile(filepath.Join(dir, statusTokenFilename))
	token := strings.TrimSpace(string(tokBytes))

	nonce, err := generateHexToken(16)
	if err != nil {
		return agentProbeResult{state: agentEndpointDown, err: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.proxyURL()+"/status", nil)
	if err != nil {
		return agentProbeResult{state: agentEndpointDown, err: err}
	}
	req.Header.Set("X-Hogman-Challenge", nonce)
	client := &http.Client{
		Timeout:       timeout,
		Transport:     loopbackStatusTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return agentProbeResult{state: agentEndpointDown, err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return agentProbeResult{
			state: agentEndpointSquatted,
			err:   fmt.Errorf("something else is listening on %s", cfg.ProxyAddr),
		}
	}

	var st agentStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&st); err != nil {
		return agentProbeResult{state: agentEndpointSquatted, err: err}
	}
	if st.Zone != cfg.Zone {
		return agentProbeResult{
			state: agentEndpointSquatted,
			err:   fmt.Errorf("something else is listening on %s", cfg.ProxyAddr),
		}
	}

	// Fail closed whenever status.token is missing, unreadable, empty, or the
	// listener fails the challenge-response HMAC proof: an unauthenticated
	// loopback process must never be trusted as a Hogman agent.
	if tokErr != nil || token == "" {
		return agentProbeResult{
			state: agentEndpointSquatted,
			err:   fmt.Errorf("missing agent status token for %s", cfg.Zone),
		}
	}
	gotProof := strings.TrimSpace(resp.Header.Get("X-Hogman-Proof"))
	wantProof := computeStatusProof(token, nonce, cfg.Zone)
	if gotProof == "" || !hmac.Equal([]byte(gotProof), []byte(wantProof)) {
		return agentProbeResult{
			state: agentEndpointSquatted,
			err:   fmt.Errorf("unverified process listening on %s", cfg.ProxyAddr),
		}
	}
	if !st.Up {
		return agentProbeResult{
			state:    agentEndpointDown,
			status:   &st,
			verified: true,
		}
	}
	return agentProbeResult{
		state:    agentEndpointUp,
		status:   &st,
		verified: true,
	}
}

func agentState(c *agentConfig) (*agentStatus, error) {
	return agentStateInDir(stateDir(c.Zone), c)
}

func agentStateInDir(dir string, c *agentConfig) (*agentStatus, error) {
	res := probeAgentStatus(dir, c, 2*time.Second)
	if !res.verified {
		if res.err != nil {
			return nil, res.err
		}
		return nil, fmt.Errorf("unverified process listening on %s", c.ProxyAddr)
	}
	return res.status, nil
}

func verifyAgentEndpoint(dir string, cfg *agentConfig) agentEndpointState {
	state, _ := verifyAgentEndpointDetail(dir, cfg)
	return state
}

func verifyAgentEndpointDetail(dir string, cfg *agentConfig) (agentEndpointState, agentEndpointDetail) {
	res := probeAgentStatus(dir, cfg, 400*time.Millisecond)
	if !res.verified {
		return res.state, agentEndpointDetail{}
	}
	detail := agentEndpointDetail{verified: true}
	if res.state == agentEndpointDown && res.status != nil {
		detail.reason = strings.TrimSpace(res.status.Error)
		detail.needsLogin = res.status.NeedsLogin
	}
	return res.state, detail
}
