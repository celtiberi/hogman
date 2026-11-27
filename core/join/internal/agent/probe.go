package agent

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

	"hogman/join/internal/state"
)

// EndpointState classifies the observed health of a pen agent's loopback port.
type EndpointState int

const (
	EndpointDown EndpointState = iota
	EndpointUp
	EndpointSquatted
)

// EndpointDetail holds verified metadata returned alongside EndpointState.
type EndpointDetail struct {
	Reason     string
	NeedsLogin bool
	Verified   bool // true only when status.token HMAC proof matched
}

// LoopbackStatusTransport disables keep-alive pooling so frequent 1-second
// loopback /status probes never accumulate idle sockets or readLoop/writeLoop
// goroutines in hogman-native-host or hogman agent.
var LoopbackStatusTransport = &http.Transport{
	Proxy:             nil,
	DisableKeepAlives: true,
}

// ProbeResult is the full outcome of an authenticated /status probe.
type ProbeResult struct {
	State    EndpointState
	Status   *Status
	Verified bool
	Err      error
}

// ProbeStatus performs the single authenticated challenge-response probe
// against a pen agent's loopback /status endpoint. It fails closed whenever
// status.token is missing, the response is non-200 or malformed, the zone
// mismatches, or the HMAC proof does not match.
func ProbeStatus(dir string, cfg *state.AgentConfig, timeout time.Duration) ProbeResult {
	tokBytes, tokErr := os.ReadFile(filepath.Join(dir, state.StatusTokenFilename))
	token := strings.TrimSpace(string(tokBytes))

	nonce, err := state.GenerateHexToken(16)
	if err != nil {
		return ProbeResult{State: EndpointDown, Err: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.ProxyURL()+"/status", nil)
	if err != nil {
		return ProbeResult{State: EndpointDown, Err: err}
	}
	req.Header.Set("X-Hogman-Challenge", nonce)
	client := &http.Client{
		Timeout:       timeout,
		Transport:     LoopbackStatusTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{State: EndpointDown, Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ProbeResult{
			State: EndpointSquatted,
			Err:   fmt.Errorf("something else is listening on %s", cfg.ProxyAddr),
		}
	}

	var st Status
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&st); err != nil {
		return ProbeResult{State: EndpointSquatted, Err: err}
	}
	if st.Zone != cfg.Zone {
		return ProbeResult{
			State: EndpointSquatted,
			Err:   fmt.Errorf("something else is listening on %s", cfg.ProxyAddr),
		}
	}

	// Fail closed whenever status.token is missing, unreadable, empty, or the
	// listener fails the challenge-response HMAC proof: an unauthenticated
	// loopback process must never be trusted as a Hogman agent.
	if tokErr != nil || token == "" {
		return ProbeResult{
			State: EndpointSquatted,
			Err:   fmt.Errorf("missing agent status token for %s", cfg.Zone),
		}
	}
	gotProof := strings.TrimSpace(resp.Header.Get("X-Hogman-Proof"))
	wantProof := state.ComputeStatusProof(token, nonce, cfg.Zone)
	if gotProof == "" || !hmac.Equal([]byte(gotProof), []byte(wantProof)) {
		return ProbeResult{
			State: EndpointSquatted,
			Err:   fmt.Errorf("unverified process listening on %s", cfg.ProxyAddr),
		}
	}
	if !st.Up {
		return ProbeResult{
			State:    EndpointDown,
			Status:   &st,
			Verified: true,
		}
	}
	return ProbeResult{
		State:    EndpointUp,
		Status:   &st,
		Verified: true,
	}
}

// State queries the authenticated /status endpoint for c in its default StateDir.
func State(c *state.AgentConfig) (*Status, error) {
	return StateInDir(state.StateDir(c.Zone), c)
}

// StateInDir queries the authenticated /status endpoint for c using dir's status.token.
func StateInDir(dir string, c *state.AgentConfig) (*Status, error) {
	res := ProbeStatus(dir, c, 2*time.Second)
	if !res.Verified {
		if res.Err != nil {
			return nil, res.Err
		}
		return nil, fmt.Errorf("unverified process listening on %s", c.ProxyAddr)
	}
	return res.Status, nil
}

// VerifyEndpoint performs a fast (400ms) authenticated check on cfg's loopback port.
func VerifyEndpoint(dir string, cfg *state.AgentConfig) EndpointState {
	st, _ := VerifyEndpointDetail(dir, cfg)
	return st
}

// VerifyEndpointDetail performs a fast (400ms) authenticated check and returns
// verified NeedsLogin / error detail when the agent is running but down.
func VerifyEndpointDetail(dir string, cfg *state.AgentConfig) (EndpointState, EndpointDetail) {
	res := ProbeStatus(dir, cfg, 400*time.Millisecond)
	if !res.Verified {
		return res.State, EndpointDetail{}
	}
	detail := EndpointDetail{Verified: true}
	if res.State == EndpointDown && res.Status != nil {
		detail.Reason = strings.TrimSpace(res.Status.Error)
		detail.NeedsLogin = res.Status.NeedsLogin
	}
	return res.State, detail
}
