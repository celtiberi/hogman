package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

type meDeviceView struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	RemovedAt *int64 `json:"removed_at"`
}

type meView struct {
	Member struct {
		Handle string `json:"handle"`
	} `json:"member"`
	ThisDevice struct {
		ID   int64  `json:"id"`
		Kind string `json:"kind"`
	} `json:"this_device"`
	Network *networkInfo   `json:"network"`
	IsOwner *bool          `json:"is_owner"`
	Owners  *int           `json:"owners"`
	Devices []meDeviceView `json:"devices"`
}

// homeAPIError captures a non-2xx HTTP error returned by the pen's mesh home API.
type homeAPIError struct {
	Status     int
	Msg        string
	RetryAfter time.Duration
}

func (e *homeAPIError) Error() string { return e.Msg }

func homeAPI(c *http.Client, zone, method, path string, in, out any) (int, error) {
	return homeAPICtx(context.Background(), c, zone, method, path, in, out)
}

func homeAPICtx(ctx context.Context, c *http.Client, zone, method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://home."+zone+"/api"+path, body)
	if err != nil {
		return 0, err
	}
	if in != nil || method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &apiErr)
		msg := strings.TrimSpace(apiErr.Error)
		if msg == "" {
			msg = strings.TrimSpace(string(data))
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		var retryAfter time.Duration
		if raw := strings.TrimSpace(resp.Header.Get("Retry-After")); raw != "" {
			if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
				retryAfter = time.Duration(secs) * time.Second
			}
		}
		return resp.StatusCode, &homeAPIError{
			Status:     resp.StatusCode,
			Msg:        msg,
			RetryAfter: retryAfter,
		}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("unreadable answer: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// selfDeleteTimeout bounds DELETE /api/devices/<self> calls: current registrars
// return 202 Accepted immediately before deleting the peer, while older ones
// may tear down WireGuard before answering. Real HTTP errors (4xx/5xx) still
// arrive in milliseconds; waiting 30s for a dropped packet only stalls shutdown.
var selfDeleteTimeout = 3 * time.Second

// confirmDeleteTimeout bounds the follow-up removal check used when a
// self-delete gets no HTTP response (code 0), so we never treat an unconfirmed
// timeout as silent success.
var confirmDeleteTimeout = 2 * time.Second

var confirmPollInterval = 150 * time.Millisecond

func isNotEnrolledError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "not enrolled")
}

func tsnetNeedsLogin(node *tsnet.Server) func(context.Context) bool {
	if node == nil {
		return nil
	}
	return func(ctx context.Context) bool {
		lc, err := node.LocalClient()
		if err != nil {
			return false
		}
		st, err := lc.StatusWithoutPeers(ctx)
		return err == nil && st != nil && st.BackendState == "NeedsLogin"
	}
}

// confirmDeviceRemoved verifies an ambiguous code-0 self-delete using two
// signals:
//  1. A single GET /api/me probe: confirms only when the registrar explicitly
//     returns HTTP 403 "not enrolled" (rejecting 200, 404, suspended, and
//     renew_only responses).
//  2. When GET /api/me also fails with transport code 0 (WireGuard already torn
//     down, e.g. against an older synchronous registrar during rolling upgrade),
//     polls checkNeedsLogin over the Headscale HTTPS control channel for
//     BackendState == "NeedsLogin".
func confirmDeviceRemoved(ctx context.Context, hc *http.Client, zone string, checkNeedsLogin func(context.Context) bool) bool {
	probeCtx, cancel := context.WithTimeout(ctx, confirmDeleteTimeout)
	defer cancel()
	probe := *hc
	if probe.Timeout == 0 || probe.Timeout > confirmDeleteTimeout {
		probe.Timeout = confirmDeleteTimeout
	}
	code, err := homeAPICtx(probeCtx, &probe, zone, "GET", "/me", nil, nil)
	if code == http.StatusForbidden && isNotEnrolledError(err) {
		return true
	}
	if code != 0 || checkNeedsLogin == nil {
		return false
	}
	nlCtx, nlCancel := context.WithTimeout(ctx, confirmDeleteTimeout)
	defer nlCancel()
	if checkNeedsLogin(nlCtx) {
		return true
	}
	t := time.NewTicker(confirmPollInterval)
	defer t.Stop()
	for {
		select {
		case <-nlCtx.Done():
			return false
		case <-t.C:
			if checkNeedsLogin(nlCtx) {
				return true
			}
		}
	}
}

type selfDeleteOutcome int

const (
	selfDeleteRemoved selfDeleteOutcome = iota
	selfDeleteLookupFailed
	selfDeleteMissingID
	selfDeleteUnconfirmed
	selfDeleteRejected
	selfDeleteCanceled
)

type selfDeleteResult struct {
	outcome selfDeleteOutcome
	err     error
}

// deleteSelfDevice performs the shared self-removal protocol used by both
// `hogman leave` (personal agent) and `hogman share stop` (server share):
// resolve own device ID if needed, issue a bounded DELETE /api/devices/<id>,
// treat 2xx/404 as removed, and verify ambiguous transport timeouts via
// confirmDeviceRemoved rather than assuming silent success.
func deleteSelfDevice(ctx context.Context, hc *http.Client, zone string, deviceID int64, checkNeedsLogin func(context.Context) bool) selfDeleteResult {
	if deviceID == 0 {
		var me meView
		if _, err := homeAPICtx(ctx, hc, zone, http.MethodGet, "/me", nil, &me); err != nil {
			if ctx.Err() != nil {
				return selfDeleteResult{outcome: selfDeleteCanceled, err: ctx.Err()}
			}
			return selfDeleteResult{outcome: selfDeleteLookupFailed, err: err}
		}
		if me.ThisDevice.ID == 0 {
			return selfDeleteResult{outcome: selfDeleteMissingID}
		}
		deviceID = me.ThisDevice.ID
	}
	delCtx, delCancel := context.WithTimeout(ctx, selfDeleteTimeout)
	defer delCancel()
	delClient := *hc
	if delClient.Timeout == 0 || delClient.Timeout > selfDeleteTimeout {
		delClient.Timeout = selfDeleteTimeout
	}
	code, err := homeAPICtx(delCtx, &delClient, zone, http.MethodDelete, "/devices/"+strconv.FormatInt(deviceID, 10), nil, nil)
	if err == nil || code == http.StatusNotFound {
		return selfDeleteResult{outcome: selfDeleteRemoved}
	}
	if code == 0 && ctx.Err() == nil {
		if confirmDeviceRemoved(ctx, hc, zone, checkNeedsLogin) {
			return selfDeleteResult{outcome: selfDeleteRemoved}
		}
		return selfDeleteResult{outcome: selfDeleteUnconfirmed, err: err}
	}
	if ctx.Err() != nil {
		return selfDeleteResult{outcome: selfDeleteCanceled, err: ctx.Err()}
	}
	return selfDeleteResult{outcome: selfDeleteRejected, err: err}
}
