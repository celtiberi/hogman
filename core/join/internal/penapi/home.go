package penapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type MeDeviceView struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	RemovedAt *int64 `json:"removed_at"`
}

type MeView struct {
	Member struct {
		Handle string `json:"handle"`
	} `json:"member"`
	ThisDevice struct {
		ID   int64  `json:"id"`
		Kind string `json:"kind"`
	} `json:"this_device"`
	Network *NetworkInfo   `json:"network"`
	IsOwner *bool          `json:"is_owner"`
	Owners  *int           `json:"owners"`
	Devices []MeDeviceView `json:"devices"`
}

// HomeAPIError captures a non-2xx HTTP error returned by the pen's mesh home API.
type HomeAPIError struct {
	Status     int
	Msg        string
	RetryAfter time.Duration
}

func (e *HomeAPIError) Error() string { return e.Msg }

const MaxHomeAPIRespBytes = 1 << 20 // 1 MiB

// SanitizeAPIErrorMsg replaces terminal control characters (C0/DEL, C1 such as
// U+009B CSI via unicode.IsControl, and Unicode format/BiDi controls such as
// U+202E via unicode.Cf) with '?' while keeping the full message intact without
// truncation.
func SanitizeAPIErrorMsg(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func formatNonJSONAPIError(status int, contentType string, hasBody bool) string {
	ct := strings.TrimSpace(contentType)
	if ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err == nil && mt != "" {
			ct = mt
		}
		ct = SanitizeAPIErrorMsg(ct)
	}
	if !hasBody {
		if ct != "" {
			return fmt.Sprintf("HTTP %d (%s)", status, ct)
		}
		return fmt.Sprintf("HTTP %d", status)
	}
	if ct != "" {
		if strings.EqualFold(ct, "text/html") || strings.EqualFold(ct, "application/xhtml+xml") {
			return fmt.Sprintf("HTTP %d (%s): not the pen's API — are you behind a Wi-Fi login page?", status, ct)
		}
		if strings.EqualFold(ct, "application/json") {
			return fmt.Sprintf("HTTP %d (%s)", status, ct)
		}
		return fmt.Sprintf("HTTP %d (%s): unexpected non-JSON response from pen API", status, ct)
	}
	return fmt.Sprintf("HTTP %d: unexpected non-JSON response from pen API", status)
}

func HomeAPI(c *http.Client, zone, method, path string, in, out any) (int, error) {
	return HomeAPICtx(context.Background(), c, zone, method, path, in, out)
}

func HomeAPICtx(ctx context.Context, c *http.Client, zone, method, path string, in, out any) (int, error) {
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxHomeAPIRespBytes+1))
	if err != nil {
		return 0, err
	}
	if len(data) > MaxHomeAPIRespBytes {
		return resp.StatusCode, &HomeAPIError{
			Status: resp.StatusCode,
			Msg:    fmt.Sprintf("HTTP %d: response body exceeded %d bytes (not read)", resp.StatusCode, MaxHomeAPIRespBytes),
		}
	}
	if resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		msg := ""
		if json.Unmarshal(data, &apiErr) == nil {
			msg = SanitizeAPIErrorMsg(apiErr.Error)
		}
		if msg == "" {
			msg = formatNonJSONAPIError(resp.StatusCode, resp.Header.Get("Content-Type"), len(bytes.TrimSpace(data)) > 0)
		}
		var retryAfter time.Duration
		if raw := strings.TrimSpace(resp.Header.Get("Retry-After")); raw != "" {
			if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
				retryAfter = time.Duration(secs) * time.Second
			}
		}
		return resp.StatusCode, &HomeAPIError{
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

// SelfDeleteTimeout bounds DELETE /api/devices/<self> calls.
var SelfDeleteTimeout = 3 * time.Second

// ConfirmDeleteTimeout bounds the follow-up removal check used when a
// self-delete gets no HTTP response (code 0).
var ConfirmDeleteTimeout = 2 * time.Second

// ConfirmPollInterval controls polling cadence during NeedsLogin fallback.
var ConfirmPollInterval = 150 * time.Millisecond

func IsNotEnrolledError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "not enrolled")
}

// ConfirmDeviceRemoved verifies an ambiguous code-0 self-delete using two
// signals: GET /api/me returning HTTP 403 "not enrolled", or (if transport also
// fails with code 0) polling checkNeedsLogin for BackendState == "NeedsLogin".
func ConfirmDeviceRemoved(ctx context.Context, hc *http.Client, zone string, checkNeedsLogin func(context.Context) bool) bool {
	probeCtx, cancel := context.WithTimeout(ctx, ConfirmDeleteTimeout)
	defer cancel()
	probe := *hc
	if probe.Timeout == 0 || probe.Timeout > ConfirmDeleteTimeout {
		probe.Timeout = ConfirmDeleteTimeout
	}
	code, err := HomeAPICtx(probeCtx, &probe, zone, http.MethodGet, "/me", nil, nil)
	if code == http.StatusForbidden && IsNotEnrolledError(err) {
		return true
	}
	if code != 0 || checkNeedsLogin == nil {
		return false
	}
	nlCtx, nlCancel := context.WithTimeout(ctx, ConfirmDeleteTimeout)
	defer nlCancel()
	if checkNeedsLogin(nlCtx) {
		return true
	}
	t := time.NewTicker(ConfirmPollInterval)
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

type SelfDeleteOutcome int

const (
	SelfDeleteRemoved SelfDeleteOutcome = iota
	SelfDeleteLookupFailed
	SelfDeleteMissingID
	SelfDeleteUnconfirmed
	SelfDeleteRejected
	SelfDeleteCanceled
)

type SelfDeleteResult struct {
	Outcome SelfDeleteOutcome
	Err     error
}

// DeleteSelfDevice performs the shared self-removal protocol used by both
// `hogman leave` and `hogman share stop`.
func DeleteSelfDevice(ctx context.Context, hc *http.Client, zone string, deviceID int64, checkNeedsLogin func(context.Context) bool) SelfDeleteResult {
	if deviceID == 0 {
		var me MeView
		if _, err := HomeAPICtx(ctx, hc, zone, http.MethodGet, "/me", nil, &me); err != nil {
			if ctx.Err() != nil {
				return SelfDeleteResult{Outcome: SelfDeleteCanceled, Err: ctx.Err()}
			}
			return SelfDeleteResult{Outcome: SelfDeleteLookupFailed, Err: err}
		}
		if me.ThisDevice.ID == 0 {
			return SelfDeleteResult{Outcome: SelfDeleteMissingID}
		}
		deviceID = me.ThisDevice.ID
	}
	delCtx, delCancel := context.WithTimeout(ctx, SelfDeleteTimeout)
	defer delCancel()
	delClient := *hc
	if delClient.Timeout == 0 || delClient.Timeout > SelfDeleteTimeout {
		delClient.Timeout = SelfDeleteTimeout
	}
	code, err := HomeAPICtx(delCtx, &delClient, zone, http.MethodDelete, "/devices/"+strconv.FormatInt(deviceID, 10), nil, nil)
	if err == nil || code == http.StatusNotFound {
		return SelfDeleteResult{Outcome: SelfDeleteRemoved}
	}
	if code == 0 && ctx.Err() == nil {
		if ConfirmDeviceRemoved(ctx, hc, zone, checkNeedsLogin) {
			return SelfDeleteResult{Outcome: SelfDeleteRemoved}
		}
		return SelfDeleteResult{Outcome: SelfDeleteUnconfirmed, Err: err}
	}
	if ctx.Err() != nil {
		return SelfDeleteResult{Outcome: SelfDeleteCanceled, Err: ctx.Err()}
	}
	return SelfDeleteResult{Outcome: SelfDeleteRejected, Err: err}
}
