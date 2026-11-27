package main

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"hogman/join/internal/state"
)

// staleHogmanPAC reports whether an automatic-proxy address is Hogman's own,
// left behind by a pen this computer no longer runs: http://127.0.0.1:<port>/proxy.pac
// where nothing answers any more, or a Hogman agent answers. Such a setting is
// safe to replace or clear. Anything else (a company's PAC, another local tool)
// is someone else's and is left alone. A variable so tests can stub it.
var staleHogmanPAC = func(raw string) bool {
	if !hogmanShapedPACURL(raw) {
		return false
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{
		Timeout:   1500 * time.Millisecond,
		Transport: tr,
		// Judge only what answers at that address: an unrelated local server
		// mustn't be able to point the check somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := c.Get(raw)
	if err != nil {
		return true // nothing listens there any more: a dead Hogman setting
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode == http.StatusOK && strings.HasPrefix(string(b), state.PACMarker)
}

// hogmanShapedPACURL: the exact shape Hogman writes, http://127.0.0.1:<port>/proxy.pac
// with an optional ?v= version.
func hogmanShapedPACURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Path != "/proxy.pac" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Hostname() != "127.0.0.1" {
		return false
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < state.PortMin || p > state.PortMax { // only ports Hogman hands out
		return false
	}
	for k := range u.Query() {
		if k != "v" {
			return false
		}
	}
	return true
}
