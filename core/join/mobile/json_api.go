package mobile

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

type jsonEnvelope struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  any    `json:"data,omitempty"`
}

func encodeOK(data any) string {
	b, err := json.Marshal(jsonEnvelope{OK: true, Data: data})
	if err != nil {
		return encodeErr(err)
	}
	return string(b)
}

func encodeErr(err error) string {
	msg := "unknown error"
	if err != nil {
		msg = err.Error()
	}
	b, mErr := json.Marshal(jsonEnvelope{OK: false, Error: msg})
	if mErr != nil {
		return `{"ok":false,"error":"marshal error"}`
	}
	return string(b)
}

// ParseUpstreamDNSJSON parses a JSON array of IP address strings with strict
// size and count bounds (rejecting oversized inputs rather than truncating).
func ParseUpstreamDNSJSON(raw string) ([]netip.Addr, error) {
	if err := checkMaxLen("upstream_dns_json", raw, MaxDNSJSONBytes); err != nil {
		return nil, err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var strs []string
	if err := json.Unmarshal([]byte(raw), &strs); err != nil {
		return nil, fmt.Errorf("invalid upstream_dns_json: %w", err)
	}
	if len(strs) > MaxUpstreamDNS {
		return nil, fmt.Errorf("upstream_dns_json exceeds maximum of %d servers", MaxUpstreamDNS)
	}
	out := make([]netip.Addr, 0, len(strs))
	for _, s := range strs {
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("invalid upstream DNS address %q", s)
		}
		out = append(out, addr.Unmap())
	}
	return out, nil
}

// ParseLinkJSON is the JSON boundary wrapper for hogman_parse_link.
func (c *Controller) ParseLinkJSON(rawLink string) string {
	res, err := c.ParseLink(rawLink)
	if err != nil {
		return encodeErr(err)
	}
	return encodeOK(res)
}

// JoinJSON is the JSON boundary wrapper for hogman_join.
func (c *Controller) JoinJSON(dataDir string, stateKey []byte, rawLink, handle, deviceName, controlCAPEM string) string {
	meta, err := c.Join(dataDir, stateKey, rawLink, handle, deviceName, controlCAPEM)
	if err != nil {
		return encodeErr(err)
	}
	return encodeOK(meta)
}

// ListPensJSON is the JSON boundary wrapper for hogman_list_pens.
func (c *Controller) ListPensJSON(dataDir string) string {
	pens, err := c.ListPens(dataDir)
	if err != nil {
		return encodeErr(err)
	}
	return encodeOK(pens)
}

// StartTunnelJSON is the JSON boundary wrapper for hogman_start_tunnel.
func (c *Controller) StartTunnelJSON(dataDir string, stateKey []byte, zone string, mtu int, upstreamDNSJSON string, cb TunnelCallbacks) string {
	upstream, err := ParseUpstreamDNSJSON(upstreamDNSJSON)
	if err != nil {
		return encodeErr(err)
	}
	if err := c.StartTunnel(dataDir, stateKey, zone, mtu, upstream, cb); err != nil {
		return encodeErr(err)
	}
	return encodeOK(c.Status())
}

// UpdateNetworkJSON is the JSON boundary wrapper for hogman_update_network.
func (c *Controller) UpdateNetworkJSON(upstreamDNSJSON string, linkChanged bool) string {
	upstream, err := ParseUpstreamDNSJSON(upstreamDNSJSON)
	if err != nil {
		return encodeErr(err)
	}
	c.UpdateNetwork(upstream, linkChanged)
	return encodeOK(nil)
}

// StatusJSON is the JSON boundary wrapper for hogman_status.
func (c *Controller) StatusJSON() string {
	return encodeOK(c.Status())
}

// StopTunnelJSON is the JSON boundary wrapper for hogman_stop_tunnel.
func (c *Controller) StopTunnelJSON() string {
	c.StopTunnel()
	return encodeOK(c.Status())
}

// LeaveJSON is the JSON boundary wrapper for hogman_leave.
func (c *Controller) LeaveJSON(dataDir string, stateKey []byte, zone string, force bool) string {
	if err := c.Leave(dataDir, stateKey, zone, force); err != nil {
		return encodeErr(err)
	}
	return encodeOK(nil)
}
