package mobile

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// StateKeyLen is the exact byte length of the device-bound AES-256-GCM DEK.
	StateKeyLen = 32

	// Hard byte caps for C-ABI / JSON bridge inputs. Inputs exceeding these
	// limits are rejected with an error rather than truncated (D-56).
	MaxDataDirBytes  = 1024
	MaxLinkBytes     = 4096
	MaxShortBytes    = 256
	MaxDNSJSONBytes  = 16 * 1024
	MaxCAPEMBytes    = 64 * 1024
	MaxUpstreamDNS   = 16
	MaxZoneBytes     = 253
	DefaultTunnelMTU = 1280
	MinTunnelMTU     = 576
	MaxTunnelMTU     = 9000
)

func checkMaxLen(field, value string, maxBytes int) error {
	if len(value) > maxBytes {
		return fmt.Errorf("%s exceeds maximum length (%d bytes)", field, maxBytes)
	}
	return nil
}

func validateStateKey(key []byte) error {
	if len(key) != StateKeyLen {
		return fmt.Errorf("state key must be exactly %d bytes (got %d)", StateKeyLen, len(key))
	}
	var allZero byte
	for _, b := range key {
		allZero |= b
	}
	if allZero == 0 {
		return errors.New("state key must not be all zeros")
	}
	return nil
}

func validateZoneName(zone string) (string, error) {
	zone = strings.ToLower(strings.TrimSpace(zone))
	if err := checkMaxLen("zone", zone, MaxZoneBytes); err != nil {
		return "", err
	}
	if zone == "" || strings.ContainsAny(zone, `/\:*?"<>| `) || strings.Contains(zone, "..") {
		return "", errors.New("invalid pen zone")
	}
	return zone, nil
}
