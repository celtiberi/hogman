//go:build cdnstest

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

const maxTestEABFileBytes = 4 << 10

// staticEABMinter hands out a fixed EAB credential loaded from a JSON file.
// Compiled only with -tags cdnstest for offline Pebble E2E runs; never present
// in production builds.
type staticEABMinter struct {
	keyID      string
	hmacB64URL string
}

var _ EABMinter = (*staticEABMinter)(nil)

func newStaticEABMinter(path string) (*staticEABMinter, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxTestEABFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxTestEABFileBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxTestEABFileBytes)
	}
	var cfg struct {
		KID        string `json:"kid"`
		HMACB64URL string `json:"hmac_b64url"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.KID = strings.TrimSpace(cfg.KID)
	cfg.HMACB64URL = strings.TrimSpace(cfg.HMACB64URL)
	if cfg.KID == "" || cfg.HMACB64URL == "" {
		return nil, fmt.Errorf("%s: kid and hmac_b64url are required", path)
	}
	return &staticEABMinter{keyID: cfg.KID, hmacB64URL: cfg.HMACB64URL}, nil
}

func (m *staticEABMinter) Mint(_ context.Context) (string, string, error) {
	return m.keyID, m.hmacB64URL, nil
}

func loadTestEABMinter(path string, logger *slog.Logger) (EABMinter, error) {
	m, err := newStaticEABMinter(path)
	if err != nil {
		return nil, fmt.Errorf("CDNS_TEST_EAB_FILE: %w", err)
	}
	defaultLogger(logger).Warn("fallback CA using static test EAB file (cdnstest build only)", "path", path)
	return m, nil
}
