//go:build !cdnstest

package main

import (
	"errors"
	"log/slog"
)

func loadTestEABMinter(_ string, _ *slog.Logger) (EABMinter, error) {
	return nil, errors.New("CDNS_TEST_EAB_FILE is unsupported in this build (requires -tags cdnstest)")
}
