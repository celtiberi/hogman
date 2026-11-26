package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"hogman/registrar/internal/acme"
)

// gateCertCmd keeps the host's front-door wildcard certificate (D-18): by
// default *.gate.hogman.network, by DNS-01 through the host's challenge DNS
// server with the host credential (which may write only the gate challenge
// name). It writes gate.crt and gate.key into GATE_TLS_DIR; a systemd path
// unit on the host reloads the front door when they change. It needs nothing
// else from a pen: no database, no Headscale.
//
//	registrar gate-cert           run, renewing until stopped
//	registrar gate-cert health    exit 0 if a valid certificate is in place
func gateCertCmd(args []string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	dir := env("GATE_TLS_DIR", "/var/lib/hogman-gate/tls")
	if len(args) == 1 && args[0] == "health" {
		return acme.VerifyTLSFiles(dir, "gate")
	}
	if len(args) != 0 {
		return errors.New("usage: registrar gate-cert [health]")
	}
	chURL := strings.TrimSpace(os.Getenv("CHALLENGE_DNS_URL"))
	if chURL == "" {
		chURL = "unix:///run/hogman-acme/api.sock"
	}
	tokPath := env("CHALLENGE_DNS_TOKEN_FILE", "/etc/hogman/gate-challenge-token")
	tok, err := os.ReadFile(tokPath)
	if err != nil {
		return fmt.Errorf("challenge DNS token %s: %w", tokPath, err)
	}
	backend, err := acme.NewChallengeDNSClient(chURL, string(tok))
	if err != nil {
		return err
	}
	mgr, err := acme.NewHomeCertManager(acme.HomeConfig{
		Host:               env("GATE_HOST", "*.gate.hogman.network"),
		FileBase:           "gate",
		HomeTLSDir:         dir,
		StorageDir:         env("ACME_STORAGE_DIR", "/var/lib/hogman-gate/acme"),
		PrimaryCA:          strings.TrimSpace(os.Getenv("ACME_CA_URL")),
		FallbackCA:         strings.TrimSpace(os.Getenv("ACME_FALLBACK_CA_URL")),
		Email:              strings.TrimSpace(os.Getenv("ACME_EMAIL")),
		CARootFile:         strings.TrimSpace(os.Getenv("ACME_CA_ROOT")),
		Resolvers:          parseCSV(os.Getenv("ACME_RESOLVERS")),
		PropagationDelay:   durEnv("ACME_PROPAGATION_DELAY", 0),
		PropagationTimeout: propTimeoutEnv("ACME_PROPAGATION_TIMEOUT"),
		Backend:            backend,
		Logger:             logger,
	})
	if err != nil {
		return err
	}
	defer mgr.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("gate-cert keeping certificate", "host", mgr.Host(), "dir", dir)
	mgr.Run(ctx)
	return nil
}
