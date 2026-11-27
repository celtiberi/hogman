package main

import (
	"errors"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"hogman/registrar/internal/acme"
	"hogman/registrar/internal/headscale"
	"hogman/registrar/internal/registrar"
	"hogman/registrar/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s is not set", k)
	}
	return v
}

func positiveIntEnv(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		log.Fatalf("%s must be a positive integer (got %q)", k, v)
	}
	return n
}

func durEnv(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("%s: %v", k, err)
		}
		return d
	}
	return def
}

func propTimeoutEnv(k string) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return 0
	}
	if v == "-1" {
		return -1
	}
	return durEnv(k, 0)
}

func parseCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// requireTsnetStateDir enforces that serve runs with an embedded tsnet state
// directory (fail closed when unset).
func requireTsnetStateDir(tsnetStateDir string) (string, error) {
	tsnetStateDir = strings.TrimSpace(tsnetStateDir)
	if tsnetStateDir == "" {
		return "", errors.New("TSNET_STATE_DIR is required")
	}
	return tsnetStateDir, nil
}

func loadHomeCertConfig(s *registrar.Service, homeTLSDir string, logger *slog.Logger) acme.HomeConfig {
	return acme.HomeConfig{
		Zone:               s.Zone(),
		HomeTLSDir:         homeTLSDir,
		StorageDir:         env("ACME_STORAGE_DIR", "/var/lib/registrar/acme"),
		PrimaryCA:          strings.TrimSpace(os.Getenv("ACME_CA_URL")),
		FallbackCA:         strings.TrimSpace(os.Getenv("ACME_FALLBACK_CA_URL")),
		Email:              strings.TrimSpace(os.Getenv("ACME_EMAIL")),
		CARootFile:         strings.TrimSpace(os.Getenv("ACME_CA_ROOT")),
		Resolvers:          parseCSV(os.Getenv("ACME_RESOLVERS")),
		PropagationDelay:   durEnv("ACME_PROPAGATION_DELAY", 0),
		PropagationTimeout: propTimeoutEnv("ACME_PROPAGATION_TIMEOUT"),
		Backend:            s.ACMEBackend(),
		IsRenewOnly:        s.IsRenewOnly,
		Logger:             logger,
	}
}

func setup() (*registrar.Service, func() error) {
	coreIP := strings.TrimSpace(os.Getenv("CORE_MESH_IP"))
	if coreIP == "" {
		if tsDir := strings.TrimSpace(os.Getenv("TSNET_STATE_DIR")); tsDir != "" {
			if raw, err := os.ReadFile(filepath.Join(tsDir, "mesh-ip")); err == nil {
				coreIP = strings.TrimSpace(string(raw))
			}
		}
	}
	var acmeBackend acme.Backend
	if chURL := strings.TrimSpace(os.Getenv("CHALLENGE_DNS_URL")); chURL != "" {
		tokPath := env("CHALLENGE_DNS_TOKEN_FILE", "/secrets/challenge_dns_token")
		tokBytes, err := os.ReadFile(tokPath)
		if err != nil {
			log.Fatalf("challenge DNS token %s: %v", tokPath, err)
		}
		cli, err := acme.NewChallengeDNSClient(chURL, string(tokBytes))
		if err != nil {
			log.Fatalf("challenge DNS client: %v", err)
		}
		acmeBackend = cli
	}
	dbPath := env("DB", "/var/lib/registrar/registrar.db")
	cfg := registrar.Config{
		Zone:              mustEnv("ZONE"),
		PublicHost:        mustEnv("PUBLIC_HOST"),
		CoreIP:            coreIP,
		Theme:             env("THEME", ""),
		InviteTTL:         durEnv("INVITE_TTL", 7*24*time.Hour),
		DeviceKeyTTL:      durEnv("DEVICE_KEY_TTL", time.Hour),
		MembersCanInvite:  env("MEMBERS_CAN_INVITE", "false") == "true",
		MaxMembers:        positiveIntEnv("MAX_MEMBERS", registrar.DefaultMaxMembers),
		MaxDevices:        positiveIntEnv("MAX_DEVICES", registrar.DefaultMaxDevices),
		BillingStatusPath: env("BILLING_STATUS_FILE", filepath.Join(filepath.Dir(dbPath), "billing-status.json")),
		ACMEBackend:       acmeBackend,
		Logger:            slog.Default(),
	}
	key, err := os.ReadFile(env("HEADSCALE_API_KEY_FILE", "/secrets/headscale_api_key"))
	if err != nil {
		log.Fatalf("headscale API key: %v", err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	st.SetLogger(slog.Default())
	hs := headscale.New(env("HEADSCALE_URL", "http://headscale:8080"), strings.TrimSpace(string(key)))
	svc, err := registrar.NewService(cfg, st, hs)
	if err != nil {
		_ = st.Close()
		log.Fatal(err)
	}
	return svc, st.Close
}
