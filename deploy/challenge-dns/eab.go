package main

// Google Trust Services (the fallback CA) needs External Account Binding: an
// ACME account must be registered with a key ID and HMAC that Google issues.
// Each pair is single-use and expires after 7 days unused, so we mint one
// only when a share actually fails over. The Google service-account key that
// can mint them stays here; pens and shares only ever see one fresh pair.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type EABMinter interface {
	Mint(ctx context.Context) (keyID, hmacB64URL string, err error)
}

type gcpMinter struct {
	project string
	base    string // https://publicca.googleapis.com
	client  *http.Client
}

// newGCPMinter reads a service-account key file. The account should hold
// only roles/publicca.externalAccountKeyCreator.
func newGCPMinter(ctx context.Context, keyFile string) (*gcpMinter, error) {
	b, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	var meta struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(b, &meta); err != nil || meta.ProjectID == "" {
		return nil, fmt.Errorf("%s: not a service-account key with a project_id", keyFile)
	}
	creds, err := google.CredentialsFromJSON(ctx, b, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, err
	}
	return &gcpMinter{project: meta.ProjectID, base: "https://publicca.googleapis.com",
		client: oauth2.NewClient(ctx, creds.TokenSource)}, nil
}

func (g *gcpMinter) Mint(ctx context.Context) (string, string, error) {
	url := fmt.Sprintf("%s/v1/projects/%s/locations/global/externalAccountKeys", g.base, g.project)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("publicca: HTTP %d: %.200s", resp.StatusCode, body)
	}
	return parseEAB(body)
}

// parseEAB reads Google's reply. b64MacKey is a protobuf bytes field that
// already holds the base64url HMAC text, so JSON encodes it a second time:
// decoding into []byte gives back exactly the base64url string ACME wants.
func parseEAB(body []byte) (string, string, error) {
	var out struct {
		KeyID     string `json:"keyId"`
		B64MacKey []byte `json:"b64MacKey"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", fmt.Errorf("publicca reply: %w", err)
	}
	if out.KeyID == "" || len(out.B64MacKey) == 0 {
		return "", "", fmt.Errorf("publicca reply has no key")
	}
	return out.KeyID, string(out.B64MacKey), nil
}
