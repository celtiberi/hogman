package penapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"hogman/join/internal/link"
	"hogman/join/internal/state"
)

type NetworkInfo struct {
	Zone        string `json:"zone"`
	LoginServer string `json:"login_server"`
	CertMode    string `json:"cert_mode"`
	Portal      string `json:"portal"`
	DNSServer   string `json:"dns_server"`
}

type Enrolment struct {
	Handle  string `json:"handle"`
	AuthKey string `json:"auth_key"`
}

type RedeemError struct {
	Status int
	Msg    string
}

func (e *RedeemError) Error() string { return e.Msg }

func ControlClient(caFile string) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		b, err := os.ReadFile(caFile)
		if err != nil || !pool.AppendCertsFromPEM(b) {
			return nil, link.Errorf("--control-ca: cannot read a certificate from %s", caFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			orig := via[0].URL
			if !strings.EqualFold(req.URL.Host, orig.Host) {
				return fmt.Errorf("refusing cross-host redirect to %s", req.URL.Host)
			}
			if strings.EqualFold(orig.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
				return errors.New("refusing HTTPS downgrade redirect")
			}
			return nil
		},
	}, nil
}

func TestACMECAPool() (*x509.CertPool, error) {
	path := strings.TrimSpace(os.Getenv("HOGMAN_ACME_CA_ROOT"))
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, link.Errorf("HOGMAN_ACME_CA_ROOT: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, link.Errorf("HOGMAN_ACME_CA_ROOT: %s contains no valid certificate", path)
	}
	return pool, nil
}

func ValidateNetworkInfo(host string, n *NetworkInfo) error {
	if n.CertMode != "" && n.CertMode != "public" {
		return link.Errorf("%s returned unsupported certificate mode %q", host, n.CertMode)
	}
	if err := link.ValidatePublicZone(host, n.Zone); err != nil {
		return err
	}
	if n.LoginServer != "https://"+host {
		return link.Errorf("refusing: %s redirected login to %q instead of https://%s", host, n.LoginServer, host)
	}
	if n.Portal != "https://home."+n.Zone {
		return link.Errorf("refusing: %s returned unexpected portal address %q", host, n.Portal)
	}
	if n.DNSServer != "" {
		addr, err := netip.ParseAddr(n.DNSServer)
		if err != nil || !link.InMeshRanges(addr) {
			return link.Errorf("refusing: %s returned non-mesh DNS address %q", host, n.DNSServer)
		}
	}
	return nil
}

func FetchNetwork(c *http.Client, host string) (*NetworkInfo, error) {
	resp, err := c.Get("https://" + host + "/hogman/v1/network")
	if err != nil {
		return nil, link.Errorf("cannot reach the network at %s: %v", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, link.Errorf("%s did not answer as a Hogman network (HTTP %d)", host, resp.StatusCode)
	}
	var n NetworkInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&n); err != nil {
		return nil, link.Errorf("%s sent an unreadable answer: %v", host, err)
	}
	if err := ValidateNetworkInfo(host, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

func Redeem(c *http.Client, host, token, handle string) (*Enrolment, error) {
	body, _ := json.Marshal(map[string]string{"token": token, "handle": handle})
	resp, err := c.Post("https://"+host+"/hogman/v1/redeem", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, link.Errorf("cannot reach the network: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 201 {
		var e struct{ Error string }
		_ = json.Unmarshal(data, &e)
		msg := SanitizeAPIErrorMsg(e.Error)
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, &RedeemError{Status: resp.StatusCode, Msg: msg}
	}
	var en Enrolment
	if err := json.Unmarshal(data, &en); err != nil || en.AuthKey == "" {
		return nil, link.Errorf("the network accepted the invite but sent an unreadable answer")
	}
	return &en, nil
}

// PenClient talks to the pen's home page as this computer, through its own
// running local agent proxy.
func PenClient(cfg *state.AgentConfig) (*http.Client, error) {
	pool, err := TestACMECAPool()
	if err != nil {
		return nil, fmt.Errorf("reading HOGMAN_ACME_CA_ROOT: %w", err)
	}
	pu, err := url.Parse(cfg.ProxyURL())
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}, nil
}
