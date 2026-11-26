package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrNotFound reports that Headscale has no user or node with the requested key.
var ErrNotFound = errors.New("headscale: not found")

// Client is a minimal client for Headscale's REST API (/api/v1).
// Headscale encodes uint64 ids as JSON strings.
type Client struct {
	base string
	key  string
	http *http.Client
}

func New(base, apiKey string) *Client {
	return &Client{base: base, key: apiKey, http: &http.Client{Timeout: 15 * time.Second}}
}

type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type PreAuthKey struct {
	ID         string   `json:"id"`
	Key        string   `json:"key"`
	Used       bool     `json:"used"`
	Expiration string   `json:"expiration"`
	ACLTags    []string `json:"aclTags"`
}

type Node struct {
	ID          string      `json:"id"`
	MachineKey  string      `json:"machineKey"`
	NodeKey     string      `json:"nodeKey"`
	Name        string      `json:"name"`
	GivenName   string      `json:"givenName"`
	IPAddresses []string    `json:"ipAddresses"`
	User        *User       `json:"user"`
	PreAuthKey  *PreAuthKey `json:"preAuthKey"`
	Tags        []string    `json:"tags"`
	Online      bool        `json:"online"`
	LastSeen    string      `json:"lastSeen,omitempty"`
}

func (n *Node) HasTag(t string) bool {
	for _, x := range n.Tags {
		if x == t {
			return true
		}
	}
	return false
}

type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string { return fmt.Sprintf("headscale: HTTP %d: %s", e.Status, e.Body) }

func IsNotFound(err error) bool {
	if errors.Is(err, ErrNotFound) {
		return true
	}
	var he *Error
	if !errors.As(err, &he) {
		return false
	}
	return he.Status == http.StatusNotFound || strings.Contains(strings.ToLower(he.Body), "not found")
}

const (
	// 8 MiB caps memory on malformed responses; GET /api/v1/node averages ~1 KB/node,
	// so this comfortably covers pens up to several thousand nodes.
	maxResponseBytes = 8 << 20
	// Cap error bodies stored in Error/logs so a verbose upstream error cannot spam logs.
	maxErrorBytes = 4 << 10
)

func truncateErrorBody(b []byte) string {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > maxErrorBytes {
		cut := trimmed[:maxErrorBytes]
		for len(cut) > 0 && !utf8.Valid(cut) {
			cut = cut[:len(cut)-1]
		}
		return string(cut) + "...(truncated)"
	}
	return string(trimmed)
}

func (h *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.base+"/api/v1"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.key)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.http.Do(req)
	if err != nil {
		return fmt.Errorf("headscale: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("headscale: read response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("headscale: response exceeded %d bytes", maxResponseBytes)
	}
	if resp.StatusCode/100 != 2 {
		return &Error{Status: resp.StatusCode, Body: truncateErrorBody(data)}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (h *Client) Health(ctx context.Context) error {
	return h.do(ctx, http.MethodGet, "/health", nil, nil)
}

func (h *Client) UserByName(ctx context.Context, name string) (*User, error) {
	var r struct{ Users []User }
	if err := h.do(ctx, http.MethodGet, "/user?name="+url.QueryEscape(name), nil, &r); err != nil {
		return nil, err
	}
	for _, u := range r.Users {
		if u.Name == name {
			return &u, nil
		}
	}
	return nil, ErrNotFound
}

// EnsureUser returns the Headscale user with this name, creating it if needed.
func (h *Client) EnsureUser(ctx context.Context, name string) (*User, error) {
	if u, err := h.UserByName(ctx, name); err == nil {
		return u, nil
	}
	var r struct{ User User }
	if err := h.do(ctx, http.MethodPost, "/user", map[string]string{"name": name}, &r); err != nil {
		return nil, err
	}
	return &r.User, nil
}

func (h *Client) DeleteUser(ctx context.Context, id string) error {
	return h.do(ctx, http.MethodDelete, "/user/"+url.PathEscape(id), nil, nil)
}

// CreateKey makes a single-use pre-auth key. Personal keys belong to a user;
// server keys carry tag:server and no user (tagged devices are owned by the tag).
func (h *Client) CreateKey(ctx context.Context, userID string, tags []string, ttl time.Duration) (*PreAuthKey, error) {
	req := map[string]any{
		"reusable":   false,
		"ephemeral":  false,
		"expiration": time.Now().Add(ttl).UTC().Format(time.RFC3339),
	}
	if userID != "" {
		req["user"] = userID
	}
	if len(tags) > 0 {
		req["aclTags"] = tags
	}
	var r struct{ PreAuthKey PreAuthKey }
	if err := h.do(ctx, http.MethodPost, "/preauthkey", req, &r); err != nil {
		return nil, err
	}
	return &r.PreAuthKey, nil
}

func (h *Client) ExpireKey(ctx context.Context, id string) error {
	return h.do(ctx, http.MethodPost, "/preauthkey/expire", map[string]string{"id": id}, nil)
}

func (h *Client) Nodes(ctx context.Context) ([]Node, error) {
	var r struct{ Nodes []Node }
	if err := h.do(ctx, http.MethodGet, "/node", nil, &r); err != nil {
		return nil, err
	}
	return r.Nodes, nil
}

func (h *Client) Node(ctx context.Context, id string) (*Node, error) {
	id = strings.TrimSpace(id)
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\\") {
		return nil, fmt.Errorf("headscale: invalid node id %q", id)
	}
	var r struct{ Node Node }
	if err := h.do(ctx, http.MethodGet, "/node/"+url.PathEscape(id), nil, &r); err != nil {
		if IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if r.Node.ID == "" || r.Node.ID != id {
		return nil, fmt.Errorf("headscale: node %q response mismatched id %q", id, r.Node.ID)
	}
	return &r.Node, nil
}

func (h *Client) DeleteNode(ctx context.Context, id string) error {
	err := h.do(ctx, http.MethodDelete, "/node/"+url.PathEscape(id), nil, nil)
	if IsNotFound(err) {
		return nil // already gone
	}
	return err
}

func (h *Client) Policy(ctx context.Context) (string, error) {
	var r struct{ Policy string }
	err := h.do(ctx, http.MethodGet, "/policy", nil, &r)
	return r.Policy, err
}

func (h *Client) SetPolicy(ctx context.Context, policy string) error {
	return h.do(ctx, http.MethodPut, "/policy", map[string]string{"policy": policy}, nil)
}
