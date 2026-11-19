package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Headscale is a minimal client for Headscale's REST API (/api/v1).
// Headscale encodes uint64 ids as JSON strings.
type Headscale struct {
	base string
	key  string
	http *http.Client
}

func NewHeadscale(base, apiKey string) *Headscale {
	return &Headscale{base: base, key: apiKey, http: &http.Client{Timeout: 15 * time.Second}}
}

type HSUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type HSPreAuthKey struct {
	ID         string   `json:"id"`
	Key        string   `json:"key"`
	Used       bool     `json:"used"`
	Expiration string   `json:"expiration"`
	ACLTags    []string `json:"aclTags"`
}

type HSNode struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	GivenName   string        `json:"givenName"`
	IPAddresses []string      `json:"ipAddresses"`
	User        *HSUser       `json:"user"`
	PreAuthKey  *HSPreAuthKey `json:"preAuthKey"`
	Tags        []string      `json:"tags"`
	Online      bool          `json:"online"`
}

func (n *HSNode) HasTag(t string) bool {
	for _, x := range n.Tags {
		if x == t {
			return true
		}
	}
	return false
}

type HSError struct {
	Status int
	Body   string
}

func (e *HSError) Error() string { return fmt.Sprintf("headscale: HTTP %d: %s", e.Status, e.Body) }

func (h *Headscale) do(ctx context.Context, method, path string, in, out any) error {
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
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return &HSError{Status: resp.StatusCode, Body: string(bytes.TrimSpace(data))}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (h *Headscale) Health(ctx context.Context) error {
	return h.do(ctx, http.MethodGet, "/health", nil, nil)
}

func (h *Headscale) UserByName(ctx context.Context, name string) (*HSUser, error) {
	var r struct{ Users []HSUser }
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
func (h *Headscale) EnsureUser(ctx context.Context, name string) (*HSUser, error) {
	if u, err := h.UserByName(ctx, name); err == nil {
		return u, nil
	}
	var r struct{ User HSUser }
	if err := h.do(ctx, http.MethodPost, "/user", map[string]string{"name": name}, &r); err != nil {
		return nil, err
	}
	return &r.User, nil
}

func (h *Headscale) DeleteUser(ctx context.Context, id string) error {
	return h.do(ctx, http.MethodDelete, "/user/"+url.PathEscape(id), nil, nil)
}

// CreateKey makes a single-use pre-auth key. Personal keys belong to a user;
// server keys carry tag:server and no user (tagged devices are owned by the tag).
func (h *Headscale) CreateKey(ctx context.Context, userID string, tags []string, ttl time.Duration) (*HSPreAuthKey, error) {
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
	var r struct{ PreAuthKey HSPreAuthKey }
	if err := h.do(ctx, http.MethodPost, "/preauthkey", req, &r); err != nil {
		return nil, err
	}
	return &r.PreAuthKey, nil
}

func (h *Headscale) ExpireKey(ctx context.Context, id string) error {
	return h.do(ctx, http.MethodPost, "/preauthkey/expire", map[string]string{"id": id}, nil)
}

func (h *Headscale) Nodes(ctx context.Context) ([]HSNode, error) {
	var r struct{ Nodes []HSNode }
	if err := h.do(ctx, http.MethodGet, "/node", nil, &r); err != nil {
		return nil, err
	}
	return r.Nodes, nil
}

func (h *Headscale) DeleteNode(ctx context.Context, id string) error {
	err := h.do(ctx, http.MethodDelete, "/node/"+url.PathEscape(id), nil, nil)
	if e, ok := err.(*HSError); ok && e.Status == http.StatusNotFound {
		return nil // already gone
	}
	return err
}

func (h *Headscale) Policy(ctx context.Context) (string, error) {
	var r struct{ Policy string }
	err := h.do(ctx, http.MethodGet, "/policy", nil, &r)
	return r.Policy, err
}

func (h *Headscale) SetPolicy(ctx context.Context, policy string) error {
	return h.do(ctx, http.MethodPut, "/policy", map[string]string{"policy": policy}, nil)
}
