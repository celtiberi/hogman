package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hogman/join/internal/share"
	"hogman/join/internal/state"
	"hogman/join/internal/ui"
)

func TestCLIPrivateNameShareParsing(t *testing.T) {
	t.Run("private-name with target and note", func(t *testing.T) {
		var gotName, gotWhat, gotLink string
		var gotOpts options
		h := cliHandlers{
			out:    &bytes.Buffer{},
			errOut: &bytes.Buffer{},
			shareStart: func(name, what, rawLink string, o options) error {
				gotName, gotWhat, gotLink, gotOpts = name, what, rawLink, o
				return nil
			},
		}
		code := runCLI([]string{"share", "--private-name", "3000", "--note", "Cooler 3"}, h)
		if code != 0 {
			t.Fatalf("exit=%d want 0; stderr=%s", code, h.errOut.(*bytes.Buffer).String())
		}
		if gotName != "" || gotWhat != "3000" || gotLink != "" || !gotOpts.privateName || gotOpts.note != "Cooler 3" || !gotOpts.noteSet {
			t.Fatalf("unexpected shareStart args: name=%q what=%q link=%q opts=%+v", gotName, gotWhat, gotLink, gotOpts)
		}
	})

	t.Run("private-name with target and link", func(t *testing.T) {
		var gotName, gotWhat, gotLink string
		var gotOpts options
		h := cliHandlers{
			out:    &bytes.Buffer{},
			errOut: &bytes.Buffer{},
			shareStart: func(name, what, rawLink string, o options) error {
				gotName, gotWhat, gotLink, gotOpts = name, what, rawLink, o
				return nil
			},
		}
		link := "https://acme.gate.example.com/join#k=secret"
		code := runCLI([]string{"share", "--private-name", "3000", link}, h)
		if code != 0 {
			t.Fatalf("exit=%d want 0; stderr=%s", code, h.errOut.(*bytes.Buffer).String())
		}
		if gotName != "" || gotWhat != "3000" || gotLink != link || !gotOpts.privateName {
			t.Fatalf("unexpected shareStart args: name=%q what=%q link=%q opts=%+v", gotName, gotWhat, gotLink, gotOpts)
		}
	})

	t.Run("rejects name alongside private-name (2 args)", func(t *testing.T) {
		var errBuf bytes.Buffer
		h := cliHandlers{
			out:    &bytes.Buffer{},
			errOut: &errBuf,
			shareStart: func(name, what, rawLink string, o options) error {
				t.Fatal("shareStart should not be called")
				return nil
			},
		}
		code := runCLI([]string{"share", "--private-name", "cameras", "3000"}, h)
		if code != 2 {
			t.Fatalf("exit=%d want 2; stderr=%s", code, errBuf.String())
		}
		if !strings.Contains(errBuf.String(), "cannot pass both a share name") {
			t.Fatalf("unexpected error: %s", errBuf.String())
		}
	})

	t.Run("rejects name alongside private-name (3 args)", func(t *testing.T) {
		var errBuf bytes.Buffer
		h := cliHandlers{
			out:    &bytes.Buffer{},
			errOut: &errBuf,
			shareStart: func(name, what, rawLink string, o options) error {
				t.Fatal("shareStart should not be called")
				return nil
			},
		}
		code := runCLI([]string{"share", "--private-name", "cameras", "3000", "https://acme.gate.example.com/join#k=x"}, h)
		if code != 2 {
			t.Fatalf("exit=%d want 2; stderr=%s", code, errBuf.String())
		}
		if !strings.Contains(errBuf.String(), "cannot pass both a share name") {
			t.Fatalf("unexpected error: %s", errBuf.String())
		}
	})

	t.Run("rejects missing target with private-name", func(t *testing.T) {
		var errBuf bytes.Buffer
		h := cliHandlers{
			out:    &bytes.Buffer{},
			errOut: &errBuf,
			shareStart: func(name, what, rawLink string, o options) error {
				t.Fatal("shareStart should not be called")
				return nil
			},
		}
		code := runCLI([]string{"share", "--private-name"}, h)
		if code != 2 {
			t.Fatalf("exit=%d want 2; stderr=%s", code, errBuf.String())
		}
	})

	t.Run("share help documents private-name and honest caveats", func(t *testing.T) {
		var out bytes.Buffer
		h := cliHandlers{out: &out, errOut: &bytes.Buffer{}}
		code := runCLI([]string{"share", "--help"}, h)
		if code != 0 {
			t.Fatalf("exit=%d want 0", code)
		}
		help := out.String()
		for _, want := range []string{"--private-name", "pen name", "site count", "certificate caps"} {
			if !strings.Contains(help, want) {
				t.Fatalf("share --help missing %q:\n%s", want, help)
			}
		}
	})
}

func TestClaimShareNamePrivateAndRestart(t *testing.T) {
	var seenBodies []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/names" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		seenBodies = append(seenBodies, body)
		if priv, _ := body["private"].(bool); priv {
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "k7p3m9x2q4v8.acme.pens.example.com", "private": true})
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"name": body["name"].(string) + ".acme.pens.example.com"})
	}))
	defer srv.Close()

	hc := srv.Client()
	origTransport := hc.Transport.(*http.Transport).Clone()
	hc.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		clone := req.Clone(req.Context())
		clone.URL.Scheme = "https"
		clone.URL.Host = strings.TrimPrefix(srv.URL, "https://")
		return origTransport.RoundTrip(clone)
	})

	dir := t.TempDir()
	cfg := &state.ShareConfig{
		PrivateName: true,
		Zone:        "acme.pens.example.com",
		Note:        "Cooler 3",
	}
	if _, err := share.ClaimName(context.Background(), hc, cfg, dir); err != nil {
		t.Fatalf("first ClaimName failed: %v", err)
	}
	if cfg.Name != "k7p3m9x2q4v8" {
		t.Fatalf("cfg.Name = %q, want k7p3m9x2q4v8", cfg.Name)
	}
	saved, err := state.LoadShare(dir)
	if err != nil {
		t.Fatalf("LoadShare failed: %v", err)
	}
	if saved.Name != "k7p3m9x2q4v8" || !saved.PrivateName || saved.Note != "Cooler 3" {
		t.Fatalf("unexpected saved share.json: %+v", saved)
	}
	if priv, _ := seenBodies[0]["private"].(bool); !priv {
		t.Fatalf("first POST /api/names should have private=true, got %+v", seenBodies[0])
	}

	// Second call (restart): sends explicit name, NOT private=true.
	if _, err := share.ClaimName(context.Background(), hc, saved, dir); err != nil {
		t.Fatalf("restart ClaimName failed: %v", err)
	}
	if _, hasPrivate := seenBodies[1]["private"]; hasPrivate {
		t.Fatalf("restart POST /api/names should not send private=true, got %+v", seenBodies[1])
	}
	if seenBodies[1]["name"] != "k7p3m9x2q4v8" {
		t.Fatalf("restart POST /api/names name=%v, want k7p3m9x2q4v8", seenBodies[1]["name"])
	}
}

func TestAllSharesInSkipsPendingDirsAndStateDirRejectsMismatch(t *testing.T) {
	base := t.TempDir()
	zone := "acme.pens.example.com"
	pendingDir := filepath.Join(base, zone, ".pending-abcd1234")
	realDir := filepath.Join(base, zone, "k7p3m9x2q4v8")
	for _, d := range []string{pendingDir, realDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := (&state.ShareConfig{Name: "", PrivateName: true, Zone: zone}).Save(pendingDir); err != nil {
		t.Fatal(err)
	}
	if err := (&state.ShareConfig{Name: "k7p3m9x2q4v8", PrivateName: true, Zone: zone, Target: "http://127.0.0.1:3000", Note: "Cooler 3"}).Save(realDir); err != nil {
		t.Fatal(err)
	}

	dirs := state.AllSharesIn(base, "")
	if len(dirs) != 1 || dirs[0] != realDir {
		t.Fatalf("AllSharesIn = %v, want [%s]", dirs, realDir)
	}
	items := share.CollectListItems(dirs)
	if len(items) != 1 || !items[0].Private || items[0].Note != "Cooler 3" {
		t.Fatalf("unexpected CollectListItems: %+v", items)
	}

	// State-dir enrolled for a non-private share must refuse --private-name.
	namedDir := t.TempDir()
	if err := (&state.ShareConfig{Name: "blog", PrivateName: false, Zone: zone}).Save(namedDir); err != nil {
		t.Fatal(err)
	}
	err := share.Start("", "3000", "", share.StartOptions{PrivateName: true, StateDir: namedDir}, ui.Default(), ensureCanonicalBinary)
	if err == nil || !strings.Contains(err.Error(), "not --private-name") {
		t.Fatalf("expected mismatch error for non-private state-dir, got: %v", err)
	}

	// Verify honest private-name notice & tip text.
	notice := share.FormatPrivateNameNotice("k7p3m9x2q4v8." + zone)
	for _, want := range []string{"k7p3m9x2q4v8." + zone, "certificate logs", "pen name", "site count"} {
		if !strings.Contains(notice, want) {
			t.Fatalf("notice missing %q: %s", want, notice)
		}
	}
	if !strings.Contains(share.FormatPrivateNoteTip(), "--note") {
		t.Fatalf("tip missing --note: %s", share.FormatPrivateNoteTip())
	}
}
