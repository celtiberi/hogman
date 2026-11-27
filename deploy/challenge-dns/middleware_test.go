package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWrapHTTPBoundaryMiddleware(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	t.Run("recovers panics as json 500", func(t *testing.T) {
		h := wrapHTTP(logger, maxHTTPBodyBytes, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("boom")
		}))
		// Wrapping twice is idempotent.
		h = wrapHTTP(logger, maxHTTPBodyBytes, h)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/txt", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", got)
		}
		if !strings.Contains(rec.Body.String(), `"internal error"`) {
			t.Fatalf("body = %q, want internal error json", rec.Body.String())
		}
		if !strings.Contains(buf.String(), "http handler panic") {
			t.Fatalf("expected structured panic log, got %q", buf.String())
		}
	})

	t.Run("enforces request body limit", func(t *testing.T) {
		h := wrapHTTP(logger, 32, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]string
			if !readJSON(w, r, &body) {
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		big := `{"fqdn":"` + strings.Repeat("a", 64) + `"}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/txt", strings.NewReader(big)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("oversized body status = %d, want 400", rec.Code)
		}
	})
}

func TestWriteFileAtomicAndMutateRollback(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	if err := writeFileAtomic(target, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatalf("writeFileAtomic initial: %v", err)
	}
	if err := writeFileAtomic(target, []byte(`{"v":2}`), 0o600); err != nil {
		t.Fatalf("writeFileAtomic overwrite: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != `{"v":2}` {
		t.Fatalf("read back = (%q, %v), want {\"v\":2}", string(got), err)
	}
	fi, err := os.Stat(target)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v (err=%v), want 0600", fi.Mode().Perm(), err)
	}

	// Break persistence path and confirm every Store mutation rolls back in-memory state cleanly.
	s, _ := newTestStore(t)
	c, _ := mustCred(t, s, "pen", penA)

	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.path = filepath.Join(notADir, "state.json")

	if _, _, err := s.AddCred("pen", penB); err == nil {
		t.Fatal("AddCred should fail on unwritable path")
	}
	if s.NameUsed(penB) || len(s.Creds()) != 1 {
		t.Fatalf("AddCred leaked state on rollback: used=%v creds=%d", s.NameUsed(penB), len(s.Creds()))
	}
	if _, err := s.SetCredPlan(c.ID, "work"); err == nil {
		t.Fatal("SetCredPlan should fail on unwritable path")
	}
	if got := s.Creds()[0].Plan; got != "" {
		t.Fatalf("SetCredPlan leaked plan %q on rollback", got)
	}
	if err := s.PutTXT(c, ch("photos", penA), val1); err == nil {
		t.Fatal("PutTXT should fail on unwritable path")
	}
	if s.Creds()[0].EverChallenged || len(s.st.Seen[c.ID]) != 0 || len(s.TXT(ch("photos", penA))) != 0 {
		t.Fatalf("PutTXT leaked state on rollback: challenged=%v seen=%v txt=%v",
			s.Creds()[0].EverChallenged, s.st.Seen[c.ID], s.TXT(ch("photos", penA)))
	}
	if err := s.AllowEAB(c); err == nil {
		t.Fatal("AllowEAB should fail on unwritable path")
	}
	if s.Creds()[0].EverChallenged || len(s.st.EAB[c.ID]) != 0 {
		t.Fatalf("AllowEAB leaked state on rollback: challenged=%v eab=%v",
			s.Creds()[0].EverChallenged, s.st.EAB[c.ID])
	}
	if err := s.RemoveCred(c.ID); err == nil {
		t.Fatal("RemoveCred should fail on unwritable path")
	}
	if len(s.Creds()) != 1 {
		t.Fatalf("RemoveCred leaked state on rollback: creds=%d", len(s.Creds()))
	}
}

func TestGCPMinterNoTruncationAndRejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	longDetail := strings.Repeat("errdetail-", 35) // > 200 bytes; must not be truncated
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projects/errproj/locations/global/externalAccountKeys":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "line1\n"+longDetail+"\nline3")
		case "/v1/projects/bigproj/locations/global/externalAccountKeys":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.Repeat([]byte("x"), maxPublicCARespBytes+10))
		}
	}))
	defer srv.Close()

	mErr := &gcpMinter{project: "errproj", base: srv.URL, client: srv.Client()}
	_, _, err := mErr.Mint(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 502")
	}
	if strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("error must be single-line, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), longDetail) || !strings.Contains(err.Error(), "line3") {
		t.Fatalf("error body was truncated: %q", err.Error())
	}

	mBig := &gcpMinter{project: "bigproj", base: srv.URL, client: srv.Client()}
	_, _, err = mBig.Mint(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response error = %v, want explicit size limit rejection", err)
	}
}

func TestAdminClientRejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxAdminRespBytes+1))
	}))
	defer srv.Close()

	_, _, _, err := adminDoWithClient(srv.Client(), srv.URL+"/admin/creds", http.MethodGet, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized admin response error = %v, want size-limit rejection", err)
	}
}
