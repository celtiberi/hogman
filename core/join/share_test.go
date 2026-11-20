package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShareTarget(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		in, want string
		folder   bool
		ok       bool
	}{
		{"3000", "http://127.0.0.1:3000", false, true},
		{"0", "", false, false},
		{"70000", "", false, false},
		{"http://localhost:8080/", "http://localhost:8080", false, true},
		{dir, dir, true, true},
		{dir + "/nope", "", false, false},
	}
	for _, c := range cases {
		got, folder, err := shareTarget(c.in)
		if (err == nil) != c.ok || got != c.want || folder != c.folder {
			t.Errorf("shareTarget(%q) = %q, %v, %v; want %q, %v, ok=%v", c.in, got, folder, err, c.want, c.folder, c.ok)
		}
	}
	f := dir + "/file"
	_ = os.WriteFile(f, []byte("x"), 0o600)
	if _, _, err := shareTarget(f); err == nil {
		t.Errorf("a file should not be shareable as a folder")
	}
}

func TestShareNames(t *testing.T) {
	for _, n := range []string{"blog", "my-notes", "a.blog", "x1"} {
		if !shareNameRE.MatchString(n) {
			t.Errorf("%q should be a valid share name", n)
		}
	}
	for _, n := range []string{"", "-x", "Blog", "a_b", "x.", "a b"} {
		if shareNameRE.MatchString(n) {
			t.Errorf("%q should not be a valid share name", n)
		}
	}
}

func TestShareFolderStaysInside(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	_ = os.WriteFile(secret, []byte("do not serve"), 0o600)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("hello"), 0o600)
	if err := os.Symlink(secret, filepath.Join(dir, "leak")); err != nil {
		t.Skip("no symlinks here:", err)
	}
	h, done, err := shareHandler(&shareConfig{Name: "x", Zone: "z.hogman", Target: dir, Folder: true})
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code, rec.Body.String()
	}
	if code, body := get("/"); code != 200 || !strings.Contains(body, "hello") {
		t.Fatalf("index: %d %q", code, body)
	}
	if code, body := get("/leak"); code == 200 || strings.Contains(body, "do not serve") {
		t.Fatalf("a symlink out of the folder was followed: %d %q", code, body)
	}
}

func TestShareNoteResolutionAndFlags(t *testing.T) {
	// Fresh share without --note has empty note.
	if got := resolveShareNote(nil, "", false); got != "" {
		t.Fatalf("fresh omit = %q want empty", got)
	}
	if got := resolveShareNote(nil, "  hello  ", true); got != "hello" {
		t.Fatalf("fresh --note = %q want hello", got)
	}
	// Bare restart preserves saved note; --note updates; --note "" clears.
	prev := &shareConfig{Note: "saved description"}
	if got := resolveShareNote(prev, "", false); got != "saved description" {
		t.Fatalf("restart without --note = %q want saved description", got)
	}
	if got := resolveShareNote(prev, "new note", true); got != "new note" {
		t.Fatalf("restart with --note = %q want new note", got)
	}
	if got := resolveShareNote(prev, "", true); got != "" {
		t.Fatalf("restart with --note '' = %q want empty", got)
	}

	// Flag parser tracks --note presence regardless of argument order.
	cases := []struct {
		args    []string
		wantPos []string
		note    string
		noteSet bool
		bg      bool
	}{
		{[]string{"share", "notes", "./dir"}, []string{"share", "notes", "./dir"}, "", false, false},
		{[]string{"share", "notes", "./dir", "--note", "Summer trip", "--background"}, []string{"share", "notes", "./dir"}, "Summer trip", true, true},
		{[]string{"share", "--note", "", "notes", "./dir"}, []string{"share", "notes", "./dir"}, "", true, false},
	}
	for _, tc := range cases {
		pos, o, ver, err := parseCLIArgs(tc.args)
		if err != nil || ver {
			t.Fatalf("parseCLIArgs(%v): ver=%v err=%v", tc.args, ver, err)
		}
		if strings.Join(pos, ",") != strings.Join(tc.wantPos, ",") || o.note != tc.note || o.noteSet != tc.noteSet || o.background != tc.bg {
			t.Fatalf("parseCLIArgs(%v) = pos:%v note:%q noteSet:%v bg:%v", tc.args, pos, o.note, o.noteSet, o.background)
		}
	}
}
