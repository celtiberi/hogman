package main

import (
	"os"
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
