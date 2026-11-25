//go:build linux

package main

import "testing"

func TestParseProcStatZombie(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"123 (hogman) S 1 123 123 0 -1", false},
		{"123 (hogman) R 1 123 123 0 -1", false},
		{"123 (hogman) Z 1 123 123 0 -1", true},
		{"123 (hogman) X 1 123 123 0 -1", true},
		{"456 (hogman (share) v2) Z 1 456 456", true},
		{"456 (hogman (share) v2) S 1 456 456", false},
		{"malformed", false},
		{"123 (x)", false},
	}
	for _, tc := range cases {
		if got := parseProcStatZombie([]byte(tc.line)); got != tc.want {
			t.Fatalf("parseProcStatZombie(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
