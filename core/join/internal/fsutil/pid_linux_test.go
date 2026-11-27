//go:build linux

package fsutil

import "testing"

func TestParseProcStatStartTime(t *testing.T) {
	t.Parallel()
	// Comm contains spaces and closing parentheses; field 22 is "987654321".
	live := []byte("4242 (hog (man) 1) S 1 4242 4242 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 4 0 987654321 12345 678\n")
	if got := parseProcStatStartTime(live); got != "987654321" {
		t.Fatalf("parseProcStatStartTime(live) = %q, want 987654321", got)
	}
	zombie := []byte("4242 (hogman) Z 1 4242 4242 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 4 0 987654321 12345 678\n")
	if got := parseProcStatStartTime(zombie); got != "" {
		t.Fatalf("parseProcStatStartTime(zombie) = %q, want empty", got)
	}
}
