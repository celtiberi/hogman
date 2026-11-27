package updater

import (
	"strings"
	"testing"
)

func TestCompareReleaseVersionsAndPackageManager(t *testing.T) {
	t.Parallel()
	if cmp, ok := CompareReleaseVersions("2026.11.26", "2026.11.25"); !ok || cmp != 1 {
		t.Fatalf("CompareReleaseVersions = (%d, %v), want (1, true)", cmp, ok)
	}
	if cmp, ok := CompareReleaseVersions("dev", "2026.11.26"); ok || cmp != 0 {
		t.Fatalf("CompareReleaseVersions(dev) = (%d, %v), want (0, false)", cmp, ok)
	}
	if mgr, _, ok := DetectPackageManager("/opt/homebrew/Cellar/hogman/1.0/bin/hogman", "darwin"); !ok || mgr != "Homebrew" {
		t.Fatalf("DetectPackageManager(homebrew) = (%q, %v)", mgr, ok)
	}
	sum := strings.Repeat("ab", 32)
	got, err := ParseSHA256SUMS([]byte(sum+"  hogman-Linux-x86_64\n"), "hogman-Linux-x86_64")
	if err != nil || got != sum {
		t.Fatalf("ParseSHA256SUMS = (%q, %v), want %q", got, err, sum)
	}
}
