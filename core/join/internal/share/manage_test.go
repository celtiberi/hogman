package share

import "testing"

func TestShareStopCommand(t *testing.T) {
	if got := shareStopCommand("windows", "win-test"); got != `~\hogman.exe share stop win-test` {
		t.Fatalf("windows shareStopCommand = %q", got)
	}
	if got := shareStopCommand("darwin", "blog"); got != "hogman share stop blog" {
		t.Fatalf("darwin shareStopCommand = %q", got)
	}
}
