package platform

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"hogman/join/internal/fsutil"
)

func TestPIDIdentityHelper(t *testing.T) {
	ready := os.Getenv("HOGMAN_TEST_PID_IDENTITY_READY")
	if ready == "" {
		return
	}
	_ = os.WriteFile(ready, []byte("ready"), 0o600)
	time.Sleep(30 * time.Second)
}

func startNonHogmanChild(t *testing.T) *exec.Cmd {
	t.Helper()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping.exe", "-n", "30", "127.0.0.1")
	} else {
		cmd = exec.Command("/bin/sleep", "30")
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start non-hogman child: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return cmd
}

func TestExeMatchesHogman(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		got       string
		want      string
		canonical string
		goos      string
		match     bool
	}{
		{"exact unix match", "/usr/local/bin/hogman", "/usr/local/bin/hogman", "", "linux", true},
		{"linux deleted replaced binary", "/home/u/.config/hogman/bin/hogman (deleted)", "/home/u/.config/hogman/bin/hogman", "", "linux", true},
		{"legacy hogman-join name", "/home/u/hogman-join", "/home/u/hogman", "", "darwin", true},
		{"windows case-insensitive match", `C:\Users\Alice\AppData\Roaming\hogman\bin\HOGMAN.EXE`, `C:\Users\alice\AppData\Roaming\hogman\bin\hogman.exe`, "", "windows", true},
		{"windows replaced .old exe", `C:\Users\Alice\hogman.exe.old`, `C:\Users\Alice\hogman.exe`, "", "windows", true},
		{"windows legacy hogman-join.exe", `C:\Users\Alice\hogman-join.exe`, `C:\Users\Alice\hogman.exe`, "", "windows", true},
		{"release binary name", `/tmp/hogman-Linux-x86_64`, `/usr/bin/other`, "", "linux", true},
		{"renamed deleted stale hogman binary", `/tmp/hogman-stale-deleted (deleted)`, `/root/.config/hogman/bin/hogman`, "", "linux", true},
		{"unrelated browser on macOS", `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`, `/opt/hogman/hogman`, "", "darwin", false},
		{"unrelated ping on Windows", `C:\Windows\System32\PING.EXE`, `C:\Users\alice\hogman.exe`, "", "windows", false},
		{"unrelated sleep on Linux", `/usr/bin/sleep`, `/home/alice/hogman`, "", "linux", false},
		{"empty path fails closed", "", "/usr/local/bin/hogman", "", "linux", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := exeMatchesHogmanForOS(tc.got, tc.want, tc.canonical, tc.goos); got != tc.match {
				t.Fatalf("exeMatchesHogmanForOS(%q, %q, %q, %q) = %v, want %v", tc.got, tc.want, tc.canonical, tc.goos, got, tc.match)
			}
		})
	}
}

func TestStalePIDFileNeverKillsNonHogmanProcess(t *testing.T) {
	// Self must always be recognized as our own executable.
	if !ProcessIsHogman(os.Getpid(), "") {
		t.Fatalf("ProcessIsHogman(self=%d) = false, want true", os.Getpid())
	}
	if tag := fsutil.ProcessStartTag(os.Getpid()); tag == "" {
		t.Fatalf("ProcessStartTag(self=%d) returned empty on %s", os.Getpid(), runtime.GOOS)
	}

	// 1. Spawn a live non-hogman process and point agent.pid at it.
	other := startNonHogmanChild(t)
	otherPID := other.Process.Pid
	if !ProcessAlive(otherPID) {
		t.Fatalf("non-hogman child %d is not alive", otherPID)
	}
	if ProcessIsHogman(otherPID, "") {
		t.Fatalf("ProcessIsHogman(%d) = true for non-hogman child, want false", otherPID)
	}

	dir := t.TempDir()
	pidPath := filepath.Join(dir, "agent.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(otherPID)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Both StopDetached and direct StopProcess must refuse to kill otherPID and
	// StopDetached must remove the stale pid file.
	StopDetached(dir)
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("stale agent.pid was not removed (err=%v)", err)
	}
	StopProcess(otherPID, 500*time.Millisecond)
	if !ProcessAlive(otherPID) {
		t.Fatalf("non-hogman child %d was killed!", otherPID)
	}

	// 2. Even when the PID belongs to our own binary (os.Args[0]), a mismatched
	// startTag must refuse to kill it (cross-pen PID reuse protection), while a
	// matching record stops it cleanly.
	readyFile := filepath.Join(dir, "helper.ready")
	helper := exec.Command(os.Args[0], "-test.run=^TestPIDIdentityHelper$")
	helper.Env = append(os.Environ(), "HOGMAN_TEST_PID_IDENTITY_READY="+readyFile)
	if err := helper.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	helperDone := make(chan error, 1)
	go func() { helperDone <- helper.Wait() }()
	t.Cleanup(func() {
		if helper.Process != nil {
			_ = helper.Process.Kill()
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(readyFile); err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if _, err := os.Stat(readyFile); err != nil {
		t.Fatalf("helper did not become ready: %v", err)
	}

	helperPID := helper.Process.Pid
	if !ProcessIsHogman(helperPID, "") {
		t.Fatalf("ProcessIsHogman(helper=%d) = false, want true", helperPID)
	}

	// Mismatched startTag (in sibling .start file, matching WritePIDFile layout) ->
	// treated as stale, removed without killing helper.
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(helperPID)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fsutil.PIDStartPath(pidPath), []byte(fmt.Sprintf("%d 999999999999999\n", helperPID)), 0o600); err != nil {
		t.Fatal(err)
	}
	StopDetached(dir)
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("mismatched-startTag agent.pid was not removed (err=%v)", err)
	}
	if _, err := os.Stat(fsutil.PIDStartPath(pidPath)); !os.IsNotExist(err) {
		t.Fatalf("mismatched-startTag agent.pid.start was not removed (err=%v)", err)
	}
	if !ProcessAlive(helperPID) {
		t.Fatalf("helper %d was killed despite startTag mismatch!", helperPID)
	}

	// Matching startTag stored via sibling .start file (standard single-PID file) -> cleanly stops helper.
	realTag := fsutil.ProcessStartTag(helperPID)
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(helperPID)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fsutil.PIDStartPath(pidPath), []byte(fmt.Sprintf("%d %s\n", helperPID, realTag)), 0o600); err != nil {
		t.Fatal(err)
	}
	StopDetached(dir)
	select {
	case <-helperDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("helper %d did not exit after matching StopDetached", helperPID)
	}
	if ProcessAlive(helperPID) {
		t.Fatalf("helper %d still alive after StopDetached", helperPID)
	}
	if _, err := os.Stat(fsutil.PIDStartPath(pidPath)); !os.IsNotExist(err) {
		t.Fatalf("agent.pid.start was not removed after StopDetached (err=%v)", err)
	}
}
