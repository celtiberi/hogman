//go:build darwin || linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestStartShAutoUpdateAndJoinBehaviorI9(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("POSIX shell test")
	}
	scriptPath, err := filepath.Abs("../join-page/start.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Skip("core/join-page/start.sh not found")
	}

	osOut, err := exec.Command("uname", "-s").Output()
	if err != nil {
		t.Fatal(err)
	}
	archOut, err := exec.Command("uname", "-m").Output()
	if err != nil {
		t.Fatal(err)
	}
	binFile := fmt.Sprintf("hogman-%s-%s", strings.TrimSpace(string(osOut)), strings.TrimSpace(string(archOut)))

	tmp := t.TempDir()
	fakeBinBody := "#!/bin/sh\necho \"FAKE_HOGMAN_ARGS:$*\"\n"
	sumBytes := sha256.Sum256([]byte(fakeBinBody))
	sumHex := hex.EncodeToString(sumBytes[:])
	sumsBody := fmt.Sprintf("%s  %s\n", sumHex, binFile)

	// Fake curl serves SHA256SUMS and binary from $FAKE_DL_DIR, logging URLs fetched.
	dlDir := filepath.Join(tmp, "dl")
	_ = os.MkdirAll(dlDir, 0o700)
	_ = os.WriteFile(filepath.Join(dlDir, "SHA256SUMS"), []byte(sumsBody), 0o600)
	_ = os.WriteFile(filepath.Join(dlDir, binFile), []byte(fakeBinBody), 0o600)

	binDir := filepath.Join(tmp, "bin")
	_ = os.MkdirAll(binDir, 0o700)
	curlStub := `#!/bin/sh
out=""
url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
printf '%s\n' "$url" >> "$FAKE_CURL_LOG"
case "$url" in
  */SHA256SUMS|*/hogman-SHA256SUMS)
    [ -f "$FAKE_DL_DIR/fail_pen" ] && case "$url" in *pen1.gate.example.com*) exit 22 ;; esac
    cp "$FAKE_DL_DIR/SHA256SUMS" "$out"
    ;;
  */hogman-*)
    cp "$FAKE_DL_DIR/$(basename "$url")" "$out"
    ;;
  *) exit 22 ;;
esac
`
	_ = os.WriteFile(filepath.Join(binDir, "curl"), []byte(curlStub), 0o755)

	configBaseFor := func(home string) string {
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Application Support", "hogman")
		}
		return filepath.Join(home, ".config", "hogman")
	}

	runStart := func(home string, extraEnv []string, args ...string) (string, string, error) {
		curlLog := filepath.Join(home, "curl.log")
		_ = os.Remove(curlLog)
		cmd := exec.Command("/bin/sh", append([]string{scriptPath}, args...)...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Env = append(os.Environ(),
			"HOME="+home,
			"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
			"PATH="+binDir+":"+os.Getenv("PATH"),
			"FAKE_DL_DIR="+dlDir,
			"FAKE_CURL_LOG="+curlLog,
		)
		cmd.Env = append(cmd.Env, extraEnv...)
		out, err := cmd.CombinedOutput()
		logBytes, _ := os.ReadFile(curlLog)
		return string(out), string(logBytes), err
	}

	// 1. Existing pen + no link arg -> installs ~/hogman from pen host and runs `~/hogman update`.
	home1 := filepath.Join(tmp, "home1")
	pen1Dir := filepath.Join(configBaseFor(home1), "pen1.example.com")
	_ = os.MkdirAll(pen1Dir, 0o700)
	_ = os.WriteFile(filepath.Join(pen1Dir, "config.json"), []byte(`{"zone":"pen1.example.com","login_server":"https://pen1.gate.example.com"}`), 0o600)
	_ = os.WriteFile(filepath.Join(home1, "hogman-join"), []byte("legacy"), 0o700)

	out, curlLog, err := runStart(home1, nil)
	if err != nil {
		t.Fatalf("case 1 (existing pen auto-update) failed: err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "FAKE_HOGMAN_ARGS:update") {
		t.Fatalf("expected ~/hogman update to run, got:\n%s", out)
	}
	if !strings.Contains(out, "delete "+filepath.Join(home1, "hogman-join")) {
		t.Fatalf("expected legacy hogman-join deletion hint, got:\n%s", out)
	}
	if !strings.Contains(curlLog, "https://pen1.gate.example.com/join/dl/SHA256SUMS") {
		t.Fatalf("expected download from pen1 host, curlLog:\n%s", curlLog)
	}

	// 2. Existing pen whose server fails -> falls back to GitHub Releases when HOGMAN_EXPECTED_HOST is unset.
	_ = os.WriteFile(filepath.Join(dlDir, "fail_pen"), []byte("1"), 0o600)
	out, curlLog, err = runStart(home1, nil)
	_ = os.Remove(filepath.Join(dlDir, "fail_pen"))
	if err != nil {
		t.Fatalf("case 2 (fallback to GitHub Releases) failed: err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "FAKE_HOGMAN_ARGS:update") || !strings.Contains(curlLog, "https://github.com/celtiberi/hogman/releases/latest/download/hogman-SHA256SUMS") {
		t.Fatalf("expected GitHub Releases fallback + update, out:\n%s\ncurlLog:\n%s", out, curlLog)
	}

	// 3. Existing pen + HOGMAN_EXPECTED_HOST matching a BRAND-NEW pen -> must NOT hijack into update;
	// asks for invite link (fails non-TTY because no link was passed).
	out, _, err = runStart(home1, []string{"HOGMAN_EXPECTED_HOST=pen2.gate.example.com"})
	if err == nil || !strings.Contains(out, "no terminal to ask for your invite link") {
		t.Fatalf("case 3 (new pen expected host) should ask for invite link, err=%v out=%s", err, out)
	}

	// 4. Existing pen + explicit link arg -> runs join with link (not update).
	out, _, err = runStart(home1, []string{"HOGMAN_EXPECTED_HOST=pen2.gate.example.com"}, "https://pen2.gate.example.com/join#t=abc123", "--no-open")
	if err != nil {
		t.Fatalf("case 4 (explicit link on existing-pen machine) failed: err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "FAKE_HOGMAN_ARGS:--no-open https://pen2.gate.example.com/join#t=abc123") {
		t.Fatalf("expected join args, got:\n%s", out)
	}

	// 5. Fresh machine (no pens) + no link arg -> fails asking for invite link.
	homeFresh := filepath.Join(tmp, "home-fresh")
	_ = os.MkdirAll(homeFresh, 0o700)
	out, _, err = runStart(homeFresh, nil)
	if err == nil || !strings.Contains(out, "no terminal to ask for your invite link") {
		t.Fatalf("case 5 (fresh machine) should ask for invite link, err=%v out=%s", err, out)
	}
}
