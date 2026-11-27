//go:build windows

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
	"testing"
)

const fakeCurlSrc = `package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var out, url string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-o" && i+1 < len(args):
			out = args[i+1]
			i++
		case strings.HasPrefix(args[i], "https://"):
			url = args[i]
		}
	}
	if logPath := os.Getenv("FAKE_CURL_LOG"); logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err == nil {
			_, _ = f.WriteString(url + "\n")
			_ = f.Close()
		}
	}
	dlDir := os.Getenv("FAKE_DL_DIR")
	var src string
	switch {
	case strings.HasSuffix(url, "/SHA256SUMS") || strings.HasSuffix(url, "/hogman-SHA256SUMS"):
		if _, err := os.Stat(filepath.Join(dlDir, "fail_pen")); err == nil && strings.Contains(url, "pen1.gate.example.com") {
			os.Exit(22)
		}
		if _, err := os.Stat(filepath.Join(dlDir, "bad_sums")); err == nil {
			src = filepath.Join(dlDir, "SHA256SUMS.bad")
		} else {
			src = filepath.Join(dlDir, "SHA256SUMS")
		}
	case strings.Contains(url, "/hogman-"):
		idx := strings.LastIndex(url, "/")
		src = filepath.Join(dlDir, url[idx+1:])
	default:
		os.Exit(22)
	}
	in, err := os.Open(src)
	if err != nil {
		os.Exit(22)
	}
	defer in.Close()
	w, err := os.Create(out)
	if err != nil {
		os.Exit(23)
	}
	defer w.Close()
	if _, err := io.Copy(w, in); err != nil {
		os.Exit(23)
	}
}
`

const fakeHogmanSrc = `package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	fmt.Printf("FAKE_HOGMAN_ARGS:%s\n", strings.Join(os.Args[1:], " "))
}
`

func buildTestHelperExe(t *testing.T, dir, name, src string) string {
	t.Helper()
	srcPath := filepath.Join(dir, name+".go")
	outPath := filepath.Join(dir, name+".exe")
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", outPath, srcPath)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build helper %s: %v\n%s", name, err, string(out))
	}
	return outPath
}

func TestStartPs1PureASCII(t *testing.T) {
	scriptPath, err := filepath.Abs("../join-page/start.ps1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range b {
		if c > 0x7f {
			t.Fatalf("start.ps1 contains non-ASCII byte 0x%02x at offset %d (keep 7-bit ASCII for PowerShell 5.1 codepage safety)", c, i)
		}
	}
}

func TestStartPs1BehaviorAndSecurity(t *testing.T) {
	scriptPath, err := filepath.Abs("../join-page/start.ps1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Skip("core/join-page/start.ps1 not found")
	}

	var arch string
	switch runtime.GOARCH {
	case "amd64":
		arch = "amd64"
	case "arm64":
		arch = "arm64"
	default:
		t.Skipf("unsupported Windows test arch %s", runtime.GOARCH)
	}
	binFile := fmt.Sprintf("hogman-windows-%s.exe", arch)

	tmp := t.TempDir()
	buildDir := filepath.Join(tmp, "build")
	binDir := filepath.Join(tmp, "bin")
	dlDir := filepath.Join(tmp, "dl")
	for _, d := range []string{buildDir, binDir, dlDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// Build real Windows PE stubs for curl.exe and hogman.exe.
	curlExe := buildTestHelperExe(t, buildDir, "curl", fakeCurlSrc)
	if err := os.Rename(curlExe, filepath.Join(binDir, "curl.exe")); err != nil {
		t.Fatal(err)
	}
	fakeHogmanExe := buildTestHelperExe(t, buildDir, "hogman", fakeHogmanSrc)
	fakeBinBytes, err := os.ReadFile(fakeHogmanExe)
	if err != nil {
		t.Fatal(err)
	}
	sumBytes := sha256.Sum256(fakeBinBytes)
	sumHex := hex.EncodeToString(sumBytes[:])
	if err := os.WriteFile(filepath.Join(dlDir, binFile), fakeBinBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dlDir, "SHA256SUMS"), []byte(fmt.Sprintf("%s  %s\n", sumHex, binFile)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dlDir, "SHA256SUMS.bad"), []byte(fmt.Sprintf("%s  %s\n", strings.Repeat("0", 64), binFile)), 0o600); err != nil {
		t.Fatal(err)
	}

	var shells []string
	for _, candidate := range []string{"powershell.exe", "pwsh.exe"} {
		if p, err := exec.LookPath(candidate); err == nil {
			shells = append(shells, p)
		}
	}
	if len(shells) == 0 {
		t.Fatal("neither powershell.exe nor pwsh.exe found on Windows runner")
	}

	mergeEnv := func(base []string, overrides map[string]string, dropKeys ...string) []string {
		drop := make(map[string]bool, len(overrides)+len(dropKeys))
		for k := range overrides {
			drop[strings.ToUpper(k)] = true
		}
		for _, k := range dropKeys {
			drop[strings.ToUpper(k)] = true
		}
		out := make([]string, 0, len(base)+len(overrides))
		for _, kv := range base {
			if k, _, ok := strings.Cut(kv, "="); ok && drop[strings.ToUpper(k)] {
				continue
			}
			out = append(out, kv)
		}
		for k, v := range overrides {
			out = append(out, k+"="+v)
		}
		return out
	}

	for _, shellExe := range shells {
		shellName := filepath.Base(shellExe)
		t.Run(shellName, func(t *testing.T) {
			dropForShell := []string{}
			if strings.EqualFold(shellName, "powershell.exe") {
				// Prevent a parent pwsh (PS 7) PSModulePath from poisoning Windows PowerShell 5.1.
				dropForShell = append(dropForShell, "PSModulePath")
			}
			runStart := func(home string, extraEnv map[string]string, psArgs ...string) (string, string, error) {
				curlLog := filepath.Join(home, "curl.log")
				_ = os.Remove(curlLog)
				appData := filepath.Join(home, "AppData", "Roaming")
				tempDir := filepath.Join(home, "Temp")
				_ = os.MkdirAll(appData, 0o700)
				_ = os.MkdirAll(tempDir, 0o700)

				args := append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath}, psArgs...)
				cmd := exec.Command(shellExe, args...)
				cmd.Stdin = strings.NewReader("")
				overrides := map[string]string{
					"USERPROFILE":   home,
					"HOME":          home,
					"APPDATA":       appData,
					"TEMP":          tempDir,
					"TMP":           tempDir,
					"PATH":          binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
					"FAKE_DL_DIR":   dlDir,
					"FAKE_CURL_LOG": curlLog,
				}
				for k, v := range extraEnv {
					overrides[k] = v
				}
				cmd.Env = mergeEnv(os.Environ(), overrides, dropForShell...)
				out, err := cmd.CombinedOutput()
				logBytes, _ := os.ReadFile(curlLog)
				return string(out), string(logBytes), err
			}

			// 1. Existing pen + no link -> installs %USERPROFILE%\hogman.exe from pen host and runs `hogman.exe update`.
			home1 := filepath.Join(tmp, shellName+"-home1")
			pen1Dir := filepath.Join(home1, "AppData", "Roaming", "hogman", "pen1.example.com")
			if err := os.MkdirAll(pen1Dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(pen1Dir, "config.json"), []byte(`{"zone":"pen1.example.com","login_server":"https://pen1.gate.example.com"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home1, "hogman-join.exe"), []byte("legacy"), 0o600); err != nil {
				t.Fatal(err)
			}

			out, curlLog, err := runStart(home1, nil)
			if err != nil {
				t.Fatalf("case 1 (existing pen auto-update) failed: err=%v out=%s", err, out)
			}
			if !strings.Contains(out, "FAKE_HOGMAN_ARGS:update") {
				t.Fatalf("case 1: expected hogman.exe update, got:\n%s", out)
			}
			if !strings.Contains(out, "delete "+filepath.Join(home1, "hogman-join.exe")) {
				t.Fatalf("case 1: expected legacy hogman-join.exe deletion hint, got:\n%s", out)
			}
			if !strings.Contains(curlLog, "https://pen1.gate.example.com/join/dl/SHA256SUMS") {
				t.Fatalf("case 1: expected download from pen1 host, curlLog:\n%s", curlLog)
			}

			// 2. Existing pen whose server fails -> falls back to GitHub Releases when ExpectedHost is unset.
			_ = os.WriteFile(filepath.Join(dlDir, "fail_pen"), []byte("1"), 0o600)
			out, curlLog, err = runStart(home1, nil)
			_ = os.Remove(filepath.Join(dlDir, "fail_pen"))
			if err != nil {
				t.Fatalf("case 2 (GitHub Releases fallback) failed: err=%v out=%s", err, out)
			}
			if !strings.Contains(out, "FAKE_HOGMAN_ARGS:update") || !strings.Contains(curlLog, "https://github.com/celtiberi/hogman/releases/latest/download/hogman-SHA256SUMS") {
				t.Fatalf("case 2: expected GitHub Releases fallback + update, out:\n%s\ncurlLog:\n%s", out, curlLog)
			}

			// 3. Existing pen + -ExpectedHost for a BRAND-NEW pen -> must NOT hijack into update; fails non-interactive.
			out, _, err = runStart(home1, nil, "-ExpectedHost", "pen2.gate.example.com")
			if err == nil || !strings.Contains(out, "no terminal to ask for your invite link") {
				t.Fatalf("case 3 (new pen expected host) should ask for invite link, err=%v out=%s", err, out)
			}

			// 4. Explicit share link + share args -> downloads from pen2 and invokes hogman.exe share blog 8080 <link>.
			shareLink := "https://pen2.gate.example.com/join#k=abc123&for=share"
			out, curlLog, err = runStart(home1, nil, "-ExpectedHost", "pen2.gate.example.com", shareLink, "share", "blog", "8080")
			if err != nil {
				t.Fatalf("case 4 (explicit share link) failed: err=%v out=%s", err, out)
			}
			if !strings.Contains(out, "FAKE_HOGMAN_ARGS:share blog 8080 "+shareLink) {
				t.Fatalf("case 4: expected share args, got:\n%s", out)
			}
			if !strings.Contains(curlLog, "https://pen2.gate.example.com/join/dl/"+binFile) {
				t.Fatalf("case 4: expected download from pen2, curlLog:\n%s", curlLog)
			}

			// 5. Scriptblock invocation (exact /join one-liner mechanism) must survive in an
			// interactive PowerShell session on BOTH success and error paths without closing the shell.
			sbHome := filepath.Join(tmp, shellName+"-sb")
			_ = os.MkdirAll(filepath.Join(sbHome, "AppData", "Roaming"), 0o700)
			_ = os.MkdirAll(filepath.Join(sbHome, "Temp"), 0o700)
			escapedScript := strings.ReplaceAll(scriptPath, "'", "''")
			runScriptBlockSession := func(invocation string) (string, error) {
				cmd := exec.Command(shellExe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
					fmt.Sprintf("$s = [System.IO.File]::ReadAllText('%s'); %s; [Console]::Out.WriteLine(\"STILL-ALIVE:$LASTEXITCODE\")",
						escapedScript, invocation))
				cmd.Stdin = strings.NewReader("")
				cmd.Env = mergeEnv(os.Environ(), map[string]string{
					"USERPROFILE": sbHome,
					"HOME":        sbHome,
					"APPDATA":     filepath.Join(sbHome, "AppData", "Roaming"),
					"TEMP":        filepath.Join(sbHome, "Temp"),
					"TMP":         filepath.Join(sbHome, "Temp"),
					"PATH":        binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
					"FAKE_DL_DIR": dlDir,
				}, dropForShell...)
				outBytes, err := cmd.CombinedOutput()
				return string(outBytes), err
			}
			// 5a. Success path: runs hogman.exe, sets $LASTEXITCODE=0, and caller session stays alive.
			if sbOut, err := runScriptBlockSession(`& ([scriptblock]::Create($s)) -ExpectedHost 'pen2.gate.example.com' 'https://pen2.gate.example.com/join#t=tok123'`); err != nil ||
				!strings.Contains(sbOut, "FAKE_HOGMAN_ARGS:https://pen2.gate.example.com/join#t=tok123") ||
				!strings.Contains(sbOut, "STILL-ALIVE:0") {
				t.Fatalf("case 5a (scriptblock success survival) failed: err=%v out=%s", err, sbOut)
			}
			// 5b. Error path (host mismatch): prints ERROR, sets $LASTEXITCODE=1, and caller session stays alive.
			if sbOut, err := runScriptBlockSession(`& ([scriptblock]::Create($s)) -ExpectedHost 'pen2.gate.example.com' 'https://evil.example.com/join#t=tok123'`); err != nil ||
				!strings.Contains(sbOut, "ERROR: refusing link for evil.example.com") ||
				!strings.Contains(sbOut, "STILL-ALIVE:1") {
				t.Fatalf("case 5b (scriptblock error survival) failed: err=%v out=%s", err, sbOut)
			}
			// 5c. Direct .ps1 file call error path: sets $LASTEXITCODE=1 and caller session stays alive.
			if sbOut, err := runScriptBlockSession(fmt.Sprintf(`& '%s' -ExpectedHost 'pen2.gate.example.com' 'https://evil.example.com/join#t=tok123'`, escapedScript)); err != nil ||
				!strings.Contains(sbOut, "ERROR: refusing link for evil.example.com") ||
				!strings.Contains(sbOut, "STILL-ALIVE:1") {
				t.Fatalf("case 5c (file invocation error survival) failed: err=%v out=%s", err, sbOut)
			}

			// 6. Host pinning refusal: -ExpectedHost mismatch must abort before downloading.
			out, curlLog, err = runStart(sbHome, nil, "-ExpectedHost", "pen2.gate.example.com", "https://evil.example.com/join#t=tok123")
			if err == nil || !strings.Contains(out, "refusing link for evil.example.com") {
				t.Fatalf("case 6 (host mismatch) should refuse, err=%v out=%s", err, out)
			}
			if strings.TrimSpace(curlLog) != "" {
				t.Fatalf("case 6: curl should not have run on host mismatch, got:\n%s", curlLog)
			}

			// 7. Bad SHA-256 checksum must fail and never execute the downloaded binary.
			badHome := filepath.Join(tmp, shellName+"-badsum")
			_ = os.MkdirAll(badHome, 0o700)
			_ = os.WriteFile(filepath.Join(dlDir, "bad_sums"), []byte("1"), 0o600)
			out, _, err = runStart(badHome, nil, "-ExpectedHost", "pen2.gate.example.com", "https://pen2.gate.example.com/join#t=tok123")
			_ = os.Remove(filepath.Join(dlDir, "bad_sums"))
			if err == nil || !strings.Contains(out, "SHA-256") || strings.Contains(out, "FAKE_HOGMAN_ARGS") {
				t.Fatalf("case 7 (bad SHA-256) should fail without running binary, err=%v out=%s", err, out)
			}
			if _, statErr := os.Stat(filepath.Join(badHome, "hogman.exe")); !os.IsNotExist(statErr) {
				t.Fatalf("case 7: bad binary should not have been installed to %s", filepath.Join(badHome, "hogman.exe"))
			}

			// 8. HTTP / malformed links must be rejected before downloading.
			for _, badLink := range []string{
				"http://pen2.gate.example.com/join#t=abc",
				"https://pen2.gate.example.com/other#t=abc",
				"https://pen2.gate.example.com/join#t=",
				"https://user@pen2.gate.example.com/join#t=abc",
			} {
				out, curlLog, err = runStart(badHome, nil, badLink)
				if err == nil || strings.TrimSpace(curlLog) != "" {
					t.Fatalf("case 8 (bad link %q) should fail without curl, err=%v out=%s curlLog=%s", badLink, err, out, curlLog)
				}
			}

			// 9. Fresh machine + no link -> fails non-interactive.
			homeFresh := filepath.Join(tmp, shellName+"-fresh")
			_ = os.MkdirAll(homeFresh, 0o700)
			out, _, err = runStart(homeFresh, nil)
			if err == nil || !strings.Contains(out, "no terminal to ask for your invite link") {
				t.Fatalf("case 9 (fresh machine) should ask for invite link, err=%v out=%s", err, out)
			}
		})
	}
}
