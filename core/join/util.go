package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

func sha1Hex(b []byte) string {
	s := sha1.Sum(b)
	return strings.ToUpper(hex.EncodeToString(s[:]))
}

var verbose bool

func say(f string, a ...any)  { fmt.Printf(f+"\n", a...) }
func step(f string, a ...any) { fmt.Printf("\n• "+f+"\n", a...) }
func note(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) }

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

var (
	stdinMu     sync.Mutex
	stdinFile   *os.File
	stdinReader *bufio.Reader
)

func ask(prompt string) string {
	fmt.Print(prompt)
	stdinMu.Lock()
	if stdinReader == nil || stdinFile != os.Stdin {
		stdinFile = os.Stdin
		stdinReader = bufio.NewReader(os.Stdin)
	}
	r := stdinReader
	stdinMu.Unlock()
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

func confirm(prompt string) bool {
	a := strings.ToLower(ask(prompt + " [y/N] "))
	return a == "y" || a == "yes"
}

// sudoPath returns the absolute path to sudo from trusted system directories so
// a poisoned PATH entry cannot hijack privileged invocations.
func sudoPath() string {
	for _, p := range []string{"/usr/bin/sudo", "/bin/sudo", "/run/wrappers/bin/sudo"} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// sudoExplained records that explainSudo already spoke this run.
var sudoExplained bool

// explainSudo says once, before the OS asks, why a password is needed, so a
// bare "Password:" never appears unexplained. Silent when no prompt will come.
// It uses the same trusted sudo as run, never a PATH lookup.
func explainSudo(why string) {
	if sudoExplained || isRoot() {
		return
	}
	sudo := sudoPath()
	if sudo == "" {
		return
	}
	if exec.Command(sudo, "-n", "true").Run() == nil {
		return // sudo won't ask: already authorized
	}
	sudoExplained = true
	note("Your computer's password is needed %s. It goes to the system, not to Hogman.", why)
}

// run executes a command, returning combined output. With asRoot, it uses sudo
// when not already root (the OS will ask for the password once).
func run(asRoot bool, name string, args ...string) (string, error) {
	if asRoot && !isRoot() {
		if sp := sudoPath(); sp != "" {
			args = append([]string{name}, args...)
			name = sp
		}
	}
	if verbose {
		note("$ %s %s", name, strings.Join(args, " "))
	}
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if asRoot && !isRoot() {
		cmd.Stdin = os.Stdin // lets sudo ask for a password without leaking native-host stdin to unprivileged children
	}
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}
