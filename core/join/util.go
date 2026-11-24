package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/term"
)

var verbose bool

func say(f string, a ...any)  { fmt.Printf(f+"\n", a...) }
func step(f string, a ...any) { fmt.Fprintf(os.Stderr, "\n• "+f+"\n", a...) }
func note(f string, a ...any) { fmt.Fprintf(os.Stderr, "  "+f+"\n", a...) }

func isTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

var (
	stdinMu     sync.Mutex
	stdinFile   *os.File
	stdinReader *bufio.Reader
)

func ask(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
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

// redactCommandArgs hides secret flag values (such as Tailscale --authkey) before
// logging a command line under --verbose.
func redactCommandArgs(args []string) []string {
	out := make([]string, len(args))
	redactNext := false
	for i, a := range args {
		if redactNext {
			out[i] = "[redacted]"
			redactNext = false
			continue
		}
		lower := strings.ToLower(a)
		if lower == "--authkey" || lower == "-authkey" {
			out[i] = a
			redactNext = true
			continue
		}
		if eq := strings.IndexByte(lower, '='); eq > 0 {
			flag := lower[:eq]
			if flag == "--authkey" || flag == "-authkey" {
				out[i] = a[:eq+1] + "[redacted]"
				continue
			}
		}
		out[i] = a
	}
	return out
}

// run executes a command unprivileged, returning combined output. Hogman never
// invokes sudo or prompts for the computer's administrator password (D-41).
func run(name string, args ...string) (string, error) {
	if verbose {
		note("$ %s %s", name, strings.Join(redactCommandArgs(args), " "))
	}
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}
