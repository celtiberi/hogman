package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

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
