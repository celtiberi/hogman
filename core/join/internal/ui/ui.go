package ui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"

	"hogman/join/internal/link"
)

// MaxStdinLinkBytes bounds --link-stdin input. Oversized input is rejected
// rather than truncated.
const MaxStdinLinkBytes = 16 * 1024

// UI owns CLI user-facing streams and interactive prompt seams so commands and
// helpers can be unit-tested in parallel without mutating package globals.
type UI struct {
	In             io.Reader
	Out            io.Writer
	Err            io.Writer
	IsTerminalFn   func() bool
	AskFn          func(prompt string) string
	ConfirmFn      func(prompt string) bool
	TypedConfirmFn func(expected, warning string) bool
	NoteFn         func(f string, a ...any)

	mu       sync.Mutex
	readerIn io.Reader
	reader   *bufio.Reader
}

// Default returns a UI wired to standard OS streams.
func Default() *UI { return &UI{} }

func (u *UI) in() io.Reader {
	if u != nil && u.In != nil {
		return u.In
	}
	return os.Stdin
}

// OutWriter returns the stdout writer for this UI (falling back to os.Stdout).
func (u *UI) OutWriter() io.Writer {
	if u != nil && u.Out != nil {
		return u.Out
	}
	return os.Stdout
}

// ErrWriter returns the stderr writer for this UI (falling back to os.Stderr).
func (u *UI) ErrWriter() io.Writer {
	if u != nil && u.Err != nil {
		return u.Err
	}
	return os.Stderr
}

func (u *UI) Say(f string, a ...any) {
	fmt.Fprintf(u.OutWriter(), f+"\n", a...)
}

func (u *UI) Step(f string, a ...any) {
	fmt.Fprintf(u.ErrWriter(), "\n• "+f+"\n", a...)
}

func (u *UI) Note(f string, a ...any) {
	if u != nil && u.NoteFn != nil {
		u.NoteFn(f, a...)
		return
	}
	fmt.Fprintf(u.ErrWriter(), "  "+f+"\n", a...)
}

func (u *UI) WriteJSON(v any) error {
	enc := json.NewEncoder(u.OutWriter())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (u *UI) IsTerminal() bool {
	if u != nil && u.IsTerminalFn != nil {
		return u.IsTerminalFn()
	}
	if f, ok := u.in().(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return false
}

func (u *UI) Ask(prompt string) string {
	if u != nil && u.AskFn != nil {
		return u.AskFn(prompt)
	}
	fmt.Fprint(u.ErrWriter(), prompt)
	in := u.in()
	if u == nil {
		r := bufio.NewReader(in)
		line, _ := r.ReadString('\n')
		return strings.TrimSpace(line)
	}
	u.mu.Lock()
	if u.reader == nil || u.readerIn != in {
		u.readerIn = in
		u.reader = bufio.NewReader(in)
	}
	r := u.reader
	u.mu.Unlock()
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

func (u *UI) Confirm(prompt string) bool {
	if u != nil && u.ConfirmFn != nil {
		return u.ConfirmFn(prompt)
	}
	a := strings.ToLower(u.Ask(prompt + " [y/N] "))
	return a == "y" || a == "yes"
}

func (u *UI) TypedConfirm(expected, warning string) bool {
	if u != nil && u.TypedConfirmFn != nil {
		return u.TypedConfirmFn(expected, warning)
	}
	if !u.IsTerminal() {
		u.Note("refusing: confirmation needs a terminal (pass --force in scripts)")
		return false
	}
	u.Say("\n⚠ %s", warning)
	return u.Ask("  Type "+expected+" to leave anyway, or press Enter to cancel: ") == expected
}

// ReadJoinLink reads a join/share link from stdin (when fromStdin is true) or
// prompts interactively on a terminal. Oversized stdin input is rejected cleanly
// instead of truncated.
func (u *UI) ReadJoinLink(fromStdin bool, stdin io.Reader) (string, error) {
	if fromStdin {
		if stdin == nil {
			stdin = u.in()
		}
		b, err := io.ReadAll(io.LimitReader(stdin, MaxStdinLinkBytes+1))
		if err != nil {
			return "", link.Errorf("could not read join link from stdin: %v", err)
		}
		if len(b) > MaxStdinLinkBytes {
			return "", link.Errorf("join link on stdin exceeds %d KiB limit", MaxStdinLinkBytes>>10)
		}
		raw := strings.TrimSpace(string(b))
		if raw == "" {
			return "", link.Errorf("no join link received on stdin")
		}
		return raw, nil
	}
	if !u.IsTerminal() {
		return "", link.UsageErrorf("provide a join link in single quotes (hogman join '<link>') or pass --link-stdin")
	}
	raw := strings.TrimSpace(u.Ask("  Paste your join link: "))
	if raw == "" {
		return "", link.Errorf("no join link entered")
	}
	return raw, nil
}
