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

func ask(prompt string) string {
	fmt.Print(prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line)
}

func confirm(prompt string) bool {
	a := strings.ToLower(ask(prompt + " [y/N] "))
	return a == "y" || a == "yes"
}

// run executes a command, returning combined output. With asRoot, it uses sudo
// when not already root (the OS will ask for the password once).
func run(asRoot bool, name string, args ...string) (string, error) {
	if asRoot && !isRoot() {
		if _, err := exec.LookPath("sudo"); err == nil {
			args = append([]string{name}, args...)
			name = "sudo"
		}
	}
	if verbose {
		note("$ %s %s", name, strings.Join(args, " "))
	}
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.Stdin = os.Stdin // lets sudo ask for a password
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}
