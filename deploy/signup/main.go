// hogman-signup: the page where people get a pen of their own on this
// server, and the broker that raises it.
//
// Two roles, one binary (ROLE=web or ROLE=broker):
//
//   - web: the public page. Unprivileged. It checks what people type, keeps
//     a rate limit, and asks the broker.
//   - broker: drives `hogman-host provision`, so it is as powerful as root. It
//     listens only on a private network shared with the page, needs a token,
//     and does three things: capacity, is-this-name-free, raise-a-pen.
package main

import (
	"log"
	"os"
	"regexp"
	"strings"
)

// Pen names become <name>.hogman and <name>.<pens domain>: 3-30 characters.
// Handles follow the registrar's rule.
var (
	penRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,28}[a-z0-9]$`)
	handleRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	codeRE   = regexp.MustCompile(`^PIG-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`)

	// Names that would confuse people or collide with ours.
	reservedPens = map[string]bool{
		"www": true, "get": true, "api": true, "admin": true, "hogman": true, "pens": true,
		"mail": true, "smtp": true, "hs": true, "home": true, "join": true, "signup": true,
		"support": true, "help": true, "status": true, "root": true, "test": true,
		"localhost": true, "example": true, "dl": true, "ca": true, "ns": true,
	}
)

func validPen(n string) (string, bool) {
	switch {
	case !penRE.MatchString(n):
		return "3 to 30 lowercase letters, digits and dashes, starting with a letter", false
	case strings.Contains(n, "--"):
		return "no double dashes", false
	case reservedPens[n]:
		return "that name is reserved", false
	}
	return "", true
}

func validHandle(h string) (string, bool) {
	if !handleRE.MatchString(h) {
		return "2 to 32 lowercase letters, digits and dashes, starting with a letter", false
	}
	return "", true
}

func normCode(c string) string { return strings.ToUpper(strings.TrimSpace(c)) }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func readToken() string {
	f := env("BROKER_TOKEN_FILE", "")
	if f == "" {
		log.Fatal("BROKER_TOKEN_FILE is not set")
	}
	b, err := os.ReadFile(f)
	if err != nil {
		log.Fatalf("token: %v", err)
	}
	t := strings.TrimSpace(string(b))
	if len(t) < 32 {
		log.Fatal("token too short")
	}
	return t
}

func main() {
	log.SetFlags(0)
	switch env("ROLE", "") {
	case "web":
		runWeb()
	case "broker":
		runBroker()
	default:
		log.Fatal("set ROLE=web or ROLE=broker")
	}
}
