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
	"crypto/rand"
	"log"
	"math/big"
	"net"
	"os"
	"regexp"
	"strings"
)

const (
	// Free/default sign-ups append "-" + 4 unambiguous lowercase chars so bare
	// vanity names cannot be squatted and users never collide on common words.
	penSuffixLen         = 4
	maxSuffixedPrefixLen = 30 - 1 - penSuffixLen // 25, keeping total <= 30
	penSuffixAlphabet    = "abcdefghjkmnpqrstuvwxyz23456789"
)

// Pen names become <name>.<pens zone> and <name>.<gate domain>: 3-30 characters.
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

func validPenPrefix(n string) (string, bool) {
	if len(n) > maxSuffixedPrefixLen {
		return "3 to 25 lowercase letters, digits and dashes, starting with a letter (we add a 4-character ending)", false
	}
	if why, ok := validPen(n); !ok {
		if !penRE.MatchString(n) {
			return "3 to 25 lowercase letters, digits and dashes, starting with a letter (we add a 4-character ending)", false
		}
		return why, false
	}
	return "", true
}

func randomPenSuffix() (string, error) {
	max := big.NewInt(int64(len(penSuffixAlphabet)))
	out := make([]byte, penSuffixLen)
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = penSuffixAlphabet[n.Int64()]
	}
	return string(out), nil
}

// parseCodeMeta extracts optional leading "vanity" and "work" tags (in either
// order) from a code's note in $HOGMAN_HOME/signup/codes:
//
//	"CODE vanity work paid cs_..." -> vanity=true, plan="work", note="paid cs_..."
//	"CODE for alice"               -> vanity=false, plan="personal", note="for alice"
func parseCodeMeta(rawNote string) (vanity bool, plan, note string) {
	rest := strings.TrimSpace(rawNote)
	plan = planPersonal
	for {
		word, after, hasSpace := strings.Cut(rest, " ")
		switch word {
		case "vanity":
			if vanity {
				return vanity, plan, rest
			}
			vanity = true
		case "work":
			if plan == planWork {
				return vanity, plan, rest
			}
			plan = planWork
		default:
			return vanity, plan, rest
		}
		if !hasSpace {
			return vanity, plan, ""
		}
		rest = strings.TrimSpace(after)
	}
}

func normalisePlan(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", planPersonal:
		return planPersonal, true
	case planWork:
		return planWork, true
	default:
		return "", false
	}
}

func validHandle(h string) (string, bool) {
	if !handleRE.MatchString(h) {
		return "2 to 32 lowercase letters, digits and dashes, starting with a letter", false
	}
	return "", true
}

func normCode(c string) string { return strings.ToUpper(strings.TrimSpace(c)) }

// normaliseTheme checks a pen UI theme against the strict allowlist:
// empty or "default" -> "" (default theme); "work" -> "work".
func normaliseTheme(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "default":
		return "", true
	case "work":
		return "work", true
	default:
		return "", false
	}
}

// stripHostPort extracts a lowercased bare hostname from a Host header or URL host.
func stripHostPort(raw string) string {
	s := strings.TrimSpace(raw)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

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
