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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
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

func brokerHealthURL(addr string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || port == "" {
		return "http://127.0.0.1:9090/health"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/health"
}

func checkBrokerHealth(ctx context.Context, healthURL, token string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	c := &http.Client{Timeout: 8 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg != "" {
			return fmt.Errorf("broker health %d: %s", resp.StatusCode, msg)
		}
		return fmt.Errorf("broker health %d", resp.StatusCode)
	}
	return nil
}

func runBrokerHealth() {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	url := brokerHealthURL(env("BROKER_ADDR", ":9090"))
	if err := checkBrokerHealth(ctx, url, readToken()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runBrokerLifecycleSweep(args []string) {
	dryRun := false
	for _, a := range args {
		switch a {
		case "--dry-run":
			dryRun = true
		default:
			fmt.Fprintf(os.Stderr, "usage: hogman-signup lifecycle-sweep [--dry-run]\n")
			os.Exit(2)
		}
	}
	u := strings.TrimSuffix(brokerHealthURL(env("BROKER_ADDR", ":9090")), "/health") + "/lifecycle/sweep"
	if dryRun {
		u += "?dry_run=1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", u, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+readToken())
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "lifecycle sweep HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(body)
}

func runBrokerLifecycleAlerts(args []string) {
	if len(args) < 2 || len(args) > 3 {
		fmt.Fprintf(os.Stderr, "usage: hogman-signup lifecycle-alert <pen> <list|add|remove> [email]\n")
		os.Exit(2)
	}
	payload := map[string]string{"pen": args[0], "action": args[1]}
	if len(args) == 3 {
		payload["email"] = args[2]
	}
	raw, _ := json.Marshal(payload)
	u := strings.TrimSuffix(brokerHealthURL(env("BROKER_ADDR", ":9090")), "/health") + "/lifecycle/alerts"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+readToken())
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "lifecycle-alert HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(body)
}

func runBrokerLifecycleTransition(args []string) {
	if len(args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: hogman-signup lifecycle-transition <sleep|wake|renew_only> <pen>\n")
		os.Exit(2)
	}
	payload := map[string]string{"action": args[0], "pen": args[1]}
	raw, _ := json.Marshal(payload)
	u := strings.TrimSuffix(brokerHealthURL(env("BROKER_ADDR", ":9090")), "/health") + "/lifecycle/transition"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+readToken())
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "lifecycle-transition HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	var res struct {
		Pen             string `json:"pen"`
		DeleteAfter     string `json:"delete_after"`
		FirstDeleteDate bool   `json:"first_delete_date"`
	}
	if json.Unmarshal(body, &res) == nil && res.FirstDeleteDate && res.DeleteAfter != "" {
		fmt.Fprintf(os.Stderr, "==> pen %s scheduled for automatic deletion after %s unless woken\n", res.Pen, res.DeleteAfter)
	}
	_, _ = os.Stdout.Write(body)
}

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "health":
			runBrokerHealth()
			return
		case "lifecycle-sweep":
			runBrokerLifecycleSweep(os.Args[2:])
			return
		case "lifecycle-alert":
			runBrokerLifecycleAlerts(os.Args[2:])
			return
		case "lifecycle-transition":
			runBrokerLifecycleTransition(os.Args[2:])
			return
		}
	}
	switch env("ROLE", "") {
	case "web":
		runWeb()
	case "broker":
		runBroker()
	default:
		log.Fatal("set ROLE=web or ROLE=broker")
	}
}
