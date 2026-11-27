package main

import (
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// CapsConfig holds certificate-name and EAB rate-limit caps across plans and
// the global fleet, plus the 7-day Let's Encrypt allowance used for alerting.
type CapsConfig struct {
	HourlyCap           int // distinct new names per personal pen per rolling hour
	WeeklyCap           int // distinct new names per personal pen per rolling 7 days
	WorkHourlyCap       int // distinct new names per work pen per rolling hour
	WorkWeeklyCap       int // distinct new names per work pen per rolling 7 days
	GlobalHourlyCap     int // soft global hourly cap across all pens
	GlobalHardHourlyCap int // hard global hourly ceiling (headroom above soft is reserved for quiet pens)
	LEWeeklyAllowance   int // Let's Encrypt 7-day registered-domain allowance for 80% alerting
}

// DefaultCapsConfig returns the production default certificate caps.
func DefaultCapsConfig() CapsConfig {
	return CapsConfig{
		HourlyCap:           defaultHourlyCap,
		WeeklyCap:           defaultCapNames,
		WorkHourlyCap:       defaultWorkHourlyCap,
		WorkWeeklyCap:       defaultWorkWeeklyCap,
		GlobalHourlyCap:     defaultGlobalHourlyCap,
		GlobalHardHourlyCap: defaultGlobalHardHourlyCap,
		LEWeeklyAllowance:   defaultLEWeeklyAllowance,
	}
}

// resolved fills zero fields with defaults and applies consistent ordering
// clamps so partial struct literals in tests behave predictably.
func (c CapsConfig) resolved() CapsConfig {
	out := c
	if out.WeeklyCap <= 0 {
		out.WeeklyCap = defaultCapNames
	}
	if out.HourlyCap <= 0 {
		out.HourlyCap = defaultHourlyCap
	}
	if out.HourlyCap > out.WeeklyCap {
		out.HourlyCap = out.WeeklyCap
	}
	if out.WorkWeeklyCap <= 0 {
		out.WorkWeeklyCap = defaultWorkWeeklyCap
	}
	if out.WorkHourlyCap <= 0 {
		out.WorkHourlyCap = defaultWorkHourlyCap
	}
	if out.WorkHourlyCap > out.WorkWeeklyCap {
		out.WorkHourlyCap = out.WorkWeeklyCap
	}
	softWasSet := out.GlobalHourlyCap > 0
	if !softWasSet {
		out.GlobalHourlyCap = defaultGlobalHourlyCap
	}
	if out.GlobalHardHourlyCap <= 0 {
		if softWasSet {
			out.GlobalHardHourlyCap = out.GlobalHourlyCap
		} else {
			out.GlobalHardHourlyCap = defaultGlobalHardHourlyCap
		}
	}
	if out.GlobalHardHourlyCap < out.GlobalHourlyCap {
		out.GlobalHardHourlyCap = out.GlobalHourlyCap
	}
	if out.LEWeeklyAllowance <= 0 {
		out.LEWeeklyAllowance = defaultLEWeeklyAllowance
	}
	return out
}

// Validate checks bounds and cross-field ordering invariants on a fully
// populated CapsConfig.
func (c CapsConfig) Validate() error {
	checkRange := func(name string, v, max int) error {
		if v < 1 || v > max {
			return fmt.Errorf("%s must be an integer between 1 and %d (got %d)", name, max, v)
		}
		return nil
	}
	if err := checkRange("CDNS_WEEKLY_CAP", c.WeeklyCap, 1000); err != nil {
		return err
	}
	if err := checkRange("CDNS_HOURLY_CAP", c.HourlyCap, 1000); err != nil {
		return err
	}
	if c.HourlyCap > c.WeeklyCap {
		return fmt.Errorf("CDNS_HOURLY_CAP (%d) must not exceed CDNS_WEEKLY_CAP (%d)", c.HourlyCap, c.WeeklyCap)
	}
	if err := checkRange("CDNS_GLOBAL_HOURLY_CAP", c.GlobalHourlyCap, 10000); err != nil {
		return err
	}
	if c.GlobalHourlyCap < c.HourlyCap {
		return fmt.Errorf("CDNS_GLOBAL_HOURLY_CAP (%d) must be at least CDNS_HOURLY_CAP (%d)", c.GlobalHourlyCap, c.HourlyCap)
	}
	if err := checkRange("CDNS_GLOBAL_HARD_HOURLY_CAP", c.GlobalHardHourlyCap, 10000); err != nil {
		return err
	}
	if c.GlobalHardHourlyCap < c.GlobalHourlyCap {
		return fmt.Errorf("CDNS_GLOBAL_HARD_HOURLY_CAP (%d) must be at least CDNS_GLOBAL_HOURLY_CAP (%d)", c.GlobalHardHourlyCap, c.GlobalHourlyCap)
	}
	if err := checkRange("CDNS_WORK_WEEKLY_CAP", c.WorkWeeklyCap, 1000); err != nil {
		return err
	}
	if err := checkRange("CDNS_WORK_HOURLY_CAP", c.WorkHourlyCap, 1000); err != nil {
		return err
	}
	if c.WorkHourlyCap > c.WorkWeeklyCap {
		return fmt.Errorf("CDNS_WORK_HOURLY_CAP (%d) must not exceed CDNS_WORK_WEEKLY_CAP (%d)", c.WorkHourlyCap, c.WorkWeeklyCap)
	}
	if c.WorkHourlyCap > c.GlobalHourlyCap {
		return fmt.Errorf("CDNS_WORK_HOURLY_CAP (%d) must not exceed CDNS_GLOBAL_HOURLY_CAP (%d)", c.WorkHourlyCap, c.GlobalHourlyCap)
	}
	if err := checkRange("CDNS_LE_WEEKLY_ALLOWANCE", c.LEWeeklyAllowance, 100000); err != nil {
		return err
	}
	return nil
}

func (c CapsConfig) Hourly() int           { return c.resolved().HourlyCap }
func (c CapsConfig) Weekly() int           { return c.resolved().WeeklyCap }
func (c CapsConfig) WorkHourly() int       { return c.resolved().WorkHourlyCap }
func (c CapsConfig) WorkWeekly() int       { return c.resolved().WorkWeeklyCap }
func (c CapsConfig) GlobalHourly() int     { return c.resolved().GlobalHourlyCap }
func (c CapsConfig) GlobalHardHourly() int { return c.resolved().GlobalHardHourlyCap }
func (c CapsConfig) LEWeekly() int         { return c.resolved().LEWeeklyAllowance }

func (c CapsConfig) WeeklyFor(cred Cred) int {
	if cred.Plan == planWork {
		return c.WorkWeekly()
	}
	return c.Weekly()
}

func (c CapsConfig) HourlyFor(cred Cred) int {
	if cred.Plan == planWork {
		return c.WorkHourly()
	}
	return c.Hourly()
}

func (c CapsConfig) WeeklyAlertThreshold() int {
	allowance := c.LEWeekly()
	t := (allowance*weeklyAlertPct + 99) / 100
	if t < 1 {
		return 1
	}
	return t
}

func parseCap(envName, raw string, def, max int) (int, error) {
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > max {
		return 0, fmt.Errorf("%s must be an integer between 1 and %d (got %q)", envName, max, raw)
	}
	return n, nil
}

// CapsConfigFromEnv parses and validates all CDNS_* cap settings using lookup
// (typically os.Getenv). Unset dependent caps automatically clamp to stay
// valid against explicitly lowered/raised sibling settings.
func CapsConfigFromEnv(lookup func(string) string) (CapsConfig, error) {
	if lookup == nil {
		lookup = os.Getenv
	}
	weekly, err := parseCap("CDNS_WEEKLY_CAP", lookup("CDNS_WEEKLY_CAP"), defaultCapNames, 1000)
	if err != nil {
		return CapsConfig{}, err
	}
	hourlyRaw := lookup("CDNS_HOURLY_CAP")
	hourlyDef := defaultHourlyCap
	if hourlyRaw == "" && weekly < hourlyDef {
		hourlyDef = weekly
	}
	hourly, err := parseCap("CDNS_HOURLY_CAP", hourlyRaw, hourlyDef, 1000)
	if err != nil {
		return CapsConfig{}, err
	}
	globalHourly, err := parseCap("CDNS_GLOBAL_HOURLY_CAP", lookup("CDNS_GLOBAL_HOURLY_CAP"), defaultGlobalHourlyCap, 10000)
	if err != nil {
		return CapsConfig{}, err
	}
	globalHardRaw := lookup("CDNS_GLOBAL_HARD_HOURLY_CAP")
	globalHardDef := defaultGlobalHardHourlyCap
	if globalHardRaw == "" && globalHourly > globalHardDef {
		globalHardDef = globalHourly
	}
	globalHardHourly, err := parseCap("CDNS_GLOBAL_HARD_HOURLY_CAP", globalHardRaw, globalHardDef, 10000)
	if err != nil {
		return CapsConfig{}, err
	}
	workWeekly, err := parseCap("CDNS_WORK_WEEKLY_CAP", lookup("CDNS_WORK_WEEKLY_CAP"), defaultWorkWeeklyCap, 1000)
	if err != nil {
		return CapsConfig{}, err
	}
	workHourlyRaw := lookup("CDNS_WORK_HOURLY_CAP")
	workHourlyDef := defaultWorkHourlyCap
	if workHourlyRaw == "" {
		if workWeekly < workHourlyDef {
			workHourlyDef = workWeekly
		}
		if globalHourly < workHourlyDef {
			workHourlyDef = globalHourly
		}
	}
	workHourly, err := parseCap("CDNS_WORK_HOURLY_CAP", workHourlyRaw, workHourlyDef, 1000)
	if err != nil {
		return CapsConfig{}, err
	}
	leWeekly, err := parseCap("CDNS_LE_WEEKLY_ALLOWANCE", lookup("CDNS_LE_WEEKLY_ALLOWANCE"), defaultLEWeeklyAllowance, 100000)
	if err != nil {
		return CapsConfig{}, err
	}
	cfg := CapsConfig{
		HourlyCap:           hourly,
		WeeklyCap:           weekly,
		WorkHourlyCap:       workHourly,
		WorkWeeklyCap:       workWeekly,
		GlobalHourlyCap:     globalHourly,
		GlobalHardHourlyCap: globalHardHourly,
		LEWeeklyAllowance:   leWeekly,
	}
	if err := cfg.Validate(); err != nil {
		return CapsConfig{}, err
	}
	return cfg, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func zonesFromEnv() Zones {
	return Zones{
		Pens: normalize(env("CDNS_PENS_ZONE", "pens.hogman.network")),
		Gate: normalize(env("CDNS_GATE_NAME", "_acme-challenge.gate.hogman.network")),
	}
}

// parseContact checks the operator's contact address for fallback CA accounts:
// a bare address (no display name), or empty for none.
func parseContact(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	a, err := mail.ParseAddress(raw)
	if err != nil || a.Name != "" || a.Address != raw || strings.ContainsAny(raw, " ,;<>") {
		return "", fmt.Errorf("CDNS_GTS_CONTACT must be a plain email address like ops@example.com (got %q)", raw)
	}
	return raw, nil
}

func parseNtfyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Path == "" || u.Path == "/" {
		return "", fmt.Errorf("CDNS_NTFY_URL must be an https:// URL with a topic path (got %q)", raw)
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		if u.Scheme != "http" || (host != "127.0.0.1" && host != "::1") {
			return "", fmt.Errorf("CDNS_NTFY_URL must use https:// (got %q)", raw)
		}
	}
	return raw, nil
}
