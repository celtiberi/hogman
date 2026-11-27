package main

import "testing"

func envLookup(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestCapsConfigDefaultsAndValidation(t *testing.T) {
	t.Parallel()

	def := DefaultCapsConfig()
	if err := def.Validate(); err != nil {
		t.Fatalf("DefaultCapsConfig.Validate: %v", err)
	}
	if def.Hourly() != 5 || def.Weekly() != 20 || def.WorkHourly() != 40 || def.WorkWeekly() != 120 ||
		def.GlobalHourly() != 80 || def.GlobalHardHourly() != 120 || def.LEWeekly() != 300 || def.WeeklyAlertThreshold() != 240 {
		t.Fatalf("unexpected defaults: %+v", def)
	}

	// Zero-value CapsConfig resolves cleanly to defaults.
	var zero CapsConfig
	if zero.Hourly() != 5 || zero.Weekly() != 20 || zero.WorkHourly() != 40 || zero.WorkWeekly() != 120 ||
		zero.GlobalHourly() != 80 || zero.GlobalHardHourly() != 120 || zero.LEWeekly() != 300 {
		t.Fatalf("zero CapsConfig resolved unexpectedly: %+v", zero.resolved())
	}

	// Setting only GlobalHourlyCap defaults hard ceiling to match soft.
	partial := CapsConfig{GlobalHourlyCap: 4}
	if partial.GlobalHourly() != 4 || partial.GlobalHardHourly() != 4 {
		t.Fatalf("partial global soft-only = (%d, %d), want (4, 4)", partial.GlobalHourly(), partial.GlobalHardHourly())
	}
}

func TestCapsConfigFromEnv(t *testing.T) {
	t.Parallel()

	cfg, err := CapsConfigFromEnv(envLookup(nil))
	if err != nil {
		t.Fatalf("empty env: %v", err)
	}
	if cfg != DefaultCapsConfig() {
		t.Fatalf("empty env = %+v, want %+v", cfg, DefaultCapsConfig())
	}

	cfg, err = CapsConfigFromEnv(envLookup(map[string]string{
		"CDNS_HOURLY_CAP":             "3",
		"CDNS_WEEKLY_CAP":             "12",
		"CDNS_WORK_HOURLY_CAP":        "20",
		"CDNS_WORK_WEEKLY_CAP":        "60",
		"CDNS_GLOBAL_HOURLY_CAP":      "30",
		"CDNS_GLOBAL_HARD_HOURLY_CAP": "45",
		"CDNS_LE_WEEKLY_ALLOWANCE":    "200",
	}))
	if err != nil {
		t.Fatalf("explicit overrides: %v", err)
	}
	if cfg.HourlyCap != 3 || cfg.WeeklyCap != 12 || cfg.WorkHourlyCap != 20 || cfg.WorkWeeklyCap != 60 ||
		cfg.GlobalHourlyCap != 30 || cfg.GlobalHardHourlyCap != 45 || cfg.LEWeeklyAllowance != 200 {
		t.Fatalf("unexpected overrides: %+v", cfg)
	}

	// Lowering weekly cap clamps unset hourly cap down.
	cfg, err = CapsConfigFromEnv(envLookup(map[string]string{"CDNS_WEEKLY_CAP": "3"}))
	if err != nil || cfg.HourlyCap != 3 || cfg.WeeklyCap != 3 {
		t.Fatalf("weekly-only clamp = (%+v, %v), want hourly=3 weekly=3", cfg, err)
	}

	// Raising global soft above default hard lifts unset hard to match.
	cfg, err = CapsConfigFromEnv(envLookup(map[string]string{"CDNS_GLOBAL_HOURLY_CAP": "150"}))
	if err != nil || cfg.GlobalHourlyCap != 150 || cfg.GlobalHardHourlyCap != 150 {
		t.Fatalf("soft-above-default-hard = (%+v, %v), want 150/150", cfg, err)
	}

	// Lowering global soft clamps unset work hourly cap down.
	cfg, err = CapsConfigFromEnv(envLookup(map[string]string{"CDNS_GLOBAL_HOURLY_CAP": "6"}))
	if err != nil || cfg.WorkHourlyCap != 6 || cfg.WorkWeeklyCap != defaultWorkWeeklyCap {
		t.Fatalf("global clamp work hourly = (%+v, %v), want workHourly=6", cfg, err)
	}

	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{"hourly > weekly", map[string]string{"CDNS_HOURLY_CAP": "6", "CDNS_WEEKLY_CAP": "5"}},
		{"global < hourly", map[string]string{"CDNS_HOURLY_CAP": "5", "CDNS_GLOBAL_HOURLY_CAP": "4"}},
		{"hard < soft", map[string]string{"CDNS_GLOBAL_HOURLY_CAP": "50", "CDNS_GLOBAL_HARD_HOURLY_CAP": "40"}},
		{"work hourly > work weekly", map[string]string{"CDNS_WORK_HOURLY_CAP": "20", "CDNS_WORK_WEEKLY_CAP": "10"}},
		{"work hourly > global", map[string]string{"CDNS_WORK_HOURLY_CAP": "90", "CDNS_GLOBAL_HOURLY_CAP": "80"}},
		{"zero hourly", map[string]string{"CDNS_HOURLY_CAP": "0"}},
		{"negative weekly", map[string]string{"CDNS_WEEKLY_CAP": "-1"}},
		{"huge weekly", map[string]string{"CDNS_WEEKLY_CAP": "1001"}},
		{"bad global", map[string]string{"CDNS_GLOBAL_HOURLY_CAP": "10001"}},
		{"bad hard", map[string]string{"CDNS_GLOBAL_HARD_HOURLY_CAP": "10001"}},
		{"bad LE allowance", map[string]string{"CDNS_LE_WEEKLY_ALLOWANCE": "100001"}},
		{"non-int", map[string]string{"CDNS_HOURLY_CAP": "abc"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := CapsConfigFromEnv(envLookup(tc.env)); err == nil {
				t.Fatalf("CapsConfigFromEnv(%s) succeeded, want error", tc.name)
			}
		})
	}
}
