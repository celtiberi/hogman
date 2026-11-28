package registrar

import (
	"testing"
	"time"
)

func TestConfigWithDefaults(t *testing.T) {
	got := (Config{MaxMembers: -5, PresenceTTL: -time.Second}).withDefaults()
	if got.MaxMembers != DefaultMaxMembers {
		t.Errorf("MaxMembers = %d, want %d", got.MaxMembers, DefaultMaxMembers)
	}
	if got.MaxDevices != DefaultMaxDevices {
		t.Errorf("MaxDevices = %d, want %d", got.MaxDevices, DefaultMaxDevices)
	}
	if got.MaxOpenDeviceKeys != defaultMaxOpenDeviceKeys {
		t.Errorf("MaxOpenDeviceKeys = %d, want %d", got.MaxOpenDeviceKeys, defaultMaxOpenDeviceKeys)
	}
	if got.MaxAdminOpenDeviceKeys != defaultMaxAdminOpenDeviceKeys {
		t.Errorf("MaxAdminOpenDeviceKeys = %d, want %d", got.MaxAdminOpenDeviceKeys, defaultMaxAdminOpenDeviceKeys)
	}
	if got.MaxNamesPerMember != defaultMaxNamesPerMember {
		t.Errorf("MaxNamesPerMember = %d, want %d", got.MaxNamesPerMember, defaultMaxNamesPerMember)
	}
	if got.MaxOpenInvites != defaultMaxOpenInvites {
		t.Errorf("MaxOpenInvites = %d, want %d", got.MaxOpenInvites, defaultMaxOpenInvites)
	}
	if got.MaxInviteNoteLen != defaultMaxInviteNoteLen {
		t.Errorf("MaxInviteNoteLen = %d, want %d", got.MaxInviteNoteLen, defaultMaxInviteNoteLen)
	}
	if got.MaxServerEABPerDay != defaultMaxServerEABPerDay {
		t.Errorf("MaxServerEABPerDay = %d, want %d", got.MaxServerEABPerDay, defaultMaxServerEABPerDay)
	}
	if got.MaxMemberEABPerDay != defaultMaxMemberEABPerDay {
		t.Errorf("MaxMemberEABPerDay = %d, want %d", got.MaxMemberEABPerDay, defaultMaxMemberEABPerDay)
	}
	if got.MaxMemberACMETXTPerHour != defaultMaxMemberACMETXTPerHour {
		t.Errorf("MaxMemberACMETXTPerHour = %d, want %d", got.MaxMemberACMETXTPerHour, defaultMaxMemberACMETXTPerHour)
	}
	if got.PresenceTTL != defaultPresenceTTL {
		t.Errorf("PresenceTTL = %v, want %v", got.PresenceTTL, defaultPresenceTTL)
	}

	clamped := (Config{
		MaxOpenDeviceKeys:      15,
		MaxAdminOpenDeviceKeys: 4,
		PresenceTTL:            2 * time.Second,
	}).withDefaults()
	if clamped.MaxAdminOpenDeviceKeys != 15 {
		t.Errorf("MaxAdminOpenDeviceKeys = %d, want clamped 15", clamped.MaxAdminOpenDeviceKeys)
	}
	if clamped.PresenceTTL != 2*time.Second {
		t.Errorf("PresenceTTL = %v, want 2s", clamped.PresenceTTL)
	}
}
