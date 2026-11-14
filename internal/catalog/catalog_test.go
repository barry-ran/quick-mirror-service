package catalog

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestStatusValidation(t *testing.T) {
	base := Status{BootID: "11111111-1111-4111-8111-111111111111", Sequence: 1, AppVersion: "1.0"}
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		change func(*Status)
	}{
		{"bad boot", func(s *Status) { s.BootID = "bad" }},
		{"negative sequence", func(s *Status) { s.Sequence = -1 }},
		{"zero sequence", func(s *Status) { s.Sequence = 0 }},
		{"long version", func(s *Status) { s.AppVersion = strings.Repeat("x", 129) }},
		{"null version", func(s *Status) { s.AppVersion = "a\x00" }},
		{"invalid utf8", func(s *Status) { s.AppVersion = string([]byte{0xff}) }},
		{"unsupported available", func(s *Status) { s.Capabilities = map[string]Capability{"touch": {Available: true}} }},
		{"long reason", func(s *Status) { s.Capabilities = map[string]Capability{"touch": {Reason: strings.Repeat("x", 257)}} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.change(&s)
			if s.validate() == nil {
				t.Fatal("invalid status accepted")
			}
		})
	}
}

func TestNavigationActionsStorageRoundTrip(t *testing.T) {
	actions := NavigationActions{"back", "home", "recents", "volume_up", "volume_down", "notifications"}
	original := map[string]Capability{"navigation_v1": {Supported: true, Available: true, Actions: &actions}, "touch": {Supported: true}}
	encoded, err := encodeCapabilities(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]Capability
	if err = json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, decoded) {
		t.Fatal("catalog JSON storage/list lost actions")
	}
	for _, name := range []string{"navigation_v1", "touch"} {
		status := Status{BootID: "11111111-1111-4111-8111-111111111111", Sequence: 1, Capabilities: map[string]Capability{name: {Actions: &actions}}}
		if (status.validate() == nil) != (name == "navigation_v1") {
			t.Fatal("navigation-only validation failed")
		}
	}
}
