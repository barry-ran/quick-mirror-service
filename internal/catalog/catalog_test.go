package catalog

import (
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
