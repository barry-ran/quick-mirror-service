package control

import (
	"encoding/json"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"strings"
	"testing"
)

func TestGenerationCanonicalBoundaries(t *testing.T) {
	for _, v := range []string{"1", "9223372036854775807"} {
		if e := generation(v); e != nil {
			t.Errorf("valid %q: %v", v, e)
		}
	}
	for _, v := range []string{"", "0", "-1", "+1", "01", "1.0", "9223372036854775808", "18446744073709551615"} {
		if generation(v) == nil {
			t.Errorf("accepted %q", v)
		}
	}
	if bump(Intent{Revision: "9223372036854775807"}) == nil {
		t.Fatal("revision wrapped")
	}
}

func TestPreviousBootVisibleOnlyToMobile(t *testing.T) {
	original := Intent{runtimeBoot: "88888888-8888-4888-8888-888888888888", runtimeHash: []byte("secret-hash"), DrainToken: "challenge"}
	mobile := visible(original, identity.Principal{Role: identity.Mobile})
	if mobile.PreviousBootID != original.runtimeBoot {
		t.Fatal("mobile missing original boot")
	}
	pc := visible(mobile, identity.Principal{Role: identity.PC})
	if pc.PreviousBootID != "" || pc.DrainToken != "" {
		t.Fatal("mobile recovery metadata leaked to PC")
	}
	wire, err := json.Marshal(mobile)
	if err != nil || strings.Contains(string(wire), "secret-hash") || strings.Contains(string(wire), "runtime_hash") || strings.Contains(string(wire), "runtime_proof") {
		t.Fatal("runtime secret leaked", err)
	}
}
