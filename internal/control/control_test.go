package control

import "testing"

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
