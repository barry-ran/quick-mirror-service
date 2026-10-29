package identity

import "testing"

func TestNormalizeUUID(t *testing.T) {
	for _, input := range []string{"", "abc", " abcdefab-1234-4567-8901-abcdefabcdef", "abcdefab-1234-4567-8901-abcdefabcdef\n"} {
		if _, ok := NormalizeUUID(input); ok {
			t.Fatalf("accepted %q", input)
		}
	}
	if got, ok := NormalizeUUID("ABCDEFAB-1234-4567-8901-ABCDEFABCDEF"); !ok || got != "abcdefab-1234-4567-8901-abcdefabcdef" {
		t.Fatal(got, ok)
	}
}
