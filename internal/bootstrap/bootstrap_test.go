package bootstrap

import (
	"strings"
	"testing"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

func TestFingerprints(t *testing.T) {
	valid := Request{Role: identity.Mobile, Label: "安装", IdempotencyKey: "abcdefab-1234-4567-8901-abcdefabcdef"}
	key, body, err := valid.fingerprints()
	if err != nil {
		t.Fatal(err)
	}
	upper := valid
	upper.IdempotencyKey = strings.ToUpper(valid.IdempotencyKey)
	k, b, err := upper.fingerprints()
	if err != nil || k != key || b != body {
		t.Fatal("UUID case normalization failed")
	}
	changed := valid
	changed.Label = "另一安装"
	k, b, err = changed.fingerprints()
	if err != nil || k != key || b == body {
		t.Fatal("label not bound to semantic body")
	}
	cases := []Request{
		{Role: "admin", IdempotencyKey: valid.IdempotencyKey},
		{Role: identity.PC, IdempotencyKey: "bad"},
		{Role: identity.PC, IdempotencyKey: valid.IdempotencyKey, Label: strings.Repeat("a", 257)},
		{Role: identity.PC, IdempotencyKey: valid.IdempotencyKey, Label: "line\nbreak"},
		{Role: identity.PC, IdempotencyKey: valid.IdempotencyKey, Label: string([]byte{0xff})},
	}
	for _, request := range cases {
		if _, _, err := request.fingerprints(); err != ErrInvalidInput {
			t.Fatal("accepted invalid request")
		}
	}
}
