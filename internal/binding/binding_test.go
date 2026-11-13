package binding

import (
	"encoding/json"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"strings"
	"testing"
)

func TestCodeAndIdentityFormats(t *testing.T) {
	for _, s := range []string{"000001", "999999", "123456"} {
		if !ValidCode(s) {
			t.Fatal("valid code rejected")
		}
	}
	for _, s := range []string{"12345", "1234567", " 123456", "123456\n", "１２３４５６", "abcdef"} {
		if ValidCode(s) {
			t.Fatal("invalid format accepted")
		}
	}
	for i := 0; i < 100; i++ {
		code, e := newCode()
		if e != nil || !ValidCode(code) {
			t.Fatal("code generation", e)
		}
		id, e := newID()
		if _, ok := identity.NormalizeUUID(id); e != nil || !ok {
			t.Fatal("id generation", e)
		}
	}
}
func TestBoundMobileHidesCodeAndRevisionStaysString(t *testing.T) {
	b, e := json.Marshal(Code{Bound: true, Binding: &Relation{ID: "x", Revision: "2", Active: true}})
	if e != nil || strings.Contains(string(b), `"code"`) || !strings.Contains(string(b), `"revision":"2"`) {
		t.Fatal(string(b), e)
	}
}
