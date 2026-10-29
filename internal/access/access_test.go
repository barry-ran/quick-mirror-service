package access

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

func TestTokenEncodingAndAuthenticatedBinding(t *testing.T) {
	token := "qma_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	hash, valid := tokenHash(token)
	if !valid {
		t.Fatal("valid token rejected")
	}
	for _, invalid := range []string{"", token + "=", "dev_" + token[4:], strings.Repeat("x", 47), token[:46] + "+"} {
		if _, ok := tokenHash(invalid); ok {
			t.Fatal("noncanonical token accepted")
		}
	}
	block, err := aes.NewCipher(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	p := identity.Principal{DeviceID: "11111111-1111-4111-8111-111111111111", TenantID: "22222222-2222-4222-8222-222222222222", ApplicationID: "33333333-3333-4333-8333-333333333333", Role: identity.PC}
	expiry := time.Unix(1800000000, 0)
	nonce := bytes.Repeat([]byte{3}, 12)
	sealed := aead.Seal(nil, nonce, []byte("dev_fixture"), aad("scope", hash, p, expiry))
	if _, err := aead.Open(nil, nonce, sealed, aad("scope", hash, p, expiry)); err != nil {
		t.Fatal(err)
	}
	changed := p
	changed.Role = identity.Mobile
	for _, binding := range [][]byte{aad("other", hash, p, expiry), aad("scope", hash, changed, expiry), aad("scope", hash, p, expiry.Add(time.Minute)), aad("scope", [32]byte{}, p, expiry)} {
		if _, err := aead.Open(nil, nonce, sealed, binding); err == nil {
			t.Fatal("tampered token row authenticated")
		}
	}
	if validCredential("bad\nheader") || validCredential("") || validCredential(strings.Repeat("x", 513)) {
		t.Fatal("invalid source credential accepted")
	}
}
