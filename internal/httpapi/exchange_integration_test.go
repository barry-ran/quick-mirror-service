//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/access"
	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

type credentialFunc func(context.Context, string) (access.VerifiedCredential, error)

func (f credentialFunc) VerifyCredential(c context.Context, s string) (access.VerifiedCredential, error) {
	return f(c, s)
}

// 真实业务PostgreSQL与TLS HTTP接缝；权威安装身份明确为夹具，不能冒充正式上游联调。
func TestExchangeAndCatalogRealDatabaseOverTLS(t *testing.T) {
	ctx := context.Background()
	pool := testHTTPPool(t)
	mobilePrincipal := identity.Principal{DeviceID: mobile, TenantID: scope, ApplicationID: mobile, Role: identity.Mobile}
	pcPrincipal := identity.Principal{DeviceID: pc, TenantID: scope, ApplicationID: pc, Role: identity.PC}
	sourceExpiry := time.Now().UTC().Add(2 * time.Minute).Truncate(time.Microsecond)
	var revoked atomic.Bool
	verifier := credentialFunc(func(_ context.Context, s string) (access.VerifiedCredential, error) {
		switch s {
		case "mobile-installation":
			if revoked.Load() {
				return access.VerifiedCredential{}, identity.ErrInvalidCredential
			}
			return access.VerifiedCredential{Principal: mobilePrincipal, ExpiresAt: sourceExpiry}, nil
		case "pc-installation":
			return access.VerifiedCredential{Principal: pcPrincipal, ExpiresAt: sourceExpiry}, nil
		case "missing-expiry":
			return access.VerifiedCredential{Principal: mobilePrincipal}, nil
		default:
			return access.VerifiedCredential{}, identity.ErrInvalidCredential
		}
	})
	issuer, err := access.NewStore(pool, scope, scope, bytes.Repeat([]byte{7}, 32), verifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	directory, err := catalog.NewStore(pool, scope, scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	exchange, err := NewExchangeHandler(issuer, directory, 8)
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := NewCatalogHandler(issuer, directory, 8)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/qm/v1/auth/", exchange)
	mux.Handle("/qm/v1/devices/", catalogue)
	mux.Handle("/qm/v1/device-self/", catalogue)
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	request := func(method, path, credential string, body []byte) (int, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+credential)
		r.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("credential/catalogue response was cacheable")
		}
		return response.StatusCode, data
	}
	issue := func(path, credential string) access.Token {
		t.Helper()
		status, data := request(http.MethodPost, path, credential, []byte("{}"))
		if status != 200 {
			t.Fatalf("exchange status %d", status)
		}
		var response struct {
			Data access.Token `json:"data"`
		}
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatal("invalid token response")
		}
		token := response.Data
		if token.AccessToken == "" || token.Scope != scope || token.ExpiresAt.After(sourceExpiry) || !token.ExpiresAt.After(time.Now()) {
			t.Fatal("invalid or overlong token")
		}
		return token
	}
	phoneToken := issue("/qm/v1/auth/device/exchange", "mobile-installation")
	pcToken := issue("/qm/v1/auth/pc/exchange", "pc-installation")
	status, data := request(http.MethodPost, "/qm/v1/devices/resolve", pcToken.AccessToken, []byte(`{"uuids":["`+mobile+`"]}`))
	var resolved struct {
		Data struct {
			Items []struct {
				Found bool `json:"found"`
			} `json:"items"`
		} `json:"data"`
	}
	if status != 200 || json.Unmarshal(data, &resolved) != nil || len(resolved.Data.Items) != 1 || !resolved.Data.Items[0].Found {
		t.Fatal("verified mobile exchange did not register directory")
	}
	statusBody := []byte(`{"boot_id":"55555555-5555-4555-8555-555555555555","seq":7,"app_version":"retained","permissions":{"projection":true}}`)
	if status, _ := request(http.MethodPut, "/qm/v1/device-self/status", phoneToken.AccessToken, statusBody); status != 200 {
		t.Fatalf("status update=%d", status)
	}
	issue("/qm/v1/auth/device/exchange", "mobile-installation")
	items, err := directory.ResolveBatch(ctx, pcPrincipal, []string{mobile})
	if err != nil || len(items) != 1 || items[0].Device.AppVersion != "retained" || !items[0].Device.Permissions.Projection {
		t.Fatal("re-exchange reset directory snapshot")
	}
	if status, _ := request(http.MethodPut, "/qm/v1/device-self/status", phoneToken.AccessToken, statusBody); status != 409 {
		t.Fatal("re-exchange reset sequence")
	}
	if status, _ := request(http.MethodPost, "/qm/v1/auth/pc/exchange", "mobile-installation", nil); status != 403 {
		t.Fatal("role confusion accepted")
	}
	if status, _ := request(http.MethodPost, "/qm/v1/auth/device/exchange", "missing-expiry", nil); status != 503 {
		t.Fatal("guessed missing credential expiry")
	}
	revoked.Store(true)
	if status, _ := request(http.MethodPut, "/qm/v1/device-self/status", phoneToken.AccessToken, statusBody); status != 401 {
		t.Fatal("business token bypassed source revocation")
	}
	if status, _ := request(http.MethodPost, "/qm/v1/auth/device/exchange", "mobile-installation", nil); status != 401 {
		t.Fatal("revoked installation exchanged")
	}
}
