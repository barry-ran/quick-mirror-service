//go:build peerloom_release_integration

package peerloom

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

// 只对显式启动的、全新隔离租户的正式服务端包执行，不查询 Peerloom 私表。
// 环境未准备时跳过；编译/跳过绝不等于正式包实际联调通过。
func TestReleasedPeerloomCredentialLifecycle(t *testing.T) {
	if os.Getenv("QM_PEERLOOM_RELEASE_TEST_ISOLATED") != "1" {
		t.Skip("isolated released-server fixture required")
	}
	target, err := url.Parse(os.Getenv("QM_PEERLOOM_RELEASE_TEST_URL"))
	if err != nil || target.Scheme != "http" || target.Hostname() != "127.0.0.1" || target.Port() == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" {
		t.Fatal("fixture must use a fixed loopback HTTP origin")
	}
	keyPath := os.Getenv("QM_PEERLOOM_RELEASE_TEST_KEY_FILE")
	info, err := os.Lstat(keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("private fixture service key file required")
	}
	rawKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal("cannot read fixture key")
	}
	serviceKey := strings.TrimSpace(string(rawKey))
	if !visibleASCII(serviceKey, 1, 512) {
		t.Fatal("invalid fixture key format")
	}
	tenant, valid := identity.NormalizeUUID(os.Getenv("QM_PEERLOOM_RELEASE_TEST_TENANT"))
	if !valid {
		t.Fatal("fixture tenant required")
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	proxy.Transport = transport
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	server := httptest.NewTLSServer(proxy)
	defer server.Close()
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	request := func(path, token string, body any, want int, output any) {
		t.Helper()
		var data []byte
		var err error
		if body != nil {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal("test request encoding failed")
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal("test request creation failed")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		var key [16]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal("test idempotency randomness unavailable")
		}
		req.Header.Set("Idempotency-Key", hex.EncodeToString(key[:]))
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal("public fixture API request failed")
		}
		defer response.Body.Close()
		data, err = io.ReadAll(io.LimitReader(response.Body, maxIdentityResponse+1))
		if err != nil || len(data) > maxIdentityResponse {
			t.Fatal("invalid fixture response size")
		}
		if response.StatusCode != want {
			t.Fatalf("public fixture API %s status=%d want=%d", path, response.StatusCode, want)
		}
		if output != nil && json.Unmarshal(data, output) != nil {
			t.Fatal("invalid public response JSON")
		}
	}
	type application struct {
		ID     string `json:"id"`
		Tenant string `json:"tenant_id"`
	}
	var pc, mobile application
	request("/v1/applications", serviceKey, map[string]any{"name": "QuickMirror PC release fixture"}, 201, &pc)
	request("/v1/applications", serviceKey, map[string]any{"name": "QuickMirror mobile release fixture"}, 201, &mobile)
	if pc.Tenant != tenant || mobile.Tenant != tenant {
		t.Fatal("fixture returned foreign tenant")
	}
	cfg := IdentityConfig{Origin: server.URL, TenantID: tenant, PCApplicationID: pc.ID, MobileApplicationID: mobile.ID}
	adapter, err := NewIdentityClient(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := NewRegistrationClient(cfg, serviceKey, client)
	if err != nil {
		t.Fatal("registration adapter configuration failed")
	}
	type credential struct {
		DeviceID   string    `json:"device_id"`
		Credential string    `json:"device_credential"`
		ExpiresAt  time.Time `json:"expires_at"`
	}
	register := func(role identity.Role, app string) credential {
		t.Helper()
		var key [16]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		grant, err := grants.Issue(ctx, role, hex.EncodeToString(key[:]), 300)
		if err != nil {
			t.Fatalf("grant adapter failed: %v", err)
		}
		var result credential
		request("/v1/device-registrations", "", map[string]any{"application_id": app, "platform": "linux", "installation_public_key": "isolated-release-fixture-" + hex.EncodeToString(key[:]), "registration_grant": grant.Grant}, 201, &result)
		return result
	}
	old := register(identity.PC, pc.ID)
	phone := register(identity.Mobile, mobile.ID)
	before, err := adapter.VerifyCredential(ctx, old.Credential)
	if err != nil {
		t.Fatalf("initial adapter failed: %v", err)
	}
	if before.Principal.DeviceID != old.DeviceID || before.Principal.Role != identity.PC || !before.ExpiresAt.Equal(old.ExpiresAt) {
		t.Fatal("initial identity/expiry mismatch")
	}
	phoneIdentity, err := adapter.VerifyCredential(ctx, phone.Credential)
	if err != nil || phoneIdentity.Principal.Role != identity.Mobile {
		t.Fatal("mobile application mapping failed")
	}
	var fresh credential
	request("/v1/device-credentials/refresh", old.Credential, map[string]any{}, 200, &fresh)
	overlap, err := adapter.VerifyCredential(ctx, old.Credential)
	if err != nil {
		t.Fatalf("overlap credential failed: %v", err)
	}
	renewed, err := adapter.VerifyCredential(ctx, fresh.Credential)
	if err != nil {
		t.Fatalf("refreshed credential failed: %v", err)
	}
	if before.Principal != overlap.Principal || before.Principal != renewed.Principal || !overlap.ExpiresAt.Before(before.ExpiresAt) || !overlap.ExpiresAt.Before(renewed.ExpiresAt) || !renewed.ExpiresAt.Equal(fresh.ExpiresAt) {
		t.Fatal("credential-specific refresh overlap mismatch")
	}
	foreign := cfg
	foreign.TenantID = "11111111-1111-4111-8111-111111111111"
	if foreign.TenantID == tenant {
		foreign.TenantID = "22222222-2222-4222-8222-222222222222"
	}
	foreignAdapter, err := NewIdentityClient(foreign, client)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := foreignAdapter.VerifyCredential(ctx, fresh.Credential); !errors.Is(err, identity.ErrForbidden) || result.Principal != (identity.Principal{}) {
		t.Fatal("cross-tenant adapter accepted credential")
	}
	request("/v1/devices/"+old.DeviceID+"/revoke", serviceKey, nil, 200, nil)
	for _, token := range []string{old.Credential, fresh.Credential} {
		result, err := adapter.VerifyCredential(ctx, token)
		if !errors.Is(err, identity.ErrInvalidCredential) || result.Principal != (identity.Principal{}) || !result.ExpiresAt.IsZero() {
			t.Fatal("revoked credential accepted or identity leaked")
		}
	}
	if _, err := adapter.VerifyCredential(ctx, phone.Credential); err != nil {
		t.Fatal("PC revocation affected unrelated mobile credential")
	}
	t.Log("released public HTTP: two roles, grant registration, exact expiry, refresh overlap, tenant isolation and revocation passed")
}
