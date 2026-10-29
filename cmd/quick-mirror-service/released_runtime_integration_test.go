//go:build runtimeintegration

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

	"github.com/barry-ran/quick-mirror-service/internal/access"
)

// 正式包环境不存在时只保留原TLS运行时测试，不声称执行了公开服务联调。
func prepareReleasedRuntime(t *testing.T, c *config) func(*http.Client, string) {
	t.Helper()
	if os.Getenv("QM_PEERLOOM_RELEASE_TEST_ISOLATED") != "1" {
		return nil
	}
	target, err := url.Parse(os.Getenv("QM_PEERLOOM_RELEASE_TEST_URL"))
	if err != nil || target.Scheme != "http" || target.Hostname() != "127.0.0.1" || target.Port() == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" {
		t.Fatal("isolated fixed loopback origin required")
	}
	keyPath := os.Getenv("QM_PEERLOOM_RELEASE_TEST_KEY_FILE")
	info, err := os.Lstat(keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("private fixture key required")
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal("fixture key unreadable")
	}
	serviceKey := strings.TrimSpace(string(raw))
	proxy := httputil.NewSingleHostReverseProxy(target)
	transport := &http.Transport{Proxy: nil}
	proxy.Transport = transport
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	upstream := httptest.NewTLSServer(proxy)
	t.Cleanup(func() { upstream.Close(); transport.CloseIdleConnections() })
	upstreamClient := upstream.Client()
	upstreamClient.Timeout = 5 * time.Second
	upstreamClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.HTTP.Identity.Origin = upstream.URL
	c.HTTP.Identity.TenantID = os.Getenv("QM_PEERLOOM_RELEASE_TEST_TENANT")
	c.ServiceCredential = serviceKey
	c.upstreamClient = upstreamClient
	call := func(client *http.Client, origin, method, path, token string, body any, want int) []byte {
		t.Helper()
		var encoded []byte
		if body != nil {
			var err error
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal("fixture body encoding")
			}
		}
		req, err := http.NewRequest(method, origin+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal("fixture request creation")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			t.Fatal("fixture random")
		}
		req.Header.Set("Idempotency-Key", hex.EncodeToString(random[:]))
		response, err := client.Do(req)
		if err != nil {
			t.Fatal("fixture HTTP unavailable")
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil || len(data) > 65536 {
			t.Fatal("invalid response size")
		}
		if response.StatusCode != want {
			t.Fatalf("%s %s got=%d want=%d", method, path, response.StatusCode, want)
		}
		return data
	}
	type registration struct {
		DeviceID   string    `json:"device_id"`
		Credential string    `json:"device_credential"`
		Expiry     time.Time `json:"expires_at"`
	}
	create := func(name string) (string, registration) {
		t.Helper()
		data := call(upstreamClient, upstream.URL, "POST", "/v1/applications", serviceKey, map[string]any{"name": name}, 201)
		var application struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(data, &application) != nil || application.ID == "" {
			t.Fatal("invalid application response")
		}
		data = call(upstreamClient, upstream.URL, "POST", "/v1/registration-grants", serviceKey, map[string]any{"application_id": application.ID}, 201)
		var grant struct {
			Grant string `json:"grant"`
		}
		if json.Unmarshal(data, &grant) != nil || grant.Grant == "" {
			t.Fatal("invalid grant response")
		}
		data = call(upstreamClient, upstream.URL, "POST", "/v1/device-registrations", "", map[string]any{"application_id": application.ID, "platform": "linux", "installation_public_key": "runtime-test-" + application.ID, "registration_grant": grant.Grant}, 201)
		var device registration
		if json.Unmarshal(data, &device) != nil || device.DeviceID == "" || device.Credential == "" || device.Expiry.IsZero() {
			t.Fatal("invalid registration response")
		}
		return application.ID, device
	}
	pcApp, pc := create("QuickMirror runtime PC")
	mobileApp, mobile := create("QuickMirror runtime mobile")
	c.HTTP.Identity.PCApplicationID = pcApp
	c.HTTP.Identity.MobileApplicationID = mobileApp
	return func(client *http.Client, origin string) {
		issue := func(path string, device registration) access.Token {
			t.Helper()
			data := call(client, origin, "POST", path, device.Credential, map[string]any{}, 200)
			var result struct {
				Data access.Token `json:"data"`
			}
			if json.Unmarshal(data, &result) != nil {
				t.Fatal("invalid exchange response")
			}
			token := result.Data
			if token.AccessToken == "" || token.Scope != c.HTTP.ServiceScope || token.ExpiresAt.After(device.Expiry) || token.ExpiresAt.After(time.Now().Add(15*time.Minute)) || !token.ExpiresAt.After(time.Now()) {
				t.Fatal("exchange principal/TTL invalid")
			}
			return token
		}
		mobileToken := issue("/qm/v1/auth/device/exchange", mobile)
		pcToken := issue("/qm/v1/auth/pc/exchange", pc)
		data := call(client, origin, "POST", "/qm/v1/devices/resolve", pcToken.AccessToken, map[string]any{"uuids": []string{mobile.DeviceID}}, 200)
		var resolved struct {
			Data struct {
				Items []struct {
					Found bool `json:"found"`
				} `json:"items"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &resolved) != nil || len(resolved.Data.Items) != 1 || !resolved.Data.Items[0].Found {
			t.Fatal("mobile exchange did not register catalog")
		}
		status := map[string]any{"boot_id": "55555555-5555-4555-8555-555555555555", "seq": 7, "app_version": "runtime-fixture", "permissions": map[string]any{"projection": true}}
		call(client, origin, "PUT", "/qm/v1/device-self/status", mobileToken.AccessToken, status, 200)
		issue("/qm/v1/auth/device/exchange", mobile)
		call(client, origin, "PUT", "/qm/v1/device-self/status", mobileToken.AccessToken, status, 409)
		call(client, origin, "POST", "/qm/v1/auth/pc/exchange", mobile.Credential, map[string]any{}, 403)
		call(upstreamClient, upstream.URL, "POST", "/v1/devices/"+mobile.DeviceID+"/revoke", serviceKey, nil, 200)
		call(client, origin, "PUT", "/qm/v1/device-self/status", mobileToken.AccessToken, status, 401)
		call(client, origin, "POST", "/qm/v1/auth/device/exchange", mobile.Credential, map[string]any{}, 401)
		call(client, origin, "POST", "/qm/v1/devices/resolve", pcToken.AccessToken, map[string]any{"uuids": []string{mobile.DeviceID}}, 200)
		t.Log("formal Peerloom + verified-TLS PostgreSQL + HTTPS runtime: exchange/TTL/catalog/status/re-exchange/role/source-revocation passed")
	}
}
