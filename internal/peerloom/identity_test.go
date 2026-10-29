package peerloom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

const (
	tenantID = "11111111-1111-4111-8111-111111111111"
	pcID     = "22222222-2222-4222-8222-222222222222"
	mobileID = "33333333-3333-4333-8333-333333333333"
	deviceID = "abcdefab-1234-4567-8901-abcdefabcdef"
)

func config(origin string) IdentityConfig {
	return IdentityConfig{Origin: origin, TenantID: tenantID, PCApplicationID: pcID, MobileApplicationID: mobileID}
}

func payload(application, tenant string) string {
	return fmt.Sprintf(`{"device_id":%q,"application_id":%q,"tenant_id":%q,"platform":"android","metadata":{"role":"mobile"}}`, strings.ToUpper(deviceID), application, tenant)
}

func TestVerifyIdentity(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		wantRole  identity.Role
		wantError error
	}{
		{"pc ignores spoofed metadata", 200, payload(pcID, tenantID), identity.PC, nil},
		{"mobile", 200, payload(mobileID, tenantID), identity.Mobile, nil},
		{"foreign tenant", 200, payload(pcID, deviceID), "", identity.ErrForbidden},
		{"foreign application", 200, payload(deviceID, tenantID), "", identity.ErrForbidden},
		{"missing fields", 200, `{}`, "", identity.ErrUnavailable},
		{"invalid uuid", 200, payload("not-an-id", tenantID), "", identity.ErrUnavailable},
		{"malformed", 200, `{`, "", identity.ErrUnavailable},
		{"trailing object", 200, payload(pcID, tenantID) + `{}`, "", identity.ErrUnavailable},
		{"oversize", 200, strings.Repeat(" ", maxIdentityResponse+1), "", identity.ErrUnavailable},
		{"revoked", 401, `secret database error`, "", identity.ErrInvalidCredential},
		{"forbidden", 403, `secret`, "", identity.ErrForbidden},
		{"busy", 429, `secret`, "", identity.ErrUnavailable},
		{"failure", 500, `secret`, "", identity.ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/device-self" || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer dev_test" {
					t.Errorf("incorrect public API request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			client, err := NewIdentityClient(config(server.URL), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.Verify(context.Background(), "dev_test")
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("error = %v, want %v", err, tc.wantError)
			}
			if tc.wantError == nil && (got.Role != tc.wantRole || got.DeviceID != deviceID) {
				t.Fatalf("principal = %+v", got)
			}
			if tc.wantError != nil && got != (identity.Principal{}) {
				t.Fatal("failure returned a principal")
			}
			verified, credentialErr := client.VerifyCredential(context.Background(), "dev_test")
			expectedError := tc.wantError
			if expectedError == nil {
				expectedError = identity.ErrUnavailable
			} // 旧响应没有可信期限。
			if !errors.Is(credentialErr, expectedError) || verified.Principal != (identity.Principal{}) || !verified.ExpiresAt.IsZero() {
				t.Fatalf("strict credential verifier did not fail closed: %+v %v", verified, credentialErr)
			}

		})
	}
}

func TestRejectRedirectAndInvalidCredential(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Location", "/leak")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	client, err := NewIdentityClient(config(server.URL), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"", "token\nHeader: leak", "has space", strings.Repeat("x", 513), "非ASCII"} {
		if _, err := client.Verify(context.Background(), credential); !errors.Is(err, identity.ErrInvalidCredential) {
			t.Fatalf("invalid credential accepted: %v", err)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("sent invalid credentials upstream")
	}
	if _, err := client.Verify(context.Background(), "dev_test"); !errors.Is(err, identity.ErrUnavailable) {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("followed redirect with credential")
	}
}

func TestConfigurationAndCancellation(t *testing.T) {
	for _, origin := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?x=y", "https://example.com?", "https://example.com#x", "https://"} {
		if _, err := NewIdentityClient(config(origin), nil); err == nil {
			t.Fatalf("accepted %q", origin)
		}
	}
	bad := config("https://example.com")
	bad.MobileApplicationID = pcID
	if _, err := NewIdentityClient(bad, nil); err == nil {
		t.Fatal("accepted ambiguous role mapping")
	}
	client, err := NewIdentityClient(config("https://example.com"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Verify(ctx, "dev_test"); !errors.Is(err, identity.ErrUnavailable) {
		t.Fatal(err)
	}
}

// 公开期限草案的 TLS 契约夹具，不冒充已发布 Peerloom 联调。
func TestVerifyCredentialExpiryContract(t *testing.T) {
	cases := []struct {
		name, expiry string
		valid        bool
	}{
		{"missing", "", false},
		{"null", "null", false},
		{"empty", `""`, false},
		{"numeric", "123", false},
		{"object", `{}`, false},
		{"malformed", `"tomorrow"`, false},
		{"no timezone", `"2026-10-29T11:00:00"`, false},
		{"zero", `"0001-01-01T00:00:00Z"`, false},
		{"seconds", `"2026-10-29T11:00:00Z"`, true},
		{"nanoseconds", `"2026-10-29T11:00:00.123456789Z"`, true},
		{"offset normalized", `"2026-10-29T12:00:00+01:00"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			body := payload(pcID, tenantID)
			if tc.expiry != "" {
				body = strings.TrimSuffix(body, "}") + `,"credential_expires_at":` + tc.expiry + `}`
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Authorization") != "Bearer dev_test" || r.URL.Path != "/v1/device-self" {
					t.Error("wrong authority request")
				}
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			client, err := NewIdentityClient(config(server.URL), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.VerifyCredential(context.Background(), "dev_test")
			if requests.Load() != 1 {
				t.Fatal("identity and expiry must come from one authenticated response")
			}
			if !tc.valid {
				if !errors.Is(err, identity.ErrUnavailable) || got.Principal != (identity.Principal{}) || !got.ExpiresAt.IsZero() {
					t.Fatalf("unsafe result: %+v %v", got, err)
				}
			} else {
				var value string
				if err := json.Unmarshal([]byte(tc.expiry), &value); err != nil {
					t.Fatal(err)
				}
				expected, parseErr := time.Parse(time.RFC3339Nano, value)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				if err != nil || got.Principal.DeviceID != deviceID || got.Principal.Role != identity.PC || !got.ExpiresAt.Equal(expected) || got.ExpiresAt.Location() != time.UTC {
					t.Fatalf("wrong verified credential: %+v %v", got, err)
				}
			}
			// 旧主体查询不要求尚未发布的新字段；期限验证不能退回该宽松入口。
			if _, err := client.Verify(context.Background(), "dev_test"); err != nil {
				t.Fatalf("legacy identity query changed: %v", err)
			}
		})
	}
}

func TestVerifyCredentialRefreshOverlapAndErrors(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		expiry := "2026-10-29T11:00:30Z"
		if r.Header.Get("Authorization") == "Bearer new" {
			expiry = "2026-10-30T11:00:00Z"
		}
		fmt.Fprint(w, strings.TrimSuffix(payload(mobileID, tenantID), "}")+`,"credential_expires_at":"`+expiry+`"}`)
	}))
	defer server.Close()
	client, err := NewIdentityClient(config(server.URL), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	old, err := client.VerifyCredential(context.Background(), "old")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := client.VerifyCredential(context.Background(), "new")
	if err != nil {
		t.Fatal(err)
	}
	if old.Principal != fresh.Principal || !old.ExpiresAt.Before(fresh.ExpiresAt) {
		t.Fatal("credential-specific overlap expiry lost")
	}
	for _, tc := range []struct {
		status int32
		want   error
	}{{401, identity.ErrInvalidCredential}, {403, identity.ErrForbidden}, {500, identity.ErrUnavailable}} {
		status.Store(tc.status)
		got, err := client.VerifyCredential(context.Background(), "old")
		if !errors.Is(err, tc.want) || got.Principal != (identity.Principal{}) || !got.ExpiresAt.IsZero() {
			t.Fatalf("error leaked authenticated identity: %+v %v", got, err)
		}
	}
}
