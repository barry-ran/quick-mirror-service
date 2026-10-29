package peerloom

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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
