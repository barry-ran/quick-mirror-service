package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/access"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

type exchangeFunc func(context.Context, identity.Role, string) (access.Token, identity.Principal, error)

func (f exchangeFunc) ExchangeVerified(c context.Context, r identity.Role, s string) (access.Token, identity.Principal, error) {
	return f(c, r, s)
}

type ensureFunc func(context.Context, identity.Principal) error

func (f ensureFunc) EnsureRegistration(c context.Context, p identity.Principal) error { return f(c, p) }

func TestExchangeRoleAndRegistrationBoundary(t *testing.T) {
	for _, role := range []identity.Role{identity.PC, identity.Mobile} {
		t.Run(string(role), func(t *testing.T) {
			expected := identity.Principal{DeviceID: mobile, TenantID: scope, ApplicationID: pc, Role: role}
			var issued, registered atomic.Int32
			h, err := NewExchangeHandler(exchangeFunc(func(ctx context.Context, r identity.Role, credential string) (access.Token, identity.Principal, error) {
				issued.Add(1)
				if r != role || credential != "installation-fixture" {
					t.Error("wrong authenticated request")
				}
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 10*time.Second {
					t.Error("missing bounded context")
				}
				return access.Token{AccessToken: "opaque-business-fixture", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Scope: scope}, expected, nil
			}), ensureFunc(func(ctx context.Context, p identity.Principal) error {
				registered.Add(1)
				if p != expected {
					t.Error("registration did not use verified subject")
				}
				return nil
			}), 2)
			if err != nil {
				t.Fatal(err)
			}
			path := "/qm/v1/auth/pc/exchange"
			if role == identity.Mobile {
				path = "/qm/v1/auth/device/exchange"
			}
			server := httptest.NewTLSServer(h)
			defer server.Close()
			req, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer installation-fixture")
			req.Header.Set("Content-Type", "application/json")
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var result struct {
				RequestID string                     `json:"request_id"`
				Data      map[string]json.RawMessage `json:"data"`
			}
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" || result.RequestID == "" || len(result.Data) != 3 || result.Data["access_token"] == nil || result.Data["expires_at"] == nil || result.Data["scope"] == nil {
				t.Fatal("wrong response boundary")
			}
			if issued.Load() != 1 || (role == identity.Mobile && registered.Load() != 1) || (role == identity.PC && registered.Load() != 0) {
				t.Fatal("unexpected issuance/registration count")
			}
		})
	}
}

func TestExchangeRejectsInputBeforeIssuance(t *testing.T) {
	var calls atomic.Int32
	h, err := NewExchangeHandler(exchangeFunc(func(context.Context, identity.Role, string) (access.Token, identity.Principal, error) {
		calls.Add(1)
		return access.Token{}, identity.Principal{}, nil
	}), ensureFunc(func(context.Context, identity.Principal) error { t.Fatal("unexpected registration"); return nil }), 1)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, method, path, body, contentType, authorization string
		duplicate                                            bool
		status                                               int
	}{
		{"path", "POST", "/qm/v1/auth/unknown/exchange", "", "", "Bearer fixture", false, 404},
		{"method", "GET", "/qm/v1/auth/pc/exchange", "", "", "Bearer fixture", false, 405},
		{"query", "POST", "/qm/v1/auth/pc/exchange?role=pc", "", "", "Bearer fixture", false, 400},
		{"empty query", "POST", "/qm/v1/auth/pc/exchange?", "", "", "Bearer fixture", false, 400},
		{"missing auth", "POST", "/qm/v1/auth/pc/exchange", "", "", "", false, 401},
		{"double auth", "POST", "/qm/v1/auth/pc/exchange", "", "", "Bearer fixture", true, 401},
		{"space auth", "POST", "/qm/v1/auth/pc/exchange", "", "", "Bearer has space", false, 401},
		{"scheme", "POST", "/qm/v1/auth/pc/exchange", "", "", "Basic fixture", false, 401},
		{"long auth", "POST", "/qm/v1/auth/pc/exchange", "", "", "Bearer " + strings.Repeat("a", 513), false, 401},
		{"content type", "POST", "/qm/v1/auth/pc/exchange", "{}", "text/plain", "Bearer fixture", false, 415},
		{"client expiry", "POST", "/qm/v1/auth/pc/exchange", `{"expires_at":"2099-01-01T00:00:00Z"}`, "application/json", "Bearer fixture", false, 400},
		{"client subject", "POST", "/qm/v1/auth/pc/exchange", `{"device_uuid":"fake"}`, "application/json", "Bearer fixture", false, 400},
		{"array", "POST", "/qm/v1/auth/pc/exchange", "[]", "application/json", "Bearer fixture", false, 400},
		{"trailing", "POST", "/qm/v1/auth/pc/exchange", "{}{}", "application/json", "Bearer fixture", false, 400},
		{"oversized", "POST", "/qm/v1/auth/pc/exchange", strings.Repeat(" ", (1<<20)+1), "application/json", "Bearer fixture", false, 413},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.authorization != "" {
				r.Header.Set("Authorization", tc.authorization)
			}
			if tc.duplicate {
				r.Header.Add("Authorization", "Bearer other")
			}
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached issuer")
	}
}

func TestExchangeErrorsDoNotExposeIssuedTokenOrSource(t *testing.T) {
	for _, tc := range []struct {
		name            string
		issue, register error
		wrongRole       bool
		status          int
	}{
		{"revoked", identity.ErrInvalidCredential, nil, false, 401},
		{"forbidden", identity.ErrForbidden, nil, false, 403},
		{"upstream", errors.New("installation-secret"), nil, false, 503},
		{"registry", nil, errors.New("database-secret"), false, 503},
		{"registry forbidden", nil, identity.ErrForbidden, false, 403},
		{"wrong mapped role", nil, nil, true, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var registered atomic.Int32
			h, err := NewExchangeHandler(exchangeFunc(func(context.Context, identity.Role, string) (access.Token, identity.Principal, error) {
				role := identity.Mobile
				if tc.wrongRole {
					role = identity.PC
				}
				return access.Token{AccessToken: "issued-secret"}, identity.Principal{Role: role}, tc.issue
			}), ensureFunc(func(context.Context, identity.Principal) error { registered.Add(1); return tc.register }), 1)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/qm/v1/auth/device/exchange", nil)
			r.Header.Set("Authorization", "Bearer installation-secret")
			r.Header.Set("Accept-Language", "zh-CN")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || strings.Contains(w.Body.String(), "secret") || !strings.Contains(w.Body.String(), "请求未能完成") {
				t.Fatalf("unsafe error response status=%d", w.Code)
			}
			if (tc.issue != nil || tc.wrongRole) && registered.Load() != 0 {
				t.Fatal("unauthorized identity registered")
			}
		})
	}
}

func TestExchangeResourceBudgetIsBounded(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h, err := NewExchangeHandler(exchangeFunc(func(ctx context.Context, role identity.Role, _ string) (access.Token, identity.Principal, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return access.Token{}, identity.Principal{}, identity.ErrUnavailable
	}), ensureFunc(func(context.Context, identity.Principal) error { return nil }), 1)
	if err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/qm/v1/auth/pc/exchange", nil)
		r.Header.Set("Authorization", "Bearer fixture")
		return r
	}
	go func() { defer close(done); h.ServeHTTP(httptest.NewRecorder(), request()) }()
	defer close(release)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("issuer not entered")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request())
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("unbounded exchange concurrency")
	}
	// release is closed by defer; do not block worker lifetime beyond this test.
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("issuer did not exit")
		}
	})
}
