package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/bootstrap"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/barry-ran/quick-mirror-service/internal/peerloom"
)

const scope = "11111111-1111-4111-8111-111111111111"
const pc = "22222222-2222-4222-8222-222222222222"
const mobile = "33333333-3333-4333-8333-333333333333"
const body = `{"install_public_label":"设备","idempotency_key":"44444444-4444-4444-8444-444444444444"}`

type issuerFunc func(context.Context, bootstrap.Request) (peerloom.RegistrationGrant, error)

func (f issuerFunc) Issue(c context.Context, r bootstrap.Request) (peerloom.RegistrationGrant, error) {
	return f(c, r)
}
func settings() BootstrapConfig {
	return BootstrapConfig{Identity: peerloom.IdentityConfig{Origin: "https://peerloom.example", TenantID: scope, PCApplicationID: pc, MobileApplicationID: mobile}, ServiceScope: scope, MaxConcurrent: 2, Burst: 100, RequestsPerSecond: 100}
}
func grant() peerloom.RegistrationGrant {
	return peerloom.RegistrationGrant{ID: scope, Grant: "reg_fixture", ExpiresAt: time.Now().Add(time.Minute)}
}

func TestBootstrapTLSResponse(t *testing.T) {
	for _, role := range []identity.Role{identity.PC, identity.Mobile} {
		h, err := NewBootstrapHandler(settings(), issuerFunc(func(ctx context.Context, r bootstrap.Request) (peerloom.RegistrationGrant, error) {
			if r.Role != role || r.Label != "设备" {
				t.Error("role or body changed")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Error("missing operation deadline")
			}
			return grant(), nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewTLSServer(h)
		response, err := server.Client().Post(server.URL+"/qm/v1/bootstrap/"+string(role), "application/json", strings.NewReader(body))
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		server.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("invalid success headers")
		}
		var decoded struct {
			RequestID string `json:"request_id"`
			Data      struct {
				Grant       string `json:"registration_grant"`
				Application string `json:"application_id"`
				Scope       string `json:"service_scope"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &decoded) != nil {
			t.Fatal("invalid JSON")
		}
		want := pc
		if role == identity.Mobile {
			want = mobile
		}
		if _, ok := identity.NormalizeUUID(decoded.RequestID); !ok || decoded.Data.Grant != "reg_fixture" || decoded.Data.Application != want || decoded.Data.Scope != scope {
			t.Fatal("invalid response contract")
		}
	}
}

func TestBootstrapRejectsMalformedRequests(t *testing.T) {
	cases := []struct {
		name, method, path, content, body string
		status                            int
	}{
		{"unknown route", "POST", "/other", "application/json", body, 404},
		{"wrong method", "GET", "/qm/v1/bootstrap/pc", "application/json", body, 405},
		{"wrong content", "POST", "/qm/v1/bootstrap/pc", "text/plain", body, 415},
		{"query", "POST", "/qm/v1/bootstrap/pc?role=mobile", "application/json", body, 400},
		{"null", "POST", "/qm/v1/bootstrap/pc", "application/json", "null", 400},
		{"unknown field", "POST", "/qm/v1/bootstrap/pc", "application/json", strings.Replace(body, "设备", "设备", 1)[:len(body)-1] + `,"role":"mobile"}`, 400},
		{"duplicate", "POST", "/qm/v1/bootstrap/pc", "application/json", body[:len(body)-1] + `,"idempotency_key":"44444444-4444-4444-8444-444444444444"}`, 400},
		{"trailing", "POST", "/qm/v1/bootstrap/pc", "application/json", body + `{}`, 400},
		{"invalid utf8", "POST", "/qm/v1/bootstrap/pc", "application/json", strings.Replace(body, "设备", string([]byte{0xff}), 1), 400},
		{"large", "POST", "/qm/v1/bootstrap/pc", "application/json", strings.Repeat(" ", (1<<20)+1), 413},
		{"missing key", "POST", "/qm/v1/bootstrap/pc", "application/json", `{}`, 400},
		{"null label", "POST", "/qm/v1/bootstrap/pc", "application/json", strings.Replace(body, `"设备"`, `null`, 1), 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := NewBootstrapHandler(settings(), issuerFunc(func(context.Context, bootstrap.Request) (peerloom.RegistrationGrant, error) {
				t.Error("invalid request reached issuer")
				return grant(), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.content)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
		})
	}
}

func TestBootstrapFailureMapping(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
		retry  bool
	}{{peerloom.ErrIdempotencyConflict, 409, "IDEMPOTENCY_CONFLICT", false}, {peerloom.ErrReplayExpired, 409, "REPLAY_EXPIRED", false}, {peerloom.ErrOutcomeUnknown, 503, "OUTCOME_UNKNOWN", false}, {errors.New("private token secret"), 503, "SERVICE_UNAVAILABLE", true}} {
		h, err := NewBootstrapHandler(settings(), issuerFunc(func(context.Context, bootstrap.Request) (peerloom.RegistrationGrant, error) {
			return peerloom.RegistrationGrant{}, tc.err
		}))
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/qm/v1/bootstrap/pc", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept-Language", "zh-CN")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var result struct {
			Error struct {
				Code, Message string
				Retryable     bool
			} `json:"error"`
		}
		if json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatal("bad failure JSON")
		}
		if w.Code != tc.status || result.Error.Code != tc.code || result.Error.Retryable != tc.retry || !strings.Contains(result.Error.Message, "请求") || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("bad failure response: %s", w.Body.String())
		}
	}
}

func TestBootstrapResourceGates(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	config := settings()
	config.MaxConcurrent = 1
	h, err := NewBootstrapHandler(config, issuerFunc(func(context.Context, bootstrap.Request) (peerloom.RegistrationGrant, error) {
		calls.Add(1)
		close(entered)
		<-release
		return grant(), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		r := httptest.NewRequest("POST", "/qm/v1/bootstrap/pc", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(httptest.NewRecorder(), request()) }()
	<-entered
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request())
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" {
		t.Error("concurrency not bounded")
	}
	close(release)
	<-done
	if calls.Load() != 1 {
		t.Fatal("excess concurrent issuer")
	}
	config = settings()
	config.Burst = 1
	config.RequestsPerSecond = .0001
	h, err = NewBootstrapHandler(config, issuerFunc(func(context.Context, bootstrap.Request) (peerloom.RegistrationGrant, error) { return grant(), nil }))
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(httptest.NewRecorder(), request())
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request())
	if w.Code != 429 {
		t.Fatal("rate not bounded")
	}
	for _, rate := range []float64{math.NaN(), math.Inf(1), 0, -1} {
		config.RequestsPerSecond = rate
		if _, err := NewBootstrapHandler(config, issuerFunc(func(context.Context, bootstrap.Request) (peerloom.RegistrationGrant, error) { return grant(), nil })); err == nil {
			t.Fatal("invalid rate accepted")
		}
	}
}
