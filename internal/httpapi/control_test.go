package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barry-ran/quick-mirror-service/internal/control"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

type controlAccess struct{}

func (controlAccess) VerifyAccess(_ context.Context, token string) (identity.Principal, error) {
	if token != "test" {
		return identity.Principal{}, identity.ErrInvalidCredential
	}
	return identity.Principal{Role: identity.PC}, nil
}

type controlFake struct {
	calls int
	last  string
	proof string
}

func (f *controlFake) value(name string) control.Intent {
	f.calls++
	f.last = name
	return control.Intent{ID: "11111111-1111-4111-8111-111111111111", Generation: "1", Revision: "1", State: "reserving", Outcome: "pending"}
}
func (f *controlFake) Create(context.Context, identity.Principal, string, string) (control.Intent, bool, error) {
	return f.value("create"), true, nil
}
func (f *controlFake) Get(context.Context, identity.Principal, string) (control.Intent, error) {
	return f.value("get"), nil
}
func (f *controlFake) ByCommand(context.Context, identity.Principal, string) (control.Intent, error) {
	return f.value("by-command"), nil
}
func (f *controlFake) Current(context.Context, identity.Principal) (*control.Intent, error) {
	f.value("current")
	return nil, nil
}
func (f *controlFake) Close(context.Context, identity.Principal, string, string, string) (control.Intent, error) {
	i := f.value("close")
	i.State = "draining"
	return i, nil
}
func (f *controlFake) Bind(_ context.Context, _ identity.Principal, _, _, _, _, _, proof string) (control.Intent, error) {
	f.proof = proof
	return f.value("bind"), nil
}
func (f *controlFake) Drained(_ context.Context, _ identity.Principal, _, _, _, _, _, _, proof string) (control.Intent, error) {
	f.proof = proof
	i := f.value("drained")
	i.State = "released"
	return i, nil
}
func TestControlHTTPRoutesAndProofRedaction(t *testing.T) {
	f := &controlFake{}
	h, e := NewControlHandler(controlAccess{}, f, 2)
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		method, path, body, action string
		status                     int
	}{
		{"POST", "/qm/v1/session-intents", `{"command_id":"key","device_uuid":"target"}`, "create", 201},
		{"GET", "/qm/v1/session-intents/id", "", "get", 200},
		{"GET", "/qm/v1/session-intents/by-command/key", "", "by-command", 200},
		{"GET", "/qm/v1/device-self/session-intents/current", "", "current", 204},
		{"POST", "/qm/v1/session-intents/id/close", `{"command_id":"key","reason":"user_pc"}`, "close", 202},
		{"POST", "/qm/v1/device-self/session-intents/id/bind", `{"command_id":"key","business_generation":"1","session_id":"s","boot_id":"b","runtime_proof":"secret-proof"}`, "bind", 200},
		{"POST", "/qm/v1/device-self/session-intents/id/drained", `{"command_id":"key","business_generation":"1","drain_token":"d","boot_id":"b","runtime_proof":"secret-proof"}`, "drained", 200},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		r.Header.Set("Authorization", "Bearer test")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.status || f.last != c.action {
			t.Fatalf("%s status=%d body=%s", c.path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "secret-proof") || strings.Contains(w.Body.String(), "runtime_proof") {
			t.Fatal("secret echoed")
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing no-store")
		}
		if c.status == 204 && w.Body.Len() != 0 {
			t.Fatal("204 has body")
		}
	}
	if f.proof != "secret-proof" {
		t.Fatal("proof not passed to domain")
	}
}
func TestControlHTTPStrictBoundary(t *testing.T) {
	f := &controlFake{}
	h, _ := NewControlHandler(controlAccess{}, f, 2)
	for _, body := range []string{`{"command_id":"x","command_id":"y"}`, `{"owner_pc_uuid":"forged"}`, `{} {}`, `{"runtime_proof":"leak"}`, strings.Repeat("x", 17000)} {
		r := httptest.NewRequest("POST", "/qm/v1/session-intents", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer test")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 && w.Code != 413 {
			t.Fatalf("status=%d", w.Code)
		}
		var data map[string]any
		if json.Unmarshal(w.Body.Bytes(), &data) != nil {
			t.Fatal("invalid error json")
		}
	}
	if f.calls != 0 {
		t.Fatal("invalid JSON reached store")
	}
	r := httptest.NewRequest(http.MethodGet, "/qm/v1/session-intents/id", nil)
	r.Header.Set("Authorization", "Bearer bad")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("invalid token accepted")
	}
	r = httptest.NewRequest("POST", "/qm/v1/session-intents", strings.NewReader(`{"relay_mode":"custom"}`))
	r.Header.Set("Authorization", "Bearer test")
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "RELAY_CONFIG_UNSUPPORTED") {
		t.Fatal("custom silently fell back")
	}
}
