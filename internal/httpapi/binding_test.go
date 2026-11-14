package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barry-ran/quick-mirror-service/internal/binding"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/barry-ran/quick-mirror-service/internal/peerloom"
)

type bindingFixture struct {
	bindCalls int
	fail      bool
}

func (f *bindingFixture) Ensure(context.Context, identity.Principal) (binding.Code, error) {
	return binding.Code{Code: "000123"}, nil
}
func (f *bindingFixture) SelfCode(context.Context, identity.Principal) (binding.Code, error) {
	return binding.Code{Code: "000123"}, nil
}
func (f *bindingFixture) Refresh(context.Context, identity.Principal, string) (binding.Code, error) {
	return binding.Code{Code: "000456"}, nil
}
func (f *bindingFixture) Bind(_ context.Context, _ identity.Principal, code, key string) (binding.Relation, error) {
	f.bindCalls++
	if code != "000123" {
		return binding.Relation{}, binding.ErrCodeInvalid
	}
	return binding.Relation{ID: scope, Revision: "1", PCID: scope, MobileID: mobile, Active: true}, nil
}
func (f *bindingFixture) List(context.Context, identity.Principal, string, int) (binding.Page, error) {
	if f.fail {
		return binding.Page{}, errors.New("db unavailable")
	}
	return binding.Page{Items: []binding.Relation{{ID: scope, Revision: "1", PCID: scope, MobileID: mobile, Active: true}}}, nil
}
func (f *bindingFixture) Unbind(context.Context, identity.Principal, string, string, string) (binding.Relation, error) {
	return binding.Relation{ID: scope, Revision: "2", Active: false, ClosePending: true}, nil
}

type bindingRegistry struct{ calls int }

func (r *bindingRegistry) EnsureRegistration(context.Context, identity.Principal) error {
	r.calls++
	return nil
}

type unknownPresence struct{}

func (unknownPresence) GetDevice(context.Context, string) (peerloom.ControlDevice, error) {
	return peerloom.ControlDevice{}, identity.ErrUnavailable
}
func TestBindingBatchAuthenticatesOnceAndKeepsPartialResults(t *testing.T) {
	f := &bindingFixture{}
	authCalls := 0
	verifier := accessFunc(func(context.Context, string) (identity.Principal, error) {
		authCalls++
		return identity.Principal{Role: identity.PC, DeviceID: scope}, nil
	})
	h, e := NewBindingHandler(verifier, f, &bindingRegistry{}, unknownPresence{}, scope, 2)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "/qm/v1/bindings/batch", strings.NewReader(`{"items":[{"client_item_id":"1","code":"000123","operation_key":"a"},{"client_item_id":"2","code":"999999","operation_key":"b"}]}`))
	r.Header.Set("Authorization", "Bearer fixture")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || authCalls != 1 || f.bindCalls != 2 || !strings.Contains(w.Body.String(), "CODE_INVALID") || !strings.Contains(w.Body.String(), `"binding"`) {
		t.Fatalf("unexpected partial batch: %d %s", w.Code, w.Body.String())
	}
	f.bindCalls = 0
	h.verifier = accessFunc(func(context.Context, string) (identity.Principal, error) {
		return identity.Principal{}, identity.ErrInvalidCredential
	})
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/qm/v1/bindings/batch", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer fixture")
	h.ServeHTTP(w, r)
	if w.Code != 401 || f.bindCalls != 0 {
		t.Fatal("unauthenticated batch executed")
	}
}
func TestBindingsUnknownPresenceDoesNotBecomeOfflineOrEmpty(t *testing.T) {
	f := &bindingFixture{}
	h, e := NewBindingHandler(fixtureAccess(identity.PC), f, &bindingRegistry{}, unknownPresence{}, scope, 2)
	if e != nil {
		t.Fatal(e)
	}
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/qm/v1/bindings", nil)
		r.Header.Set("Authorization", "Bearer fixture")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := call()
	var result struct {
		Data struct {
			Items []struct {
				Peer struct {
					Online *bool `json:"online"`
				} `json:"peer"`
			} `json:"items"`
		} `json:"data"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Data.Items) != 1 || result.Data.Items[0].Peer.Online != nil {
		t.Fatalf("unknown discarded bindings: %s", w.Body.String())
	}
	f.fail = true
	w = call()
	if w.Code != 503 || strings.Contains(w.Body.String(), `"items"`) {
		t.Fatal("database failure fabricated empty list")
	}
}
func TestEnsureDoesNotRegisterPCAsMobile(t *testing.T) {
	for _, role := range []identity.Role{identity.PC, identity.Mobile} {
		t.Run(string(role), func(t *testing.T) {
			reg := &bindingRegistry{}
			h, e := NewBindingHandler(fixtureAccess(role), &bindingFixture{}, reg, unknownPresence{}, scope, 2)
			if e != nil {
				t.Fatal(e)
			}
			r := httptest.NewRequest("POST", "/qm/v1/installations/self/ensure", strings.NewReader(`{}`))
			r.Header.Set("Authorization", "Bearer fixture")
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"service_scope"`) {
				t.Fatalf("ensure: %s", w.Body.String())
			}
			want := 0
			if role == identity.Mobile {
				want = 1
			}
			if reg.calls != want {
				t.Fatal("wrong catalog initialization")
			}
		})
	}
}

func TestBindingEnvelopeRequestIDIsCanonicalUUIDv4(t *testing.T) {
	seen := make(map[string]bool)
	for _, tc := range []struct {
		name, method, path string
		authenticated      bool
		status             int
	}{
		{"ensure", "POST", "/qm/v1/installations/self/ensure", true, 200},
		{"binding-code", "GET", "/qm/v1/binding-code/self", true, 200},
		{"bindings", "GET", "/qm/v1/bindings", true, 200},
		{"unauthorized", "POST", "/qm/v1/installations/self/ensure", false, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := NewBindingHandler(fixtureAccess(identity.PC), &bindingFixture{}, &bindingRegistry{}, unknownPresence{}, scope, 2)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
			r.Header.Set("Content-Type", "application/json")
			if tc.authenticated {
				r.Header.Set("Authorization", "Bearer fixture")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status: got %d want %d", w.Code, tc.status)
			}
			var envelope struct {
				RequestID string          `json:"request_id"`
				Data      json.RawMessage `json:"data"`
				Error     json.RawMessage `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			id, valid := identity.NormalizeUUID(envelope.RequestID)
			if !valid || id != envelope.RequestID || len(id) != 36 {
				t.Fatalf("noncanonical request_id: %q", envelope.RequestID)
			}
			if id[14] != '4' || !strings.ContainsRune("89ab", rune(id[19])) {
				t.Fatalf("not UUIDv4 with RFC variant: %q", id)
			}
			if seen[id] {
				t.Fatal("request_id reused across responses")
			}
			seen[id] = true
			if tc.status == 200 && len(envelope.Data) == 0 || tc.status == 401 && len(envelope.Error) == 0 {
				t.Fatal("missing expected envelope payload")
			}
		})
	}
}
