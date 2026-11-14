package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

type accessFunc func(context.Context, string) (identity.Principal, error)

func (f accessFunc) Verify(c context.Context, s string) (identity.Principal, error) {
	return f(c, s)
}

type catalogFixture struct {
	resolve func(context.Context, identity.Principal, []string) ([]catalog.Resolution, error)
	update  func(context.Context, identity.Principal, catalog.Status) error
}

func (f catalogFixture) ResolveBatch(c context.Context, p identity.Principal, s []string) ([]catalog.Resolution, error) {
	if f.resolve == nil {
		return nil, errors.New("unexpected resolve")
	}
	return f.resolve(c, p, s)
}
func (f catalogFixture) UpdateStatus(c context.Context, p identity.Principal, s catalog.Status) error {
	if f.update == nil {
		return errors.New("unexpected status")
	}
	return f.update(c, p, s)
}

func fixtureAccess(role identity.Role) identity.Verifier {
	return accessFunc(func(ctx context.Context, token string) (identity.Principal, error) {
		if token != "fixture" {
			return identity.Principal{}, identity.ErrInvalidCredential
		}
		return identity.Principal{DeviceID: mobile, TenantID: scope, ApplicationID: pc, Role: role}, nil
	})
}
func catalogRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer fixture")
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestCatalogStatusIdentityComesOnlyFromVerifier(t *testing.T) {
	calls := 0
	h, err := NewCatalogHandler(fixtureAccess(identity.Mobile), catalogFixture{update: func(ctx context.Context, p identity.Principal, status catalog.Status) error {
		calls++
		if p.DeviceID != mobile || status.BootID != scope || status.Sequence != 1 {
			t.Error("status did not use verified installation")
		}
		return nil
	}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"boot_id":"` + scope + `","seq":1,"permissions":{"projection":true},"capabilities":{}}`, 200},
		{`{"boot_id":"` + scope + `","seq":1,"device_uuid":"victim"}`, 400},
		{`{"boot_id":"` + scope + `","seq":1,"permissions":{"projection":true,"projection":false}}`, 400},
		{`{"boot_id":"` + scope + `","seq":1,"permissions":{"admin":true}}`, 400},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, catalogRequest("PUT", "/qm/v1/device-self/status", tc.body))
		if w.Code != tc.status {
			t.Fatalf("status=%d want=%d", w.Code, tc.status)
		}
	}
	if calls != 1 {
		t.Fatal("invalid/spoofed status reached store")
	}
}

func TestLegacyUUIDResolveRemoved(t *testing.T) {
	h, err := NewCatalogHandler(fixtureAccess(identity.PC), catalogFixture{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, catalogRequest("POST", "/qm/v1/devices/resolve", `{"uuids":[]}`))
	if w.Code != 404 {
		t.Fatal("legacy UUID endpoint still exposed")
	}
}

func TestNavigationStatusStrictHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, key, extra string
		code             int
	}{
		{"legacy", "navigation_v1", "", 200},
		{"six", "navigation_v1", `,"actions":["back","home","recents","volume_up","volume_down","notifications"]`, 200},
		{"empty", "navigation_v1", `,"actions":[]`, 200},
		{"other", "touch", `,"actions":[]`, 400},
		{"unknown", "navigation_v1", `,"actions":["power"]`, 400},
		{"duplicate", "navigation_v1", `,"actions":["home","home"]`, 400},
		{"uppercase-null", "navigation_v1", `,"Actions":null`, 400},
		{"uppercase-override", "navigation_v1", `,"actions":["home"],"Actions":null`, 400},
		{"null", "navigation_v1", `,"actions":null`, 400},
		{"nullitem", "navigation_v1", `,"actions":[null]`, 400},
		{"number", "navigation_v1", `,"actions":[1]`, 400},
		{"string", "navigation_v1", `,"actions":"home"`, 400},
		{"extra", "navigation_v1", `,"evil":true`, 400},
		{"seven", "navigation_v1", `,"actions":["back","home","recents","volume_up","volume_down","notifications","home"]`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h, err := NewCatalogHandler(fixtureAccess(identity.Mobile), catalogFixture{update: func(ctx context.Context, p identity.Principal, s catalog.Status) error {
				calls++
				if tc.name == "six" && (s.Capabilities[tc.key].Actions == nil || len(*s.Capabilities[tc.key].Actions) != 6) {
					t.Fatal("actions lost")
				}
				return nil
			}}, 2)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"boot_id":"` + scope + `","seq":1,"capabilities":{"` + tc.key + `":{"supported":true,"available":true` + tc.extra + `}}}`
			w := httptest.NewRecorder()
			h.ServeHTTP(w, catalogRequest("PUT", "/qm/v1/device-self/status", body))
			if w.Code != tc.code {
				t.Fatalf("got %d want %d", w.Code, tc.code)
			}
			if (calls == 1) != (tc.code == 200) {
				t.Fatal("invalid status reached store")
			}
		})
	}
}
