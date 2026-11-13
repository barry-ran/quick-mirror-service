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
