package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

type accessFunc func(context.Context, string) (identity.Principal, error)

func (f accessFunc) VerifyAccess(c context.Context, s string) (identity.Principal, error) {
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

func fixtureAccess(role identity.Role) AccessVerifier {
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

func TestCatalogResolveOverTLSReportsExistenceOnly(t *testing.T) {
	h, err := NewCatalogHandler(fixtureAccess(identity.PC), catalogFixture{resolve: func(ctx context.Context, p identity.Principal, ids []string) ([]catalog.Resolution, error) {
		if p.Role != identity.PC || len(ids) != 2 || ids[0] != mobile {
			t.Error("incorrect authenticated resolution")
		}
		return []catalog.Resolution{{UUID: mobile, Found: true, Device: &catalog.Device{UUID: mobile, Permissions: catalog.Permissions{Projection: true}}}, {UUID: "invalid", ErrorCode: "INVALID_UUID"}}, nil
	}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	r, err := http.NewRequest("POST", server.URL+"/qm/v1/devices/resolve", strings.NewReader(`{"uuids":["`+mobile+`","invalid"]}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer fixture")
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 || strings.Contains(string(data), "projection") || strings.Contains(string(data), "online") {
		t.Fatalf("old snapshot leaked as availability: %s", data)
	}
	var envelope struct {
		Data struct {
			Items []struct {
				UUID  string `json:"uuid"`
				Found bool   `json:"found"`
				Error string `json:"error_code"`
			} `json:"items"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &envelope) != nil || len(envelope.Data.Items) != 2 || !envelope.Data.Items[0].Found || envelope.Data.Items[1].Error != "INVALID_UUID" {
		t.Fatal("per-item contract lost")
	}
}

func TestCatalogStatusIdentityComesOnlyFromAccessVerifier(t *testing.T) {
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

func TestCatalogRejectsInvalidRequestsBeforeStore(t *testing.T) {
	called := false
	repo := catalogFixture{resolve: func(context.Context, identity.Principal, []string) ([]catalog.Resolution, error) {
		called = true
		return nil, nil
	}}
	h, err := NewCatalogHandler(fixtureAccess(identity.PC), repo, 2)
	if err != nil {
		t.Fatal(err)
	}
	tooMany := `{"uuids":[` + strings.TrimSuffix(strings.Repeat(`"`+mobile+`",`, 201), ",") + `]}`
	for _, body := range []string{`null`, `{}`, `{"uuids":null}`, `{"uuids":[],"uuids":[]}`, `{"uuids":[],"role":"mobile"}`, `{"uuids":[1]}`, `{"uuids":[]} {}`, tooMany, string([]byte{'{', '"', 0xff, '"', ':', '0', '}'}), `{"uuids":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`, `{"uuids":` + strings.Repeat("[0,", 5000) + `0` + strings.Repeat("]", 5000) + `}`} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, catalogRequest("POST", "/qm/v1/devices/resolve", body))
		if w.Code != 400 {
			t.Fatalf("invalid request status %d", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, catalogRequest("POST", "/qm/v1/devices/resolve", strings.Repeat(" ", (1<<20)+1)))
	if w.Code != 413 {
		t.Fatal("body budget not enforced")
	}
	if called {
		t.Fatal("invalid request called store")
	}
}

func TestCatalogAuthenticationAndErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		role                  identity.Role
		authError, storeError error
		status                int
		code                  string
	}{
		{identity.Mobile, nil, nil, 403, "INSTALLATION_FORBIDDEN"},
		{identity.PC, identity.ErrInvalidCredential, nil, 401, "AUTH_INVALID"},
		{identity.PC, errors.New("private source credential"), nil, 503, "SERVICE_UNAVAILABLE"},
		{identity.PC, nil, catalog.ErrInvalidInput, 400, "INVALID_INPUT"},
		{identity.PC, nil, catalog.ErrNotFound, 404, "DEVICE_NOT_FOUND"},
		{identity.PC, nil, catalog.ErrStaleStatus, 409, "STALE_STATUS"},
		{identity.PC, nil, errors.New("private database detail"), 503, "SERVICE_UNAVAILABLE"},
	} {
		h, err := NewCatalogHandler(accessFunc(func(context.Context, string) (identity.Principal, error) {
			return identity.Principal{Role: tc.role}, tc.authError
		}), catalogFixture{resolve: func(context.Context, identity.Principal, []string) ([]catalog.Resolution, error) {
			return nil, tc.storeError
		}}, 2)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, catalogRequest("POST", "/qm/v1/devices/resolve", `{"uuids":[]}`))
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) || strings.Contains(w.Body.String(), "private") {
			t.Fatalf("unsafe error mapping %d %s", w.Code, w.Body.String())
		}
	}
	h, err := NewCatalogHandler(accessFunc(func(context.Context, string) (identity.Principal, error) {
		t.Error("invalid header reached verifier")
		return identity.Principal{}, nil
	}), catalogFixture{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "Basic fixture", "Bearer ", "Bearer has space", "Bearer 非ASCII"} {
		r := catalogRequest("POST", "/qm/v1/devices/resolve", `{"uuids":[]}`)
		r.Header.Set("Authorization", value)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("bad bearer accepted")
		}
	}
	r := catalogRequest("POST", "/qm/v1/devices/resolve", `{"uuids":[]}`)
	r.Header.Add("Authorization", "Bearer second")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("ambiguous authorization accepted")
	}
}

func TestCatalogBoundsVerifierConcurrencyAndPropagatesCancellation(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	verifier := accessFunc(func(ctx context.Context, token string) (identity.Principal, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 10*time.Second {
			t.Error("unbounded authentication deadline")
		}
		close(entered)
		<-release
		return identity.Principal{Role: identity.PC}, nil
	})
	h, err := NewCatalogHandler(verifier, catalogFixture{resolve: func(context.Context, identity.Principal, []string) ([]catalog.Resolution, error) { return nil, nil }}, 1)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(done)
		h.ServeHTTP(httptest.NewRecorder(), catalogRequest("POST", "/qm/v1/devices/resolve", `{"uuids":[]}`))
	}()
	<-entered
	w := httptest.NewRecorder()
	h.ServeHTTP(w, catalogRequest("POST", "/qm/v1/devices/resolve", `{"uuids":[]}`))
	if w.Code != 429 {
		t.Error("verifier concurrency unbounded")
	}
	close(release)
	<-done
	h, err = NewCatalogHandler(accessFunc(func(ctx context.Context, token string) (identity.Principal, error) {
		<-ctx.Done()
		return identity.Principal{}, ctx.Err()
	}), catalogFixture{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := catalogRequest("POST", "/qm/v1/devices/resolve", `{"uuids":[]}`).WithContext(ctx)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal("canceled verification returned successful identity")
	}
}
