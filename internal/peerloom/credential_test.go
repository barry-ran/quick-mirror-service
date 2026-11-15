package peerloom

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

func TestFileCredentialValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if _, err := NewFileCredentialSource("relative"); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatal("relative path accepted")
	}
	if _, err := NewFileCredentialSource(path); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatal("missing file accepted")
	}
	for _, value := range []string{"svc_fixture", "svc_fixture\n", "svc_fixture\r\n"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		source, err := NewFileCredentialSource(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := source.Read()
		if err != nil || got != "svc_fixture" {
			t.Fatal("line ending not normalized")
		}
	}
	for _, value := range []string{"", "private secret", "svc_one\nsvc_two", strings.Repeat("a", 513), "svc_a\x00"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := NewFileCredentialSource(path)
		if !errors.Is(err, ErrCredentialUnavailable) || strings.Contains(err.Error(), "private") {
			t.Fatal("invalid file accepted or leaked")
		}
	}
	if _, err := NewFileCredentialSource(filepath.Dir(path)); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatal("directory accepted")
	}
}

func TestFileRotationPinsReplayDomainAndRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	write := func(value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("svc_old")
	source, err := NewFileCredentialSource(path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var headers []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		headers = append(headers, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.URL.Path == "/v1/registration-grants" {
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(RegistrationGrant{ID: deviceID, Grant: "reg_fixture", ExpiresAt: time.Now().Add(time.Minute)})
		} else {
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		}
	}))
	defer server.Close()
	registration, err := NewRegistrationClientWithSource(config(server.URL), source, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	control, err := NewControlClientWithSource(config(server.URL), source, server.Client(), 300)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := registration.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	frozenControl, err := control.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	oldDomain := frozen.ReplayDomain()
	oldControlDomain := frozenControl.ReplayDomain()
	write("svc_new")
	if oldDomain == registration.ReplayDomain() || oldControlDomain == control.ReplayDomain() {
		t.Fatal("rotation did not fence replay")
	}
	if _, err := frozen.Issue(context.Background(), identity.PC, "test-key-123", 300); err != nil {
		t.Fatal(err)
	}
	var out map[string]bool
	if err := frozenControl.request(context.Background(), http.MethodGet, "/v1/test", "", nil, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := registration.Issue(context.Background(), identity.PC, "test-key-456", 300); err != nil {
		t.Fatal(err)
	}
	if err := control.request(context.Background(), http.MethodGet, "/v1/test", "", nil, &out); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if strings.Join(headers, ",") != "Bearer svc_old,Bearer svc_old,Bearer svc_new,Bearer svc_new" {
		t.Error("snapshot credential changed")
	}
	before := len(headers)
	mu.Unlock()
	write("")
	if _, err := registration.Issue(context.Background(), identity.PC, "test-key-789", 300); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatal("failed file used old key")
	}
	if err := control.request(context.Background(), http.MethodGet, "/v1/test", "", nil, &out); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatal("control used cached key")
	}
	if registration.ReplayDomain() != "" || control.ReplayDomain() != "" {
		t.Fatal("unavailable source has domain")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(headers) != before {
		t.Fatal("invalid file sent HTTP")
	}
}

func TestRotatedCredentialManagesExistingGrant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("svc_old"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := NewFileCredentialSource(path)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer svc_new" {
			t.Error("old credential reused")
		}
		if r.Method == http.MethodDelete {
			json.NewEncoder(w).Encode(map[string]any{"id": deviceID, "revoked": true})
		} else {
			json.NewEncoder(w).Encode(ControlGrant{ID: deviceID, TenantID: tenantID, SourceDeviceID: pcID, TargetDeviceID: mobileID, ExpiresAt: time.Now().Add(time.Hour), ExpiryAction: "no_new_connections", MaxSessions: 1})
		}
	}))
	defer server.Close()
	client, err := NewControlClientWithSource(config(server.URL), source, server.Client(), 300)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("svc_new"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetGrant(context.Background(), deviceID); err != nil {
		t.Fatal(err)
	}
	if err := client.RevokeGrant(context.Background(), deviceID, "revoke-key-123"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetGrant(context.Background(), deviceID); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatal("missing file fallback")
	}
	if err := os.WriteFile(path, []byte("svc_new"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetGrant(context.Background(), deviceID); err != nil {
		t.Fatal("valid file restoration failed", err)
	}
}

func TestCredentialJSONOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	good := `{"tenant_id":"fixture","service_credential":"svc_fixture","expires_at":"2026-12-15T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := NewFileCredentialSource(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := source.Read(); err != nil || got != "svc_fixture" {
		t.Fatal("setup output rejected")
	}
	for _, value := range []string{`{}`, `{"service_credential":17}`, `{"service_credential":"secret invalid"}`, good + `{}`, strings.Repeat(" ", 16<<10) + good} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := source.Read(); !errors.Is(err, ErrCredentialUnavailable) {
			t.Fatal("invalid output accepted")
		}
	}
}
