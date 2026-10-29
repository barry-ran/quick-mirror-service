//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func testHTTPPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("QM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("integration tests require QM_TEST_DATABASE_URL for a dedicated *_test database")
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test database configuration")
	}
	if !strings.HasSuffix(config.ConnConfig.Database, "_test") {
		t.Fatal("refusing integration tests outside a dedicated *_test database")
	}
	ctx := context.Background()
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "qm_test_" + hex.EncodeToString(suffix[:])
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, err := admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
		if err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	return pool
}

func testHTTPDirectory(t *testing.T) *catalog.Store {
	t.Helper()
	ctx := context.Background()
	pool := testHTTPPool(t)
	store, err := catalog.NewStore(pool, scope, scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal("migration not repeatable", err)
	}
	return store
}

func TestCatalogHTTPRealDatabaseAndTLS(t *testing.T) {
	directory := testHTTPDirectory(t)
	ctx := context.Background()
	pcPrincipal := identity.Principal{DeviceID: pc, TenantID: scope, ApplicationID: pc, Role: identity.PC}
	device := identity.Principal{DeviceID: mobile, TenantID: scope, ApplicationID: mobile, Role: identity.Mobile}
	if err := directory.Register(ctx, device, "test"); err != nil {
		t.Fatal(err)
	}
	verifier := accessFunc(func(ctx context.Context, token string) (identity.Principal, error) {
		switch token {
		case "pc_fixture":
			return pcPrincipal, nil
		case "mobile_fixture":
			return device, nil
		case "foreign_fixture":
			foreign := pcPrincipal
			foreign.TenantID = mobile
			return foreign, nil
		default:
			return identity.Principal{}, identity.ErrInvalidCredential
		}
	})
	handler, err := NewCatalogHandler(verifier, directory, 8)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	request := func(method, path, token string, payload []byte) (int, []byte) {
		t.Helper()
		r, err := http.NewRequest(method, server.URL+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	status := []byte(`{"boot_id":"` + scope + `","seq":1,"permissions":{"projection":true},"capabilities":{"mirror":{"supported":true,"available":true}}}`)
	if code, _ := request("PUT", "/qm/v1/device-self/status", "mobile_fixture", status); code != 200 {
		t.Fatalf("update=%d", code)
	}
	if code, _ := request("PUT", "/qm/v1/device-self/status", "mobile_fixture", status); code != 409 {
		t.Fatal("stale status not rejected", code)
	}
	if code, _ := request("PUT", "/qm/v1/device-self/status", "pc_fixture", status); code != 403 {
		t.Fatal("PC wrote mobile status", code)
	}
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = fmt.Sprintf("66666666-6666-4666-8666-%012d", i)
		p := device
		p.DeviceID = ids[i]
		if err := directory.Register(ctx, p, "test"); err != nil {
			t.Fatal(err)
		}
	}
	total := 0
	for start := 0; start < len(ids); start += 200 {
		end := start + 200
		if end > len(ids) {
			end = len(ids)
		}
		body, _ := json.Marshal(map[string]any{"uuids": ids[start:end]})
		code, data := request("POST", "/qm/v1/devices/resolve", "pc_fixture", body)
		if code != 200 {
			t.Fatal("resolve", code)
		}
		var result struct {
			Data struct {
				Items []struct {
					Found bool `json:"found"`
				} `json:"items"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &result) != nil || len(result.Data.Items) != end-start {
			t.Fatal("batch truncated")
		}
		for _, item := range result.Data.Items {
			if !item.Found {
				t.Fatal("registered offline record hidden")
			}
			total++
		}
	}
	if total != 501 {
		t.Fatal("device count capped")
	}
	body, _ := json.Marshal(map[string]any{"uuids": ids[:201]})
	if code, _ := request("POST", "/qm/v1/devices/resolve", "pc_fixture", body); code != 400 {
		t.Fatal("oversize batch accepted", code)
	}
	body, _ = json.Marshal(map[string]any{"uuids": []string{mobile}})
	code, data := request("POST", "/qm/v1/devices/resolve", "pc_fixture", body)
	if code != 200 || strings.Contains(string(data), "projection") || strings.Contains(string(data), "online") {
		t.Fatal("permission snapshot represented availability")
	}
	if code, _ := request("POST", "/qm/v1/devices/resolve", "foreign_fixture", body); code != 403 {
		t.Fatal("foreign tenant allowed", code)
	}
	records, err := directory.ResolveBatch(ctx, pcPrincipal, []string{mobile})
	if err != nil || len(records) != 1 || records[0].Device == nil || !records[0].Device.Permissions.Projection {
		t.Fatal("status did not persist", err)
	}
}
