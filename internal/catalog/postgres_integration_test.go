//go:build integration

package catalog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testTenant = "11111111-1111-4111-8111-111111111111"
const testApplication = "22222222-2222-4222-8222-222222222222"
const testDevice = "33333333-3333-4333-8333-333333333333"
const testScope = "44444444-4444-4444-8444-444444444444"

func testStore(t *testing.T) *Store {
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
	store, err := NewStore(pool, testScope, testTenant)
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

func mobile(id string) identity.Principal {
	return identity.Principal{DeviceID: id, ApplicationID: testApplication, TenantID: testTenant, Role: identity.Mobile}
}

func pc() identity.Principal {
	p := mobile(testDevice)
	p.Role = identity.PC
	return p
}

func TestPostgresRegistrationStatusAndIsolation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := mobile(testDevice)
	if err := s.Register(ctx, pc(), "1"); !errors.Is(err, identity.ErrForbidden) {
		t.Fatal("PC registered mobile", err)
	}
	if err := s.Register(ctx, p, "1"); err != nil {
		t.Fatal(err)
	}
	status := Status{BootID: "55555555-5555-4555-8555-555555555555", Sequence: 1, AppVersion: "1"}
	if err := s.UpdateStatus(ctx, p, status); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateStatus(ctx, p, status); !errors.Is(err, ErrStaleStatus) {
		t.Fatal("duplicate accepted", err)
	}
	old := status
	status.BootID = "66666666-6666-4666-8666-666666666666"
	status.Permissions.Projection = true
	if err := s.UpdateStatus(ctx, p, status); err != nil {
		t.Fatal(err)
	}
	old.Sequence = 999
	if err := s.UpdateStatus(ctx, p, old); !errors.Is(err, ErrStaleStatus) {
		t.Fatal("retired boot accepted", err)
	}
	items, err := s.ResolveBatch(ctx, pc(), []string{testDevice, "bad", strings.ToUpper(testDevice), testApplication})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 4 || !items[0].Found || !items[0].Device.Permissions.Projection || items[1].ErrorCode != "INVALID_UUID" || !items[2].Found || items[3].Found {
		t.Fatalf("bad resolution %+v", items)
	}
	other, err := NewStore(s.pool, "77777777-7777-4777-8777-777777777777", testTenant)
	if err != nil {
		t.Fatal(err)
	}
	items, err = other.ResolveBatch(ctx, pc(), []string{testDevice})
	if err != nil || items[0].Found {
		t.Fatal("cross scope leak", err)
	}
	forged := p
	forged.ApplicationID = testScope
	if err := s.Register(ctx, forged, "2"); !errors.Is(err, identity.ErrForbidden) {
		t.Fatal("application changed", err)
	}
}

func TestPostgresConcurrentStatus(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := mobile(testDevice)
	if err := s.Register(ctx, p, "1"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := int64(1); i <= 100; i++ {
		wg.Add(1)
		go func(seq int64) {
			defer wg.Done()
			err := s.UpdateStatus(ctx, p, Status{BootID: testScope, Sequence: seq, AppVersion: fmt.Sprint(seq)})
			if err != nil && !errors.Is(err, ErrStaleStatus) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	items, err := s.ResolveBatch(ctx, pc(), []string{testDevice})
	if err != nil || items[0].Device.AppVersion != "100" {
		t.Fatal("concurrent sequence regressed", items, err)
	}
}

func TestPostgresBatchBeyond500(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", i)
		if err := s.Register(ctx, mobile(ids[i]), "1"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ResolveBatch(ctx, pc(), ids); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("batch body boundary ignored", err)
	}
	count := 0
	for start := 0; start < len(ids); start += BatchSize {
		end := min(start+BatchSize, len(ids))
		items, err := s.ResolveBatch(ctx, pc(), ids[start:end])
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			if !item.Found {
				t.Fatal("missing device", item.UUID)
			}
			count++
		}
	}
	if count != 501 {
		t.Fatal("total device truncation", count)
	}
}

func TestPostgresEnsureRegistrationPreservesStatus(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	principal := mobile(testDevice)
	if err := s.EnsureRegistration(ctx, pc()); !errors.Is(err, identity.ErrForbidden) {
		t.Fatal("PC created mobile record", err)
	}
	if err := s.EnsureRegistration(ctx, principal); err != nil {
		t.Fatal(err)
	}
	initial, err := s.ResolveBatch(ctx, pc(), []string{testDevice})
	if err != nil || !initial[0].Found || initial[0].Device.AppVersion != "" {
		t.Fatal("new identity missing", err)
	}
	status := Status{BootID: "55555555-5555-4555-8555-555555555555", Sequence: 7, AppVersion: "1.2.3", Permissions: Permissions{Projection: true}, Capabilities: map[string]Capability{"capture": {Supported: true, Available: true}}}
	if err := s.UpdateStatus(ctx, principal, status); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := s.pool.QueryRow(ctx, `SELECT row_to_json(d)::text FROM qm_device_catalog d WHERE service_scope=$1 AND device_uuid=$2`, testScope, testDevice).Scan(&before); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.EnsureRegistration(ctx, principal) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var after string
	if err := s.pool.QueryRow(ctx, `SELECT row_to_json(d)::text FROM qm_device_catalog d WHERE service_scope=$1 AND device_uuid=$2`, testScope, testDevice).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("identity re-exchange changed existing device snapshot")
	}
	other := principal
	other.ApplicationID = "66666666-6666-4666-8666-666666666666"
	if err := s.EnsureRegistration(ctx, other); !errors.Is(err, identity.ErrForbidden) {
		t.Fatal("application takeover accepted", err)
	}
	other = principal
	other.TenantID = "77777777-7777-4777-8777-777777777777"
	if err := s.EnsureRegistration(ctx, other); !errors.Is(err, identity.ErrForbidden) {
		t.Fatal("foreign tenant accepted", err)
	}
	if err := s.UpdateStatus(ctx, principal, status); !errors.Is(err, ErrStaleStatus) {
		t.Fatal("re-exchange reset sequence", err)
	}
}
