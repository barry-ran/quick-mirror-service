//go:build integration

package binding

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"sync"
	"testing"
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

func TestBindingLifecycleAndIdempotency(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := pc()
	m := mobile("55555555-5555-4555-8555-555555555555")
	s.generateCode = func() (string, error) { return "000001", nil }
	pcCode, e := s.Ensure(ctx, p)
	if e != nil || pcCode.Code != "000001" {
		t.Fatal(pcCode, e)
	}
	s.generateCode = func() (string, error) { return "000002", nil }
	mobileCode, e := s.Ensure(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.Ensure(ctx, p)
	if e != nil || again.Code != pcCode.Code {
		t.Fatal("ensure changed permanent code", e)
	}
	r, e := s.Bind(ctx, m, pcCode.Code, "binding-key-1")
	if e != nil || !r.Active || r.PCID != p.DeviceID {
		t.Fatal(r, e)
	}
	dup, e := s.Bind(ctx, p, mobileCode.Code, "binding-key-2")
	if e != nil || dup.ID != r.ID {
		t.Fatal("repeat pair", dup, e)
	}
	hidden, e := s.SelfCode(ctx, m)
	if e != nil || !hidden.Bound || hidden.Code != "" {
		t.Fatal("bound code exposed", e)
	}
	if _, e = s.Refresh(ctx, m, "refresh-key-1"); !errors.Is(e, ErrRefreshNotAllowed) {
		t.Fatal("bound refresh", e)
	}
	released, e := s.Unbind(ctx, m, r.ID, r.Revision, "unbind-key-1")
	if e != nil || released.Active || !released.ClosePending {
		t.Fatal(released, e)
	}
	restored, e := s.SelfCode(ctx, m)
	if e != nil || restored.Code != mobileCode.Code {
		t.Fatal("unbind rotated code", e)
	}
	r2, e := s.Bind(ctx, p, mobileCode.Code, "binding-key-3")
	if e != nil || r2.ID == r.ID {
		t.Fatal("new relationship ID", e)
	}
	if _, e = s.Unbind(ctx, m, r.ID, r.Revision, "unbind-key-2"); e != nil {
		t.Fatal("repeat old unbind", e)
	}
	page, e := s.List(ctx, p, "", 200)
	if e != nil || len(page.Items) != 1 || page.Items[0].ID != r2.ID {
		t.Fatal("old unbind removed new relation", e)
	}
	var tasks int
	if e = s.pool.QueryRow(ctx, `SELECT count(*) FROM qm_binding_close_tasks`).Scan(&tasks); e != nil || tasks != 1 {
		t.Fatal("outbox not atomic", tasks, e)
	}
	_, e = s.Unbind(ctx, p, r2.ID, r2.Revision, "unbind-key-3")
	if e != nil {
		t.Fatal(e)
	}
	s.generateCode = func() (string, error) { return "000003", nil }
	fresh, e := s.Refresh(ctx, m, "refresh-key-2")
	if e != nil || fresh.Code == mobileCode.Code {
		t.Fatal(e)
	}
	replay, e := s.Refresh(ctx, m, "refresh-key-2")
	if e != nil || replay.Code != fresh.Code {
		t.Fatal("refresh replay", e)
	}
	if _, e = s.Bind(ctx, p, mobileCode.Code, "binding-key-4"); !errors.Is(e, ErrCodeInvalid) {
		t.Fatal("retired code accepted", e)
	}
	if _, e = s.Bind(ctx, p, fresh.Code, "binding-key-2"); !errors.Is(e, ErrIdempotencyConflict) {
		t.Fatal("key conflict", e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE qm_binding_receipts SET expires_at=clock_timestamp()-interval '1 second' WHERE operation='refresh'`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Refresh(ctx, m, "refresh-key-2"); !errors.Is(e, ErrOutcomeUnknown) {
		t.Fatal("expired key reexecuted", e)
	}
}
func TestBindingConcurrentPCsAndIsolation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := pc()
	p2 := p
	p2.DeviceID = "66666666-6666-4666-8666-666666666666"
	m := mobile("55555555-5555-4555-8555-555555555555")
	for _, who := range []identity.Principal{p, p2, m} {
		if _, e := s.Ensure(ctx, who); e != nil {
			t.Fatal(e)
		}
	}
	code, e := s.SelfCode(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, who := range []identity.Principal{p, p2} {
		wg.Add(1)
		go func(who identity.Principal) {
			defer wg.Done()
			_, e := s.Bind(ctx, who, code.Code, "concurrent-key")
			results <- e
		}(who)
	}
	wg.Wait()
	close(results)
	wins, losses := 0, 0
	for e := range results {
		if e == nil {
			wins++
		} else if errors.Is(e, ErrAlreadyBound) {
			losses++
		} else {
			t.Fatal(e)
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatal("two winners", wins, losses)
	}
	bad := p
	bad.TenantID = "77777777-7777-4777-8777-777777777777"
	if _, e = s.SelfCode(ctx, bad); !errors.Is(e, identity.ErrForbidden) {
		t.Fatal("tenant bypass", e)
	}
	bad = p
	bad.ApplicationID = m.DeviceID
	if _, e = s.Ensure(ctx, bad); !errors.Is(e, identity.ErrForbidden) {
		t.Fatal("application overwrite", e)
	}
}
func TestAllocationCollisionRollback(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	s.generateCode = func() (string, error) { return "000001", nil }
	if _, e := s.Ensure(ctx, pc()); e != nil {
		t.Fatal(e)
	}
	m := mobile("55555555-5555-4555-8555-555555555555")
	if _, e := s.Ensure(ctx, m); !errors.Is(e, ErrAllocationRetry) {
		t.Fatal("unbounded or false exhaustion", e)
	}
	var count int
	if e := s.pool.QueryRow(ctx, `SELECT count(*) FROM qm_installations`).Scan(&count); e != nil || count != 1 {
		t.Fatal("partial allocation leaked", e)
	}
}

func TestRefreshBindRaceAndClosureCompletion(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := pc()
	m := mobile("55555555-5555-4555-8555-555555555555")
	if _, e := s.Ensure(ctx, p); e != nil {
		t.Fatal(e)
	}
	old, e := s.Ensure(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var bindErr, refreshErr error
	var relation Relation
	wg.Add(2)
	go func() { defer wg.Done(); relation, bindErr = s.Bind(ctx, p, old.Code, "race-bind-key") }()
	go func() { defer wg.Done(); _, refreshErr = s.Refresh(ctx, m, "race-refresh-key") }()
	wg.Wait()
	if bindErr == nil {
		if !errors.Is(refreshErr, ErrRefreshNotAllowed) {
			t.Fatal("bind won but refresh succeeded", refreshErr)
		}
	} else {
		if !errors.Is(bindErr, ErrCodeInvalid) || refreshErr != nil {
			t.Fatal("refresh winner invalid", bindErr, refreshErr)
		}
		code, e := s.SelfCode(ctx, m)
		if e != nil {
			t.Fatal(e)
		}
		relation, e = s.Bind(ctx, p, code.Code, "post-race-bind")
		if e != nil {
			t.Fatal(e)
		}
	}
	if _, e = s.Unbind(ctx, p, relation.ID, relation.Revision, "closure-key-1"); e != nil {
		t.Fatal(e)
	}
	tasks, e := s.PendingClosures(ctx, 200)
	if e != nil || len(tasks) != 1 || tasks[0].ID != relation.ID {
		t.Fatal("missing pending closure", e)
	}
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if e = s.CompleteClosure(ctx, tx, relation.ID); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	done, e := s.Unbind(ctx, p, relation.ID, relation.Revision, "closure-key-1")
	if e != nil || done.ClosePending {
		t.Fatal("replayed close status stale", e)
	}
	tasks, e = s.PendingClosures(ctx, 200)
	if e != nil || len(tasks) != 0 {
		t.Fatal("completed task remains", e)
	}
}
func TestOnePCManyMobilesAndCursor(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := pc()
	if _, e := s.Ensure(ctx, p); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"} {
		m := mobile(id)
		code, e := s.Ensure(ctx, m)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Bind(ctx, p, code.Code, "many-"+id); e != nil {
			t.Fatal(e)
		}
	}
	first, e := s.List(ctx, p, "", 1)
	if e != nil || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatal(first, e)
	}
	second, e := s.List(ctx, p, first.NextCursor, 1)
	if e != nil || len(second.Items) != 1 || second.NextCursor != "" || first.Items[0].ID == second.Items[0].ID {
		t.Fatal(second, e)
	}
}
func TestRetiredCodeSpaceExhaustion(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := pc()
	if _, e := s.Ensure(ctx, p); e != nil {
		t.Fatal(e)
	}
	_, e := s.pool.Exec(ctx, `INSERT INTO qm_binding_codes(service_scope,code,owner_device_id,current,retired_at) SELECT $1,lpad(n::text,6,'0'),$2,false,clock_timestamp() FROM generate_series(0,999999) n ON CONFLICT DO NOTHING`, s.scope, p.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Ensure(ctx, mobile("55555555-5555-4555-8555-555555555555")); !errors.Is(e, ErrCodeSpaceExhausted) {
		t.Fatal("exhaustion not explicit", e)
	}
}

func TestClosurePollingDoesNotStarveBeyondFirstPage(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := pc()
	m := mobile("55555555-5555-4555-8555-555555555555")
	if _, e := s.Ensure(ctx, p); e != nil {
		t.Fatal(e)
	}
	code, e := s.Ensure(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 201; n++ {
		key, e := newID()
		if e != nil {
			t.Fatal(e)
		}
		r, e := s.Bind(ctx, p, code.Code, key)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Unbind(ctx, p, r.ID, r.Revision, key); e != nil {
			t.Fatal(e)
		}
	}
	seen := map[string]bool{}
	for n := 0; n < 3; n++ {
		pending, e := s.PendingClosures(ctx, 100)
		if e != nil {
			t.Fatal(e)
		}
		for _, r := range pending {
			seen[r.ID] = true
		}
	}
	if len(seen) != 201 {
		t.Fatalf("pending rows starved: scanned=%d", len(seen))
	}
}
