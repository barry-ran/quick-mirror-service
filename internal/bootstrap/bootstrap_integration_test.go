//go:build integration

package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/barry-ran/quick-mirror-service/internal/peerloom"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"sync"
	"testing"
)

const testScope = "44444444-4444-4444-8444-444444444444"
const testKey = "11111111-1111-4111-8111-111111111111"

func testStore(t *testing.T, issuer GrantIssuer) *Store {
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
	store, err := NewStore(pool, testScope, issuer)
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

type recordingIssuer struct {
	mu     sync.Mutex
	keys   []string
	domain string
	err    error
}

func (r *recordingIssuer) ReplayDomain() string { return r.domain }
func (r *recordingIssuer) Issue(ctx context.Context, role identity.Role, key string, ttl int) (peerloom.RegistrationGrant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, key)
	if ttl != 300 {
		return peerloom.RegistrationGrant{}, fmt.Errorf("wrong TTL")
	}
	return peerloom.RegistrationGrant{}, r.err
}

func TestBootstrapDurableIntent(t *testing.T) {
	issuer := &recordingIssuer{domain: strings.Repeat("a", 64), err: peerloom.ErrOutcomeUnknown}
	store := testStore(t, issuer)
	request := Request{Role: identity.Mobile, Label: "测试安装", IdempotencyKey: testKey}
	var group sync.WaitGroup
	for i := 0; i < 100; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := store.Issue(context.Background(), request); !errors.Is(err, peerloom.ErrOutcomeUnknown) {
				t.Errorf("unexpected issue result: %v", err)
			}
		}()
	}
	group.Wait()
	restarted, err := NewStore(store.pool, testScope, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Issue(context.Background(), request); !errors.Is(err, peerloom.ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	if len(issuer.keys) != 101 {
		t.Fatalf("calls %d", len(issuer.keys))
	}
	original := issuer.keys[0]
	for _, key := range issuer.keys {
		if key != original {
			t.Fatal("retries changed upstream key")
		}
	}
	for _, changed := range []Request{{Role: identity.PC, Label: request.Label, IdempotencyKey: testKey}, {Role: request.Role, Label: "changed", IdempotencyKey: testKey}} {
		if _, err := store.Issue(context.Background(), changed); !errors.Is(err, peerloom.ErrIdempotencyConflict) {
			t.Fatalf("conflict: %v", err)
		}
	}
	if len(issuer.keys) != 101 {
		t.Fatal("conflict issued new grant")
	}
	rotated := &recordingIssuer{domain: strings.Repeat("b", 64)}
	rotationStore, err := NewStore(store.pool, testScope, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotationStore.Issue(context.Background(), request); !errors.Is(err, peerloom.ErrReplayExpired) {
		t.Fatalf("credential rotation reused intent: %v", err)
	}
	if len(rotated.keys) != 0 {
		t.Fatal("credential rotation issued duplicate")
	}
	if _, err := store.pool.Exec(context.Background(), `UPDATE qm_bootstrap_intents SET expires_at=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Issue(context.Background(), request); !errors.Is(err, peerloom.ErrReplayExpired) {
		t.Fatalf("expired: %v", err)
	}
	if err := store.PurgeExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.pool.QueryRow(context.Background(), `SELECT count(*) FROM qm_bootstrap_intents`).Scan(&count); err != nil || count != 0 {
		t.Fatal("purge failed", err)
	}
}

func TestBootstrapScopeAndInputIsolation(t *testing.T) {
	issuer := &recordingIssuer{domain: strings.Repeat("a", 64)}
	store := testStore(t, issuer)
	request := Request{Role: identity.PC, Label: "PC", IdempotencyKey: testKey}
	if _, err := store.Issue(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	other, err := NewStore(store.pool, "55555555-5555-4555-8555-555555555555", issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Issue(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(issuer.keys) != 2 || issuer.keys[0] == issuer.keys[1] {
		t.Fatal("scope shared upstream key")
	}
	request.IdempotencyKey = "invalid"
	if _, err := store.Issue(context.Background(), request); !errors.Is(err, ErrInvalidInput) {
		t.Fatal(err)
	}
	if len(issuer.keys) != 2 {
		t.Fatal("invalid input called issuer")
	}
}
