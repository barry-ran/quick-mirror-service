//go:build integration

package peerloom

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
)

func TestReplayMigrationExactCredentialAndRestart(t *testing.T) {
	ctx := context.Background()
	dsn := os.Getenv("QM_TEST_DATABASE_URL")
	c, e := pgxpool.ParseConfig(dsn)
	if dsn == "" || e != nil || !strings.HasSuffix(c.ConnConfig.Database, "_test") {
		t.Fatal("dedicated *_test database required")
	}
	admin, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	id, _ := operationID()
	schema := "qm_replay_" + strings.ReplaceAll(id, "-", "")
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	c.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	for _, table := range []string{"qm_bootstrap_intents", "qm_control_intents"} {
		if _, e = pool.Exec(ctx, "CREATE TABLE "+table+"(service_scope uuid,replay_domain text)"); e != nil {
			t.Fatal(e)
		}
	}
	if e = MigrateReplaySchema(ctx, pool); e != nil {
		t.Fatal(e)
	}
	f := renewalFixture()
	m := testManager(f)
	config := IdentityConfig{"https://fixture.invalid", renewalTenant, "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"}
	r, _ := NewRegistrationClientWithSource(config, m, nil)
	u, _ := NewControlClientWithSource(config, m, nil, 300)
	rs, _ := r.Snapshot()
	us, _ := u.Snapshot()
	for _, v := range []struct{ table, old string }{{"qm_bootstrap_intents", rs.LegacyReplayDomain()}, {"qm_control_intents", us.LegacyReplayDomain()}} {
		_, e = pool.Exec(ctx, "INSERT INTO "+v.table+" VALUES($1,$2),($1,'unrelated_old_hash')", renewalTenant, v.old)
		if e != nil {
			t.Fatal(e)
		}
	}
	if e = MigrateReplayDomains(ctx, pool, renewalTenant, r, u); e != nil {
		t.Fatal(e)
	}
	if e = m.Step(ctx); e != nil {
		t.Fatal(e)
	}
	// New-key startup cannot recover or guess older hashes, but existing stable rows remain valid.
	if e = MigrateReplayDomains(ctx, pool, renewalTenant, r, u); e != nil {
		t.Fatal(e)
	}
	for _, v := range []struct{ table, domain string }{{"qm_bootstrap_intents", r.ReplayDomain()}, {"qm_control_intents", u.ReplayDomain()}} {
		var n int
		_ = pool.QueryRow(ctx, "SELECT count(*) FROM "+v.table+" WHERE replay_domain=$1", v.domain).Scan(&n)
		if n != 1 {
			t.Fatal("stable receipt lost")
		}
		_ = pool.QueryRow(ctx, "SELECT count(*) FROM "+v.table+" WHERE replay_domain='unrelated_old_hash'").Scan(&n)
		if n != 1 {
			t.Fatal("unverified hash migrated")
		}
	}
	var count int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM qm_peerloom_replay_domains").Scan(&count)
	if count != 4 {
		t.Fatal("mapping not durable")
	}
}
