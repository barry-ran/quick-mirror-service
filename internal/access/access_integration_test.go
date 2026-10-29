//go:build integration

package access

import (
	"bytes"
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
	"time"
)

const testScope = "11111111-1111-4111-8111-111111111111"
const testTenant = "22222222-2222-4222-8222-222222222222"
const testDevice = "33333333-3333-4333-8333-333333333333"
const testApplication = "44444444-4444-4444-8444-444444444444"

type verifierFunc func(context.Context, string) (VerifiedCredential, error)

func (v verifierFunc) VerifyCredential(c context.Context, s string) (VerifiedCredential, error) {
	return v(c, s)
}
func principal() identity.Principal {
	return identity.Principal{DeviceID: testDevice, TenantID: testTenant, ApplicationID: testApplication, Role: identity.Mobile}
}
func testStore(t *testing.T, verifier CredentialVerifier) *Store {
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
	store, err := NewStore(pool, testScope, testTenant, bytes.Repeat([]byte{7}, 32), verifier)
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

func TestAccessExpiryEncryptionAndRevocation(t *testing.T) {
	ctx := context.Background()
	source := VerifiedCredential{Principal: principal(), ExpiresAt: time.Now().Add(2 * time.Minute)}
	var failure error
	calls := 0
	verifier := verifierFunc(func(ctx context.Context, credential string) (VerifiedCredential, error) {
		calls++
		if credential != "dev_fixture" {
			t.Error("credential roundtrip changed")
		}
		return source, failure
	})
	store := testStore(t, verifier)
	token, err := store.Exchange(ctx, identity.Mobile, "dev_fixture")
	if err != nil {
		t.Fatal(err)
	}
	if token.ExpiresAt.After(source.ExpiresAt) || token.ExpiresAt.Location() != time.UTC || token.Scope != testScope {
		t.Fatal("credential lifetime extended")
	}
	got, err := store.VerifyAccess(ctx, token.AccessToken)
	if err != nil || got != source.Principal || calls != 2 {
		t.Fatalf("verification failed: %v", err)
	}
	hash, _ := tokenHash(token.AccessToken)
	var sealed, nonce []byte
	if err := store.pool.QueryRow(ctx, `SELECT credential_ciphertext,credential_nonce FROM qm_access_tokens WHERE token_hash=$1`, hash[:]).Scan(&sealed, &nonce); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("dev_fixture")) || len(nonce) != 12 {
		t.Fatal("source credential not sealed")
	}
	if _, err := store.Exchange(ctx, identity.PC, "dev_fixture"); !errors.Is(err, identity.ErrForbidden) {
		t.Fatal("role confusion", err)
	}
	originalPrincipal := source.Principal
	for _, changed := range []identity.Principal{
		{DeviceID: testApplication, TenantID: testTenant, ApplicationID: testApplication, Role: identity.Mobile},
		{DeviceID: testDevice, TenantID: testScope, ApplicationID: testApplication, Role: identity.Mobile},
		{DeviceID: testDevice, TenantID: testTenant, ApplicationID: testDevice, Role: identity.Mobile},
		{DeviceID: testDevice, TenantID: testTenant, ApplicationID: testApplication, Role: identity.PC},
	} {
		source.Principal = changed
		if _, err := store.VerifyAccess(ctx, token.AccessToken); !errors.Is(err, identity.ErrInvalidCredential) {
			t.Fatal("source principal mutation accepted", err)
		}
	}
	source.Principal = originalPrincipal
	failure = identity.ErrInvalidCredential
	if _, err := store.VerifyAccess(ctx, token.AccessToken); !errors.Is(err, identity.ErrInvalidCredential) {
		t.Fatal("revoked source credential accepted", err)
	}
	failure = errors.New("private upstream failure")
	if _, err := store.VerifyAccess(ctx, token.AccessToken); !errors.Is(err, identity.ErrUnavailable) {
		t.Fatal("outage falsely authenticated or leaked", err)
	}
	failure = nil
	source.ExpiresAt = time.Time{}
	if _, err := store.Exchange(ctx, identity.Mobile, "dev_fixture"); !errors.Is(err, identity.ErrUnavailable) {
		t.Fatal("missing trusted expiry accepted", err)
	}
	if _, err := store.VerifyAccess(ctx, token.AccessToken); !errors.Is(err, identity.ErrUnavailable) {
		t.Fatal("missing current expiry accepted", err)
	}
	source.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := store.Exchange(ctx, identity.Mobile, "dev_fixture"); !errors.Is(err, identity.ErrInvalidCredential) {
		t.Fatal("expired source issued token", err)
	}
	source.ExpiresAt = time.Now().Add(time.Hour)
	longer, err := store.Exchange(ctx, identity.Mobile, "dev_fixture")
	if err != nil {
		t.Fatal(err)
	}
	if longer.ExpiresAt.After(time.Now().Add(15*time.Minute)) || longer.ExpiresAt.Before(time.Now().Add(14*time.Minute)) {
		t.Fatal("business token cap not applied")
	}
	rotated, err := NewStore(store.pool, testScope, testTenant, bytes.Repeat([]byte{9}, 32), verifier)
	if err != nil {
		t.Fatal(err)
	}
	count := calls
	if _, err := rotated.VerifyAccess(ctx, longer.AccessToken); !errors.Is(err, identity.ErrInvalidCredential) || calls != count {
		t.Fatal("rotation did not invalidate old ciphertext", err)
	}
	longerHash, _ := tokenHash(longer.AccessToken)
	if _, err := store.pool.Exec(ctx, `UPDATE qm_access_tokens SET expires_at=expires_at+interval '1 hour' WHERE token_hash=$1`, longerHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyAccess(ctx, longer.AccessToken); !errors.Is(err, identity.ErrInvalidCredential) {
		t.Fatal("DB expiry tampering accepted", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE qm_access_tokens SET expires_at=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err := store.PurgeExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyAccess(ctx, token.AccessToken); !errors.Is(err, identity.ErrInvalidCredential) {
		t.Fatal("expired/purged token accepted", err)
	}
}

func TestConcurrentAccessTokensAndScope(t *testing.T) {
	verified := VerifiedCredential{Principal: principal(), ExpiresAt: time.Now().Add(time.Hour)}
	verifier := verifierFunc(func(context.Context, string) (VerifiedCredential, error) { return verified, nil })
	store := testStore(t, verifier)
	ctx := context.Background()
	var group sync.WaitGroup
	tokens := make(chan string, 32)
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			token, err := store.Exchange(ctx, identity.Mobile, "dev_fixture")
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := store.VerifyAccess(ctx, token.AccessToken); err != nil {
				t.Error(err)
			}
			tokens <- token.AccessToken
		}()
	}
	group.Wait()
	close(tokens)
	seen := map[string]bool{}
	for token := range tokens {
		if seen[token] {
			t.Fatal("duplicate random token")
		}
		seen[token] = true
	}
	if len(seen) != 32 {
		t.Fatal("lost concurrent tokens")
	}
	other, err := NewStore(store.pool, "55555555-5555-4555-8555-555555555555", testTenant, bytes.Repeat([]byte{7}, 32), verifier)
	if err != nil {
		t.Fatal(err)
	}
	for token := range seen {
		if _, err := other.VerifyAccess(ctx, token); !errors.Is(err, identity.ErrInvalidCredential) {
			t.Fatal("cross scope token accepted", err)
		}
		break
	}
}

func TestGCMKeyBudgetIsPersistentAndDoesNotBlockExistingTokens(t *testing.T) {
	verified := VerifiedCredential{Principal: principal(), ExpiresAt: time.Now().Add(time.Hour)}
	verifier := verifierFunc(func(context.Context, string) (VerifiedCredential, error) { return verified, nil })
	store := testStore(t, verifier)
	ctx := context.Background()
	if _, err := store.pool.Exec(ctx, `INSERT INTO qm_access_key_usage(key_hash,encryptions) VALUES($1,4294967295)`, store.keyHash[:]); err != nil {
		t.Fatal(err)
	}
	token, err := store.Exchange(ctx, identity.Mobile, "dev_fixture")
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStore(store.pool, testScope, testTenant, bytes.Repeat([]byte{7}, 32), verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Exchange(ctx, identity.Mobile, "dev_fixture"); !errors.Is(err, identity.ErrUnavailable) {
		t.Fatal("exhausted key issued token", err)
	}
	if _, err := restarted.VerifyAccess(ctx, token.AccessToken); err != nil {
		t.Fatal("budget blocked existing valid token", err)
	}
	if err := store.PurgeExpired(ctx); err != nil {
		t.Fatal(err)
	}
	var used int64
	if err := store.pool.QueryRow(ctx, `SELECT encryptions FROM qm_access_key_usage WHERE key_hash=$1`, store.keyHash[:]).Scan(&used); err != nil || used != 4294967296 {
		t.Fatal("budget was reset", err)
	}
}

func TestTokenCanExpireWhileAuthoritativeVerificationIsBlocked(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	calls := 0
	verifier := verifierFunc(func(context.Context, string) (VerifiedCredential, error) {
		calls++
		if calls == 1 {
			return VerifiedCredential{Principal: principal(), ExpiresAt: time.Now().Add(3 * time.Second)}, nil
		}
		close(entered)
		<-release
		return VerifiedCredential{Principal: principal(), ExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	store := testStore(t, verifier)
	ctx := context.Background()
	token, err := store.Exchange(ctx, identity.Mobile, "dev_fixture")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := store.VerifyAccess(ctx, token.AccessToken); done <- err }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("verification did not enter upstream: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("upstream not entered")
	}
	time.Sleep(time.Until(token.ExpiresAt.Add(20 * time.Millisecond)))
	close(release)
	if err := <-done; !errors.Is(err, identity.ErrInvalidCredential) {
		t.Fatal("expired during upstream call but accepted", err)
	}
}

func TestBudgetReservationForcesOnlyItsOwnTransactionDurable(t *testing.T) {
	verified := VerifiedCredential{Principal: principal(), ExpiresAt: time.Now().Add(time.Hour)}
	verifier := verifierFunc(func(context.Context, string) (VerifiedCredential, error) { return verified, nil })
	store := testStore(t, verifier)
	ctx := context.Background()
	_, err := store.pool.Exec(ctx, `CREATE FUNCTION assert_budget_durable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
IF current_setting('synchronous_commit') <> 'on' THEN RAISE EXCEPTION 'budget reservation was asynchronous'; END IF;
RETURN NEW;
END $$;
CREATE TRIGGER budget_durability BEFORE INSERT OR UPDATE ON qm_access_key_usage
FOR EACH ROW EXECUTE FUNCTION assert_budget_durable()`)
	if err != nil {
		t.Fatal(err)
	}
	configuration := store.pool.Config()
	configuration.ConnConfig.RuntimeParams["synchronous_commit"] = "off"
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	other, err := NewStore(pool, testScope, testTenant, bytes.Repeat([]byte{7}, 32), verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Exchange(ctx, identity.Mobile, "dev_fixture"); err != nil {
		t.Fatal("budget trigger rejected nondurable reservation", err)
	}
	var setting string
	if err := pool.QueryRow(ctx, `SHOW synchronous_commit`).Scan(&setting); err != nil || setting != "off" {
		t.Fatal("reservation changed session/global durability configuration", err)
	}
}
