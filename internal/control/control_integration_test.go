//go:build integration

package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/barry-ran/quick-mirror-service/internal/peerloom"
	"github.com/jackc/pgx/v5/pgxpool"
)

const scope = "44444444-4444-4444-8444-444444444444"
const tenant = "11111111-1111-4111-8111-111111111111"
const mobileApp = "22222222-2222-4222-8222-222222222222"
const phone = "33333333-3333-4333-8333-333333333333"
const pc = "55555555-5555-4555-8555-555555555555"
const runtimeBoot = "88888888-8888-4888-8888-888888888888"

var runtimeProof = base64.RawURLEncoding.EncodeToString(make([]byte, 32))

const grantID = "66666666-6666-4666-8666-666666666666"

var owner = identity.Principal{DeviceID: pc, TenantID: tenant, ApplicationID: "77777777-7777-4777-8777-777777777777", Role: identity.PC}

type fakeUpstream struct {
	mu          sync.Mutex
	calls       int
	domain      string
	unknown     bool
	deviceError error
	grant       peerloom.ControlGrant
	session     peerloom.ControlSession
	afterCreate func()
}

func (f *fakeUpstream) ReplayDomain() string { return f.domain }
func (f *fakeUpstream) CreateGrant(_ context.Context, source, target, key string) (peerloom.ControlGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.unknown {
		return peerloom.ControlGrant{}, peerloom.ErrOutcomeUnknown
	}
	f.grant = peerloom.ControlGrant{ID: grantID, TenantID: tenant, SourceDeviceID: source, TargetDeviceID: target, ExpiresAt: time.Now().Add(time.Hour), ExpiryAction: "no_new_connections"}
	if f.afterCreate != nil {
		f.afterCreate()
	}
	return f.grant, nil
}
func (f *fakeUpstream) GetGrant(context.Context, string) (peerloom.ControlGrant, error) {
	return f.grant, nil
}
func (f *fakeUpstream) RevokeGrant(context.Context, string, string) error {
	n := time.Now()
	f.grant.RevokedAt = &n
	return nil
}
func (f *fakeUpstream) GetSession(context.Context, string) (peerloom.ControlSession, error) {
	return f.session, nil
}
func (f *fakeUpstream) GetDevice(context.Context, string) (peerloom.ControlDevice, error) {
	if f.deviceError != nil {
		return peerloom.ControlDevice{}, f.deviceError
	}
	on := true
	return peerloom.ControlDevice{ID: phone, TenantID: tenant, ApplicationID: mobileApp, Status: "active", Online: &on}, nil
}
func testStore(t *testing.T, f *fakeUpstream) *Store {
	t.Helper()
	dsn := os.Getenv("QM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("dedicated QM_TEST_DATABASE_URL required")
	}
	c, e := pgxpool.ParseConfig(dsn)
	if e != nil || !strings.HasSuffix(c.ConnConfig.Database, "_test") {
		t.Fatal("isolated *_test database required")
	}
	ctx := context.Background()
	admin, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	id, e := uuid()
	if e != nil {
		t.Fatal(e)
	}
	schema := "qm_control_" + strings.ReplaceAll(id, "-", "")
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	c.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, e := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); e != nil {
			t.Error(e)
		}
		admin.Close()
	})
	s, e := NewStore(pool, scope, tenant, mobileApp, f)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal("migration repeat", e)
	}
	directory, e := catalog.NewStore(pool, scope, tenant)
	if e != nil {
		t.Fatal(e)
	}
	if e = directory.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	mobile := identity.Principal{DeviceID: phone, TenantID: tenant, ApplicationID: mobileApp, Role: identity.Mobile}
	if e = directory.EnsureRegistration(ctx, mobile); e != nil {
		t.Fatal(e)
	}
	if e = directory.UpdateStatus(ctx, mobile, catalog.Status{BootID: runtimeBoot, Sequence: 1, RuntimeProof: runtimeProof}); e != nil {
		t.Fatal(e)
	}
	return s
}
func command(t *testing.T) string {
	t.Helper()
	v, e := uuid()
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestConcurrentOwnersAndReplay(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "a"}
	s := testStore(t, f)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for n := 0; n < 20; n++ {
		p := owner
		p.DeviceID = command(t)
		key := command(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, created, e := s.Create(ctx, p, phone, key)
			if e == nil && created {
				mu.Lock()
				wins++
				mu.Unlock()
				return
			}
			var ce *Error
			if !errors.As(e, &ce) || ce.Code != "DEVICE_OCCUPIED" {
				t.Errorf("unexpected: %v", e)
			}
		}()
	}
	wg.Wait()
	if wins != 1 || f.calls != 1 {
		t.Fatalf("winners=%d grants=%d", wins, f.calls)
	}
}
func TestUnknownCreateNeverRedispatchedAfterRestartOrDomainChange(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "original", unknown: true}
	s := testStore(t, f)
	key := command(t)
	i, _, e := s.Create(ctx, owner, phone, key)
	if e != nil || i.Outcome != "unknown" {
		t.Fatalf("%+v %v", i, e)
	}
	// Persisted unknown survives an arbitrary elapsed replay window and new credential domain.
	if _, e = s.pool.Exec(ctx, "UPDATE qm_control_intents SET created_at=clock_timestamp()-interval '8 days'"); e != nil {
		t.Fatal(e)
	}
	f.domain = "rotated"
	restarted, e := NewStore(s.pool, scope, tenant, mobileApp, f)
	if e != nil {
		t.Fatal(e)
	}
	again, new, e := restarted.Create(ctx, owner, phone, key)
	if e != nil || new || again.ID != i.ID || f.calls != 1 {
		t.Fatalf("replayed: %+v %v calls=%d", again, e, f.calls)
	}
	if _, _, e = restarted.Create(ctx, owner, phone, command(t)); e == nil {
		t.Fatal("new command bypassed unknown slot")
	}
}
func TestCommandTombstoneAndGenerationOverflow(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "a"}
	s := testStore(t, f)
	key := command(t)
	i, _, e := s.Create(ctx, owner, phone, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE qm_control_intents SET state='released',terminal_at=clock_timestamp()-interval '25 hours' WHERE id=$1`, i.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE qm_control_slots SET active_intent=NULL,generation=9223372036854775807`); e != nil {
		t.Fatal(e)
	}
	_, _, e = s.Create(ctx, owner, phone, key)
	var ce *Error
	if !errors.As(e, &ce) || ce.Code != "UNKNOWN" {
		t.Fatalf("old key: %v", e)
	}
	_, _, e = s.Create(ctx, owner, phone, command(t))
	if !errors.As(e, &ce) || ce.Code != "RESOURCE_EXHAUSTED" {
		t.Fatalf("overflow: %v", e)
	}
	if f.calls != 1 {
		t.Fatal("issued additional grant")
	}
}
func TestScopeAndParticipantIsolation(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "a"}
	s := testStore(t, f)
	key := command(t)
	i, _, e := s.Create(ctx, owner, phone, key)
	if e != nil {
		t.Fatal(e)
	}
	stranger := owner
	stranger.DeviceID = command(t)
	if _, e = s.Get(ctx, stranger, i.ID); e == nil {
		t.Fatal("foreign owner read")
	}
	if _, e = s.ByCommand(ctx, stranger, key); e == nil {
		t.Fatal("foreign key read")
	}
	other, e := NewStore(s.pool, command(t), tenant, mobileApp, f)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = other.Get(ctx, owner, i.ID); e == nil {
		t.Fatal("cross-scope read")
	}
}

func mobilePrincipal() identity.Principal {
	return identity.Principal{DeviceID: phone, TenantID: tenant, ApplicationID: mobileApp, Role: identity.Mobile}
}
func TestUnboundDrainRequiresOriginalRuntime(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "a"}
	s := testStore(t, f)
	i, _, e := s.Create(ctx, owner, phone, command(t))
	if e != nil {
		t.Fatal(e)
	}
	i, e = s.Close(ctx, owner, i.ID, command(t), "user_pc")
	if e != nil || i.State != "draining" || i.DrainToken != "" {
		t.Fatalf("close: %+v %v", i, e)
	}
	current, e := s.Current(ctx, mobilePrincipal())
	if e != nil || current == nil || current.DrainToken == "" {
		t.Fatalf("current: %+v %v", current, e)
	}
	// A token is not enough: another runtime proof cannot ACK, even knowing the original boot UUID.
	bad := base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	_, e = s.Drained(ctx, mobilePrincipal(), i.ID, command(t), i.Generation, "", current.DrainToken, runtimeBoot, bad)
	if e == nil {
		t.Fatal("foreign runtime ACK accepted")
	}
	key := command(t)
	released, e := s.Drained(ctx, mobilePrincipal(), i.ID, key, i.Generation, "", current.DrainToken, runtimeBoot, runtimeProof)
	if e != nil || released.State != "released" {
		t.Fatalf("release %+v %v", released, e)
	}
	replay, e := s.Drained(ctx, mobilePrincipal(), i.ID, key, i.Generation, "", current.DrainToken, runtimeBoot, runtimeProof)
	if e != nil || replay.State != "released" {
		t.Fatal("ACK lost response retry", e)
	}
	empty, e := s.Current(ctx, mobilePrincipal())
	if e != nil || empty != nil {
		t.Fatal("slot not free", e)
	}
}
func TestNewBootCannotDrainOldRuntime(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "a"}
	s := testStore(t, f)
	i, _, e := s.Create(ctx, owner, phone, command(t))
	if e != nil {
		t.Fatal(e)
	}
	directory, e := catalog.NewStore(s.pool, scope, tenant)
	if e != nil {
		t.Fatal(e)
	}
	newBoot := command(t)
	newProof := base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	if e = directory.UpdateStatus(ctx, mobilePrincipal(), catalog.Status{BootID: newBoot, Sequence: 1, RuntimeProof: newProof}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Recover(ctx, ""); e != nil {
		t.Fatal(e)
	}
	current, e := s.Current(ctx, mobilePrincipal())
	if e != nil || current.State != "draining" {
		t.Fatalf("newboot state %+v %v", current, e)
	}
	for _, pair := range [][2]string{{newBoot, newProof}, {runtimeBoot, runtimeProof}} {
		_, e = s.Drained(ctx, mobilePrincipal(), i.ID, command(t), i.Generation, "", current.DrainToken, pair[0], pair[1])
		if e == nil {
			t.Fatal("retired/new boot ACK accepted")
		}
	}
	if _, _, e = s.Create(ctx, owner, phone, command(t)); e == nil {
		t.Fatal("new owner allowed without old runtime proof")
	}
}
func TestUnknownGrantCloseDoesNotIssueChallenge(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "a", unknown: true}
	s := testStore(t, f)
	i, _, e := s.Create(ctx, owner, phone, command(t))
	if e != nil {
		t.Fatal(e)
	}
	i, e = s.Close(ctx, owner, i.ID, command(t), "user_pc")
	if e != nil || i.State != "draining" || i.Outcome != "unknown" {
		t.Fatalf("%+v %v", i, e)
	}
	current, e := s.Current(ctx, mobilePrincipal())
	if e != nil || current.DrainToken != "" {
		t.Fatal("unknown grant received challenge")
	}
	_, e = s.Drained(ctx, mobilePrincipal(), i.ID, command(t), i.Generation, "", command(t), runtimeBoot, runtimeProof)
	if e == nil {
		t.Fatal("unknown grant released")
	}
	if _, e = s.Recover(ctx, ""); e != nil {
		t.Fatal(e)
	}
	if f.calls != 1 {
		t.Fatal("unknown create redispatched")
	}
}
func TestBindExpiredAdmissionWindowAndClose(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "a"}
	s := testStore(t, f)
	i, _, e := s.Create(ctx, owner, phone, command(t))
	if e != nil {
		t.Fatal(e)
	}
	f.grant.ExpiresAt = time.Now().Add(-time.Minute)
	session := command(t)
	f.session = peerloom.ControlSession{ID: session, TenantID: tenant, SourceDeviceID: pc, TargetDeviceID: phone, GrantID: grantID, State: "connecting", SourceLeaseExpiresAt: time.Now().Add(time.Minute), TargetLeaseExpiresAt: time.Now().Add(time.Minute)}
	key := command(t)
	i, e = s.Bind(ctx, mobilePrincipal(), i.ID, key, i.Generation, session, runtimeBoot, runtimeProof)
	if e != nil || i.State != "active" {
		t.Fatalf("expired admission window killed existing session: %+v %v", i, e)
	}
	again, e := s.Bind(ctx, mobilePrincipal(), i.ID, key, i.Generation, session, runtimeBoot, runtimeProof)
	if e != nil || again.Session != session {
		t.Fatal("bind replay", e)
	}
	i, e = s.Close(ctx, owner, i.ID, command(t), "user_pc")
	if e != nil {
		t.Fatal(e)
	}
	current, e := s.Current(ctx, mobilePrincipal())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Drained(ctx, mobilePrincipal(), i.ID, command(t), i.Generation, "", current.DrainToken, runtimeBoot, runtimeProof); e == nil {
		t.Fatal("bound ACK omitted session")
	}
	done, e := s.Drained(ctx, mobilePrincipal(), i.ID, command(t), i.Generation, session, current.DrainToken, runtimeBoot, runtimeProof)
	if e != nil || done.State != "released" {
		t.Fatal("bound drain", e)
	}
}
func TestRuntimeEnrollmentIsIdempotentAndPrivate(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "a"}
	s := testStore(t, f)
	d, e := catalog.NewStore(s.pool, scope, tenant)
	if e != nil {
		t.Fatal(e)
	}
	status := catalog.Status{BootID: runtimeBoot, Sequence: 1, RuntimeProof: runtimeProof}
	if e = d.UpdateStatus(ctx, mobilePrincipal(), status); e != nil {
		t.Fatal("first response lost retry", e)
	}
	status.Sequence = 2
	status.RuntimeProof = base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	if e = d.UpdateStatus(ctx, mobilePrincipal(), status); e == nil {
		t.Fatal("sameboot proof replaced")
	}
	items, e := d.ResolveBatch(ctx, owner, []string{phone})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(items)
	if strings.Contains(string(raw), "runtime_proof") || strings.Contains(string(raw), runtimeProof) {
		t.Fatal("catalog leaked proof")
	}
	i, _, e := s.Create(ctx, owner, phone, command(t))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ = json.Marshal(i)
	if strings.Contains(string(raw), runtimeProof) || strings.Contains(string(raw), "runtime_hash") {
		t.Fatal("intent leaked proof")
	}
}

func TestSameCommandRaceAndCrashAfterGrant(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "a"}
	s := testStore(t, f)
	key := command(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := map[string]bool{}
	for n := 0; n < 20; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i, _, e := s.Create(ctx, owner, phone, key)
			if e != nil {
				t.Error(e)
				return
			}
			mu.Lock()
			ids[i.ID] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(ids) != 1 || f.calls != 1 {
		t.Fatalf("ids=%d calls=%d", len(ids), f.calls)
	}
	// Separate scope/schema: the upstream commits but the request context dies before storing its ID.
	f2 := &fakeUpstream{domain: "a"}
	s2 := testStore(t, f2)
	crashCtx, cancel := context.WithCancel(ctx)
	f2.afterCreate = cancel
	key2 := command(t)
	if _, _, e := s2.Create(crashCtx, owner, phone, key2); e == nil {
		t.Fatal("expected persistence interruption")
	}
	got, e := s2.ByCommand(ctx, owner, key2)
	if e != nil || got.Outcome != "unknown" {
		t.Fatalf("lost outcome %+v %v", got, e)
	}
	f2.afterCreate = nil
	if _, e = s2.Recover(ctx, ""); e != nil {
		t.Fatal(e)
	}
	if f2.calls != 1 {
		t.Fatal("recovery created second grant")
	}
}
func TestBindCloseRaceCannotReopen(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "a"}
	s := testStore(t, f)
	i, _, e := s.Create(ctx, owner, phone, command(t))
	if e != nil {
		t.Fatal(e)
	}
	session := command(t)
	f.session = peerloom.ControlSession{ID: session, TenantID: tenant, SourceDeviceID: pc, TargetDeviceID: phone, GrantID: grantID, State: "connecting", SourceLeaseExpiresAt: time.Now().Add(time.Minute), TargetLeaseExpiresAt: time.Now().Add(time.Minute)}
	// Close before bind's final transaction must reject stale admission.
	if _, e = s.Close(ctx, owner, i.ID, command(t), "user_pc"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Bind(ctx, mobilePrincipal(), i.ID, command(t), i.Generation, session, runtimeBoot, runtimeProof); e == nil {
		t.Fatal("late bind reopened draining")
	}
	got, e := s.Get(ctx, owner, i.ID)
	if e != nil || got.State != "draining" {
		t.Fatal("lost close state", e)
	}
}

func TestRuntimeProofNotReadyIsNotOffline(t *testing.T) {
	ctx := context.Background()
	f := &fakeUpstream{domain: "a"}
	s := testStore(t, f)
	if _, e := s.pool.Exec(ctx, `UPDATE qm_device_catalog SET runtime_proof_hash=NULL`); e != nil {
		t.Fatal(e)
	}
	_, _, e := s.Create(ctx, owner, phone, command(t))
	var ce *Error
	if !errors.As(e, &ce) || ce.Code != "RUNTIME_NOT_READY" || f.calls != 0 {
		t.Fatalf("got=%v calls=%d", e, f.calls)
	}
}

func TestRecoverySkipsPoisonRowButReportsFailure(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, &fakeUpstream{domain: "a"})
	// Two different targets, deliberately ordered: exhausted revision first,
	// recoverable undispatched reservation second. Both lost their old boot.
	first := "10000000-0000-4000-8000-000000000001"
	second := "20000000-0000-4000-8000-000000000002"
	secondPhone := "30000000-0000-4000-8000-000000000003"
	directory, err := catalog.NewStore(s.pool, scope, tenant)
	if err != nil {
		t.Fatal(err)
	}
	mobile := mobilePrincipal()
	mobile.DeviceID = secondPhone
	if err = directory.EnsureRegistration(ctx, mobile); err != nil {
		t.Fatal(err)
	}
	for n, row := range []struct{ id, target string }{{first, phone}, {second, secondPhone}} {
		revision := int64(1)
		if n == 0 {
			revision = 9223372036854775807
		}
		_, err = s.pool.Exec(ctx, `INSERT INTO qm_control_intents(service_scope,id,target_uuid,owner_uuid,runtime_boot,runtime_hash,generation,revision,state,outcome,create_key,revoke_key,replay_domain) VALUES($1,$2,$3,$4,$5,$6,1,$7,'reserving','pending',$8,$9,'a')`, scope, row.id, row.target, pc, command(t), []byte("old-runtime"), revision, command(t), command(t))
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.pool.Exec(ctx, `INSERT INTO qm_control_slots(service_scope,target_uuid,generation,active_intent) VALUES($1,$2,1,$3)`, scope, row.target, row.id)
		if err != nil {
			t.Fatal(err)
		}
	}
	cursor, err := s.Recover(ctx, "")
	var local *Error
	if cursor != "" || !errors.As(err, &local) || local.Code != "RESOURCE_EXHAUSTED" {
		t.Fatalf("cursor=%q err=%v", cursor, err)
	}
	for _, row := range []struct{ id, state string }{{first, "reserving"}, {second, "failed"}} {
		var state string
		if err = s.pool.QueryRow(ctx, `SELECT state FROM qm_control_intents WHERE service_scope=$1 AND id=$2`, scope, row.id).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state != row.state {
			t.Fatalf("%s: state=%s", row.id, state)
		}
	}
	var occupied bool
	if err = s.pool.QueryRow(ctx, `SELECT active_intent IS NOT NULL FROM qm_control_slots WHERE service_scope=$1 AND target_uuid=$2`, scope, phone).Scan(&occupied); err != nil || !occupied {
		t.Fatalf("poison must stay occupied: %v", err)
	}
	// Cancellation and global database failures are not swallowed as row errors.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	cursor, err = s.Recover(canceled, first)
	if cursor != first || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation cursor=%q err=%v", cursor, err)
	}
	if _, err = s.pool.Exec(ctx, `DROP TABLE qm_control_intents`); err != nil {
		t.Fatal(err)
	}
	cursor, err = s.Recover(ctx, first)
	if cursor != first || err == nil {
		t.Fatalf("database failure cursor=%q err=%v", cursor, err)
	}
}

func TestCreateMissingDeviceIsNotTransient(t *testing.T) {
	f := &fakeUpstream{domain: "a", deviceError: peerloom.ErrDeviceNotFound}
	s := testStore(t, f)
	_, _, err := s.Create(context.Background(), owner, phone, command(t))
	var local *Error
	if !errors.As(err, &local) || local.Code != "DEVICE_NOT_FOUND" || local.Status != 404 {
		t.Fatalf("missing device: %v", err)
	}
	f.deviceError = identity.ErrUnavailable
	_, _, err = s.Create(context.Background(), owner, phone, command(t))
	if !errors.Is(err, identity.ErrUnavailable) {
		t.Fatalf("upstream unavailable: %v", err)
	}
	var count int
	if err = s.pool.QueryRow(context.Background(), `SELECT count(*) FROM qm_control_intents`).Scan(&count); err != nil || count != 0 || f.calls != 0 {
		t.Fatalf("must not reserve/create grant: count=%d calls=%d err=%v", count, f.calls, err)
	}
}
