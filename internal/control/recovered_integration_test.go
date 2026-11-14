//go:build integration

package control

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/barry-ran/quick-mirror-service/internal/peerloom"
)

func boundRecoveryFixture(t *testing.T) (*Store, *fakeUpstream, Intent) {
	t.Helper()
	ctx := context.Background()
	f := &fakeUpstream{domain: "a"}
	s := testStore(t, f)
	i, _, err := s.Create(ctx, owner, phone, command(t))
	if err != nil {
		t.Fatal(err)
	}
	session := command(t)
	f.session = peerloom.ControlSession{ID: session, TenantID: tenant, SourceDeviceID: pc, TargetDeviceID: phone, GrantID: grantID, State: "connecting", SourceLeaseExpiresAt: time.Now().Add(time.Minute), TargetLeaseExpiresAt: time.Now().Add(time.Minute)}
	i, err = s.Bind(ctx, mobilePrincipal(), i.ID, command(t), i.Generation, session, runtimeBoot, runtimeProof)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, i
}
func replaceRecoveryRuntime(t *testing.T, s *Store) (string, string, *catalog.Store) {
	t.Helper()
	directory, err := catalog.NewStore(s.pool, scope, tenant)
	if err != nil {
		t.Fatal(err)
	}
	boot := command(t)
	proof := base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	if err = directory.UpdateStatus(context.Background(), mobilePrincipal(), catalog.Status{BootID: boot, Sequence: 1, RuntimeProof: proof}); err != nil {
		t.Fatal(err)
	}
	return boot, proof, directory
}
func recoveryChallenge(t *testing.T, s *Store, id string) Intent {
	t.Helper()
	if _, err := s.Recover(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	i, err := s.Get(context.Background(), mobilePrincipal(), id)
	if err != nil || i.State != "draining" || i.DrainToken == "" || !i.revoked {
		t.Fatalf("not ready: %+v %v", i, err)
	}
	return i
}
func TestBoundRecoveryNewRuntimeReleasesAndReplayPreservesNewSlot(t *testing.T) {
	s, _, i := boundRecoveryFixture(t)
	boot, proof, directory := replaceRecoveryRuntime(t, s)
	i = recoveryChallenge(t, s, i.ID)
	if i.PreviousBootID != runtimeBoot {
		t.Fatal("missing immutable boot")
	}
	key := command(t)
	got, err := s.Recovered(context.Background(), mobilePrincipal(), i.ID, key, i.Generation, i.Session, i.DrainToken, boot, proof)
	if err != nil || got.State != "released" {
		t.Fatalf("recovery failed: %+v %v", got, err)
	}
	next, _, err := s.Create(context.Background(), owner, phone, command(t))
	if err != nil || next.Generation == i.Generation {
		t.Fatal("new session blocked", err)
	}
	// A later runtime must not make the old idempotent response mutate a new slot.
	replaceRecoveryRuntime(t, s)
	again, err := s.Recovered(context.Background(), mobilePrincipal(), i.ID, key, i.Generation, i.Session, i.DrainToken, boot, proof)
	if err != nil || again.ID != i.ID || again.State != "released" {
		t.Fatal("lost response replay", err)
	}
	if _, err = s.Recovered(context.Background(), mobilePrincipal(), i.ID, key, i.Generation, i.Session, command(t), boot, proof); err == nil {
		t.Fatal("changed replay body accepted")
	}
	current, err := s.Current(context.Background(), mobilePrincipal())
	if err != nil || current == nil || current.ID != next.ID {
		t.Fatal("old recovery cleared new slot", err)
	}
	if err = directory.UpdateStatus(context.Background(), mobilePrincipal(), catalog.Status{BootID: runtimeBoot, Sequence: 99, RuntimeProof: runtimeProof}); !errors.Is(err, catalog.ErrStaleStatus) {
		t.Fatal("old status revived", err)
	}
}
func TestBoundRecoveryRejectsWrongTupleRuntimeAndPrincipal(t *testing.T) {
	s, _, i := boundRecoveryFixture(t)
	boot, proof, _ := replaceRecoveryRuntime(t, s)
	i = recoveryChallenge(t, s, i.ID)
	type attempt struct {
		name                             string
		p                                identity.Principal
		gen, session, token, boot, proof string
	}
	foreign := mobilePrincipal()
	foreign.DeviceID = command(t)
	foreignTenant := mobilePrincipal()
	foreignTenant.TenantID = command(t)
	cases := []attempt{
		{"same boot", mobilePrincipal(), i.Generation, i.Session, i.DrainToken, runtimeBoot, runtimeProof},
		{"wrong proof", mobilePrincipal(), i.Generation, i.Session, i.DrainToken, boot, runtimeProof},
		{"unknown boot", mobilePrincipal(), i.Generation, i.Session, i.DrainToken, command(t), proof},
		{"generation", mobilePrincipal(), "999", i.Session, i.DrainToken, boot, proof},
		{"session", mobilePrincipal(), i.Generation, command(t), i.DrainToken, boot, proof},
		{"empty session", mobilePrincipal(), i.Generation, "", i.DrainToken, boot, proof},
		{"token", mobilePrincipal(), i.Generation, i.Session, command(t), boot, proof},
		{"PC", owner, i.Generation, i.Session, i.DrainToken, boot, proof},
		{"foreign phone", foreign, i.Generation, i.Session, i.DrainToken, boot, proof},
		{"foreign tenant", foreignTenant, i.Generation, i.Session, i.DrainToken, boot, proof},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := s.Recovered(context.Background(), c.p, i.ID, command(t), c.gen, c.session, c.token, c.boot, c.proof); err == nil {
				t.Fatal("invalid recovery accepted")
			}
		})
	}
	if _, err := s.Drained(context.Background(), mobilePrincipal(), i.ID, command(t), i.Generation, i.Session, i.DrainToken, boot, proof); err == nil {
		t.Fatal("normal drain accepted new boot")
	}
	got, err := s.Get(context.Background(), mobilePrincipal(), i.ID)
	if err != nil || got.State != "draining" {
		t.Fatal("rejected operation released slot", err)
	}
	newer, _, _ := replaceRecoveryRuntime(t, s)
	if newer == boot {
		t.Fatal("test collision")
	}
	if _, err = s.Recovered(context.Background(), mobilePrincipal(), i.ID, command(t), i.Generation, i.Session, i.DrainToken, boot, proof); err == nil {
		t.Fatal("superseded new runtime accepted")
	}
}
func TestBoundRecoveryRejectsBeforeRevocationAndKeepsNormalDrain(t *testing.T) {
	s, f, i := boundRecoveryFixture(t)
	f.refuseRevoke = true
	boot, proof, _ := replaceRecoveryRuntime(t, s)
	// A failed revoke may be surfaced by the bounded recovery pass. The slot stays occupied.
	_, _ = s.Recover(context.Background(), "")
	got, err := s.Get(context.Background(), mobilePrincipal(), i.ID)
	if err != nil || got.revoked || got.DrainToken != "" {
		t.Fatal("unverified grant acquired challenge", err)
	}
	if _, err = s.Recovered(context.Background(), mobilePrincipal(), i.ID, command(t), i.Generation, i.Session, command(t), boot, proof); err == nil {
		t.Fatal("unrevoked recovery accepted")
	}
	s2, _, normal := boundRecoveryFixture(t)
	if _, err = s2.Close(context.Background(), owner, normal.ID, command(t), "user_pc"); err != nil {
		t.Fatal(err)
	}
	normal, err = s2.Get(context.Background(), mobilePrincipal(), normal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s2.Recovered(context.Background(), mobilePrincipal(), normal.ID, command(t), normal.Generation, normal.Session, normal.DrainToken, runtimeBoot, runtimeProof); err == nil {
		t.Fatal("same runtime used recovery shortcut")
	}
	done, err := s2.Drained(context.Background(), mobilePrincipal(), normal.ID, command(t), normal.Generation, normal.Session, normal.DrainToken, runtimeBoot, runtimeProof)
	if err != nil || done.State != "released" {
		t.Fatal("normal drain regressed", err)
	}
}
func TestBoundRecoveryRuntimeRowPinnedUntilTransactionEnds(t *testing.T) {
	s, _, i := boundRecoveryFixture(t)
	boot, proof, directory := replaceRecoveryRuntime(t, s)
	i = recoveryChallenge(t, s, i.ID)
	tx, err := s.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err = s.recoveryRuntime(context.Background(), tx, i, boot, proof); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	err = directory.UpdateStatus(ctx, mobilePrincipal(), catalog.Status{BootID: command(t), Sequence: 1, RuntimeProof: proof})
	cancel()
	if err == nil {
		t.Fatal("catalog changed while release transaction held runtime share lock")
	}
	if err = tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = directory.UpdateStatus(context.Background(), mobilePrincipal(), catalog.Status{BootID: command(t), Sequence: 1, RuntimeProof: proof}); err != nil {
		t.Fatal("catalog stayed blocked after rollback", err)
	}
}
