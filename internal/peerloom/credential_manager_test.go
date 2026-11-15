package peerloom

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

const renewalTenant = "11111111-1111-4111-8111-111111111111"
const renewalSubject = "22222222-2222-4222-8222-222222222222"
const renewalOld = "33333333-3333-4333-8333-333333333333"
const renewalNew = "44444444-4444-4444-8444-444444444444"

type fakeRenewal struct {
	oldInvalid            bool
	old, new              ServiceCredentialInfo
	selfError, renewError error
	ops                   []string
	onRenew               func(string)
}

func renewalFixture() *fakeRenewal {
	now := time.Now()
	old := ServiceCredentialInfo{true, renewalSubject, renewalTenant, renewalOld, "admin", now.Add(5 * 24 * time.Hour), now.Add(-time.Hour), now.Add(5 * 24 * time.Hour)}
	n := old
	n.CredentialID = renewalNew
	n.ExpiresAt = now.Add(30 * 24 * time.Hour)
	n.RenewAfter = now.Add(23 * 24 * time.Hour)
	n.EffectiveAcceptUntil = n.ExpiresAt
	return &fakeRenewal{old: old, new: n}
}
func (f *fakeRenewal) Self(_ context.Context, s string) (ServiceCredentialInfo, error) {
	if f.selfError != nil {
		return ServiceCredentialInfo{}, f.selfError
	}
	if s == "old_secret" {
		if f.oldInvalid {
			return ServiceCredentialInfo{}, ErrRenewalRejected
		}
		return f.old, nil
	}
	if s == "new_secret" {
		return f.new, nil
	}
	return ServiceCredentialInfo{}, ErrRenewalRejected
}
func (f *fakeRenewal) Renew(_ context.Context, s, op string) (RenewalResult, error) {
	f.ops = append(f.ops, op)
	if f.onRenew != nil {
		f.onRenew(op)
	}
	if s != "old_secret" {
		return RenewalResult{}, ErrRenewalRejected
	}
	return RenewalResult{f.new, "new_secret", renewalOld, time.Now().Add(24 * time.Hour)}, f.renewError
}
func testManager(f *fakeRenewal) *CredentialManager {
	return &CredentialManager{tenant: renewalTenant, api: f, doc: managedDocument{ServiceCredentialInfo: f.old, ServiceCredential: "old_secret"}, extra: map[string]json.RawMessage{}, now: time.Now, unlock: func() {}, persist: func([]byte) error { return nil }}
}
func TestManagedCredentialDurableBeforeSwitch(t *testing.T) {
	f := renewalFixture()
	m := testManager(f)
	var writes []managedDocument
	m.persist = func(b []byte) error {
		var d managedDocument
		if json.Unmarshal(b, &d) != nil {
			t.Fatal("invalid persistence")
		}
		writes = append(writes, d)
		if len(writes) == 2 {
			if got, _ := m.Read(); got != "old_secret" {
				t.Fatal("published before durable save")
			}
		}
		return nil
	}
	f.onRenew = func(op string) {
		if len(writes) != 1 || writes[0].Operation != op || writes[0].ServiceCredential != "old_secret" {
			t.Fatal("operation not durable before request")
		}
	}
	if err := m.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Read(); got != "new_secret" {
		t.Fatal("not switched")
	}
	if writes[1].Operation != "" || writes[1].ServiceCredential != "new_secret" {
		t.Fatal("journal not cleared")
	}
	if m.Health().Status != "healthy" {
		t.Fatal("unhealthy after success")
	}
}
func TestManagedPersistenceFailureRetainsOperation(t *testing.T) {
	f := renewalFixture()
	m := testManager(f)
	n := 0
	m.persist = func([]byte) error {
		n++
		if n == 2 {
			return errors.New("fixture IO")
		}
		return nil
	}
	if err := m.Step(context.Background()); !errors.Is(err, ErrManagedCredentialStorage) {
		t.Fatal(err)
	}
	if got, _ := m.Read(); got != "old_secret" {
		t.Fatal("failed save published new secret")
	}
	if m.Health().Status != "storage_failed" {
		t.Fatal("failed storage looks healthy")
	}
	if err := m.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.ops) != 1 {
		t.Fatal("known successor should persist without another renewal call")
	}
	if m.Health().Status != "healthy" {
		t.Fatal("recovery did not clear degradation")
	}
}
func TestManagedJournalFailureNeverCallsRenew(t *testing.T) {
	f := renewalFixture()
	m := testManager(f)
	m.persist = func([]byte) error { return errors.New("fixture IO") }
	if m.Step(context.Background()) == nil || len(f.ops) != 0 {
		t.Fatal("renewed without durable journal")
	}
}
func TestManagedUnavailableVsRevoked(t *testing.T) {
	f := renewalFixture()
	m := testManager(f)
	f.selfError = ErrCredentialUnavailable
	if m.Step(context.Background()) == nil {
		t.Fatal("expected network failure")
	}
	if _, err := m.Read(); err != nil {
		t.Fatal("network failure interrupted still-valid credential")
	}
	f.selfError = ErrRenewalRejected
	_ = m.Step(context.Background())
	if _, err := m.Read(); err == nil {
		t.Fatal("revoked credential served")
	}
}
func TestManagedWrongSubjectNeverSwitches(t *testing.T) {
	f := renewalFixture()
	m := testManager(f)
	f.new.SubjectID = renewalNew
	if m.Step(context.Background()) == nil {
		t.Fatal("accepted changed principal")
	}
	if m.doc.ServiceCredential != "old_secret" {
		t.Fatal("changed principal persisted")
	}
}
func TestManagedConcurrentStepsSingleSuccessor(t *testing.T) {
	f := renewalFixture()
	m := testManager(f)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Step(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(f.ops) != 1 {
		t.Fatal("more than one renewal")
	}
}
func TestManagedReplayDomainStableAcrossRenewal(t *testing.T) {
	f := renewalFixture()
	m := testManager(f)
	config := IdentityConfig{"https://fixture.invalid", renewalTenant, "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"}
	c, e := NewControlClientWithSource(config, m, nil, 300)
	if e != nil {
		t.Fatal(e)
	}
	r, e := NewRegistrationClientWithSource(config, m, nil)
	if e != nil {
		t.Fatal(e)
	}
	cd, rd := c.ReplayDomain(), r.ReplayDomain()
	old, e := c.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	if cd != c.ReplayDomain() || rd != r.ReplayDomain() {
		t.Fatal("renewal changed replay domain")
	}
	if old.credential != "old_secret" {
		t.Fatal("in-flight snapshot mutated")
	}
	newSnapshot, _ := c.Snapshot()
	if old.LegacyReplayDomain() == newSnapshot.LegacyReplayDomain() {
		t.Fatal("legacy fingerprint should differ")
	}
}

func TestManagedDelayedRenewalResponseUsesVerifiedSuccessor(t *testing.T) {
	f := renewalFixture()
	m := testManager(f)
	f.onRenew = func(string) { m.now = func() time.Time { return time.Now().Add(26 * time.Hour) } }
	if err := m.Step(context.Background()); err != nil {
		t.Fatal("late response should verify successor rather than require old overlap", err)
	}
	if got, err := m.Read(); got != "new_secret" || err != nil {
		t.Fatal("successor not accepted", err)
	}
}
func TestServiceScopeValidation(t *testing.T) {
	f := renewalFixture()
	v := f.old
	v.Scope = "root"
	if validServiceInfo(v, renewalTenant) {
		t.Fatal("unknown scope accepted")
	}
	v.Scope = "read"
	if !validServiceInfo(v, renewalTenant) {
		t.Fatal("generic read scope rejected")
	}
}

func TestManagedDisabledRenewalDoesNotUpgradeLegacyAuthority(t *testing.T) {
	f := renewalFixture()
	m := testManager(f)
	f.old.RenewalEnabled = false
	if err := m.Step(context.Background()); !errors.Is(err, ErrManagedRenewalDisabled) {
		t.Fatal(err)
	}
	if len(f.ops) != 0 || m.Health().Status != "renewal_disabled" {
		t.Fatal("disabled subject silently upgraded")
	}
	f.old.RenewalEnabled = true
	if err := m.Step(context.Background()); err != nil {
		t.Fatal("operator enable not recovered", err)
	}
}
