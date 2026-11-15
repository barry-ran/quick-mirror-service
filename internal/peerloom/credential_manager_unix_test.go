//go:build linux || darwin

package peerloom

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagedRestartRecoversSameOperation(t *testing.T) {
	f := renewalFixture()
	p := filepath.Join(privateCredentialDir(t), "connection.json")
	if err := os.WriteFile(p, []byte("old_secret"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := NewCredentialManager(context.Background(), p, renewalTenant, f)
	if err != nil {
		t.Fatal(err)
	}
	f.renewError = ErrCredentialUnavailable
	if m.Step(context.Background()) == nil {
		t.Fatal("expected lost response")
	}
	op := f.ops[0]
	m.Close()
	f.renewError = nil
	m, err = NewCredentialManager(context.Background(), p, renewalTenant, f)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = m.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.ops) != 2 || f.ops[1] != op {
		t.Fatal("restart lost operation")
	}
	data, _ := os.ReadFile(p)
	var d managedDocument
	_ = json.Unmarshal(data, &d)
	if d.ServiceCredential != "new_secret" || d.Operation != "" {
		t.Fatal("wrong persisted result")
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0600 {
		t.Fatal("credential file not private")
	}
}
func TestManagedDirectoryLockAndPrivateMode(t *testing.T) {
	f := renewalFixture()
	dir := privateCredentialDir(t)
	p := filepath.Join(dir, "key")
	_ = os.WriteFile(p, []byte("old_secret"), 0600)
	m, err := NewCredentialManager(context.Background(), p, renewalTenant, f)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err = NewCredentialManager(context.Background(), p, renewalTenant, f); !errors.Is(err, ErrManagedCredentialStorage) {
		t.Fatal("second writer accepted", err)
	}
	m.Close()
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = NewCredentialManager(context.Background(), p, renewalTenant, f); !errors.Is(err, ErrManagedCredentialStorage) {
		t.Fatal("non-private directory accepted", err)
	}
}
func TestManagedRejectsMismatchedJournal(t *testing.T) {
	f := renewalFixture()
	p := filepath.Join(privateCredentialDir(t), "key")
	doc := managedDocument{ServiceCredentialInfo: f.old, ServiceCredential: "old_secret", Operation: renewalNew, OperationCredential: renewalNew, OperationSubject: renewalSubject}
	b, _ := json.Marshal(doc)
	_ = os.WriteFile(p, b, 0600)
	if _, err := NewCredentialManager(context.Background(), p, renewalTenant, f); !errors.Is(err, ErrManagedCredentialJournal) {
		t.Fatal(err)
	}
}

func TestManagedExternalFileChangeFailsClosed(t *testing.T) {
	f := renewalFixture()
	p := filepath.Join(privateCredentialDir(t), "key")
	_ = os.WriteFile(p, []byte("old_secret"), 0600)
	m, err := NewCredentialManager(context.Background(), p, renewalTenant, f)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	saved, _ := os.ReadFile(p)
	if err = os.WriteFile(p, []byte("different_secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Read(); !errors.Is(err, ErrManagedCredentialStorage) {
		t.Fatal("served cached credential after external replacement")
	}
	if m.Health().Status != "storage_changed" {
		t.Fatal("false healthy")
	}
	if err = m.Step(context.Background()); !errors.Is(err, ErrManagedCredentialStorage) || len(f.ops) != 0 {
		t.Fatal("overwrote external change")
	}
	_ = os.WriteFile(p, saved, 0600)
	if _, err = m.Read(); err != nil {
		t.Fatal("exact recovery not accepted", err)
	}
	_ = os.Remove(p)
	if _, err = m.Read(); err == nil {
		t.Fatal("missing file accepted")
	}
}
func TestManagedRestartAfterRenameBeforeDirectorySync(t *testing.T) {
	f := renewalFixture()
	p := filepath.Join(privateCredentialDir(t), "key")
	_ = os.WriteFile(p, []byte("old_secret"), 0600)
	m, err := NewCredentialManager(context.Background(), p, renewalTenant, f)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	m.persist = func(data []byte) error {
		n++
		if err := persistCredential(p, data); err != nil {
			return err
		}
		if n == 2 {
			return errors.New("fixture directory sync failure")
		}
		return nil
	}
	if err = m.Step(context.Background()); !errors.Is(err, ErrManagedCredentialStorage) {
		t.Fatal(err)
	}
	if got, err := m.Read(); got != "old_secret" || err != nil {
		t.Fatal("old in-memory snapshot not retained", err)
	}
	m.Close()
	m, err = NewCredentialManager(context.Background(), p, renewalTenant, f)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if got, err := m.Read(); got != "new_secret" || err != nil {
		t.Fatal("restart did not authenticate durable successor", err)
	}
	if err = m.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.ops) != 1 {
		t.Fatal("restart created another successor")
	}
}

func privateCredentialDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestManagedDurableSuccessorRecoversAfterOldOverlapExpires(t *testing.T) {
	f := renewalFixture()
	p := filepath.Join(privateCredentialDir(t), "key")
	_ = os.WriteFile(p, []byte("old_secret"), 0600)
	m, err := NewCredentialManager(context.Background(), p, renewalTenant, f)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	n := 0
	m.persist = func(data []byte) error {
		n++
		if err := persistCredential(p, data); err != nil {
			return err
		}
		if n == 2 {
			return errors.New("fixture directory sync failure")
		}
		return nil
	}
	if err = m.Step(context.Background()); !errors.Is(err, ErrManagedCredentialStorage) {
		t.Fatal(err)
	}
	m.now = func() time.Time { return time.Now().Add(26 * time.Hour) }
	f.oldInvalid = true
	if err = m.Step(context.Background()); err != nil {
		t.Fatal("failed to recover known successor after old key expiry", err)
	}
	if got, err := m.Read(); got != "new_secret" || err != nil {
		t.Fatal("successor not published", err)
	}
	if len(f.ops) != 1 || m.Health().Status != "healthy" {
		t.Fatal("recovery forked or stayed degraded")
	}
}

func TestManagedDisabledSubjectRejectedAtStartup(t *testing.T) {
	f := renewalFixture()
	f.old.RenewalEnabled = false
	p := filepath.Join(privateCredentialDir(t), "key")
	_ = os.WriteFile(p, []byte("old_secret"), 0600)
	if _, err := NewCredentialManager(context.Background(), p, renewalTenant, f); !errors.Is(err, ErrManagedRenewalDisabled) {
		t.Fatal(err)
	}
}
