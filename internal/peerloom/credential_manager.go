package peerloom

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"io"
	"path/filepath"
	"sync"
	"time"
)

var ErrManagedCredentialUnsupported = errors.New("PEERLOOM_MANAGED_CREDENTIAL_UNSUPPORTED")
var ErrManagedCredentialStorage = errors.New("PEERLOOM_MANAGED_CREDENTIAL_STORAGE_UNAVAILABLE")
var ErrManagedCredentialJournal = errors.New("PEERLOOM_RENEWAL_JOURNAL_INVALID")

type CredentialSnapshot struct{ Secret, SubjectID string }
type managedDocument struct {
	ServiceCredentialInfo
	ServiceCredential   string `json:"service_credential"`
	Operation           string `json:"qm_renewal_operation,omitempty"`
	OperationCredential string `json:"qm_renewal_credential_id,omitempty"`
	OperationSubject    string `json:"qm_renewal_subject_id,omitempty"`
}

// CredentialManager owns one private file. Only its worker writes; requests take immutable snapshots.
type CredentialManager struct {
	storage      sync.RWMutex
	expected     map[[32]byte]bool
	status       string
	mu           sync.RWMutex
	step         sync.Mutex
	path, tenant string
	api          RenewalAPI
	doc          managedDocument
	extra        map[string]json.RawMessage
	unlock       func()
	now          func() time.Time
	persist      func([]byte) error
	rejected     bool
}

func NewCredentialManager(ctx context.Context, path, tenant string, api RenewalAPI) (*CredentialManager, error) {
	if api == nil || !filepath.IsAbs(path) {
		return nil, ErrManagedCredentialStorage
	}
	unlock, err := lockCredentialDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			unlock()
		}
	}()
	f, err := openCredentialFile(path)
	if err != nil {
		return nil, ErrManagedCredentialStorage
	}
	fileInfo, statErr := f.Stat()
	if statErr != nil || !validManagedFile(fileInfo) {
		f.Close()
		return nil, ErrManagedCredentialStorage
	}
	data, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	f.Close()
	if err != nil || len(data) > 16<<10 {
		return nil, ErrManagedCredentialStorage
	}
	secret, err := parseCredential(data)
	if err != nil {
		return nil, err
	}
	info, err := api.Self(ctx, secret)
	if err != nil {
		return nil, err
	}
	if !validServiceInfo(info, tenant) || !time.Now().Before(info.EffectiveAcceptUntil) {
		return nil, ErrRenewalRejected
	}
	extra := map[string]json.RawMessage{}
	var old managedDocument
	if json.Unmarshal(data, &extra) == nil {
		if json.Unmarshal(data, &old) != nil {
			return nil, ErrManagedCredentialJournal
		}
	}
	if old.Operation != "" {
		if _, ok := identity.NormalizeUUID(old.Operation); !ok {
			return nil, ErrManagedCredentialJournal
		}
	}
	if old.Operation != "" && (old.OperationCredential != info.CredentialID || old.OperationSubject != info.SubjectID) {
		return nil, ErrManagedCredentialJournal
	}
	if old.Operation == "" && (old.OperationCredential != "" || old.OperationSubject != "") {
		return nil, ErrManagedCredentialJournal
	}
	m := &CredentialManager{path: path, tenant: tenant, api: api, extra: extra, unlock: unlock, now: time.Now, expected: map[[32]byte]bool{sha256.Sum256(data): true}}
	m.doc = managedDocument{ServiceCredentialInfo: info, ServiceCredential: secret, Operation: old.Operation, OperationCredential: old.OperationCredential, OperationSubject: old.OperationSubject}
	m.persist = func(data []byte) error { return persistCredential(path, data) }
	// Prove durable writable storage before reporting a healthy automatic service.
	if err = m.save(m.doc); err != nil {
		return nil, err
	}
	ok = true
	return m, nil
}
func (m *CredentialManager) Close() {
	m.step.Lock()
	defer m.step.Unlock()
	if m.unlock != nil {
		m.unlock()
		m.unlock = nil
		m.mu.Lock()
		m.rejected = true
		m.mu.Unlock()
	}
}
func (m *CredentialManager) Read() (string, error) {
	s, e := m.SnapshotCredential()
	return s.Secret, e
}
func (m *CredentialManager) SnapshotCredential() (CredentialSnapshot, error) {
	if m.checkStorage() != nil {
		return CredentialSnapshot{}, ErrManagedCredentialStorage
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.rejected || !m.now().Before(m.doc.EffectiveAcceptUntil) {
		return CredentialSnapshot{}, ErrCredentialUnavailable
	}
	return CredentialSnapshot{m.doc.ServiceCredential, m.doc.SubjectID}, nil
}
func (m *CredentialManager) save(d managedDocument) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return ErrManagedCredentialStorage
	}
	fields := map[string]json.RawMessage{}
	for k, v := range m.extra {
		fields[k] = v
	}
	// Journal fields must be removed on completed rotation rather than inherited from setup JSON.
	delete(fields, "qm_renewal_operation")
	delete(fields, "qm_renewal_credential_id")
	delete(fields, "qm_renewal_subject_id")
	var values map[string]json.RawMessage
	_ = json.Unmarshal(raw, &values)
	for k, v := range values {
		fields[k] = v
	}
	raw, err = json.Marshal(fields)
	if err != nil || len(raw) > 16<<10 {
		return ErrManagedCredentialStorage
	}
	raw = append(raw, '\n')
	m.storage.Lock()
	defer m.storage.Unlock()
	if m.persist(raw) != nil {
		// A failed directory fsync may follow a successful rename. Accept only our exact attempted document, never arbitrary external edits.
		if m.expected == nil {
			m.expected = map[[32]byte]bool{}
		}
		m.expected[sha256.Sum256(raw)] = true
		return ErrManagedCredentialStorage
	}
	m.expected = map[[32]byte]bool{sha256.Sum256(raw): true}
	return nil
}
func operationID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrManagedCredentialStorage
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// Step never abandons a pending operation or switches secrets before durable persistence.
func (m *CredentialManager) Step(ctx context.Context) (result error) {
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.status = "healthy"
		if result != nil {
			m.status = "renewal_pending"
		}
		if errors.Is(result, ErrManagedCredentialStorage) {
			m.status = "storage_failed"
		}
		if errors.Is(result, ErrRenewalRejected) {
			m.status = "rejected"
		}
		if errors.Is(result, ErrManagedCredentialJournal) || errors.Is(result, ErrRenewalJournalConflict) || errors.Is(result, ErrRenewalUnavailable) {
			m.status = "journal_invalid"
		}
	}()
	m.step.Lock()
	defer m.step.Unlock()
	if m.checkStorage() != nil {
		return ErrManagedCredentialStorage
	}
	if m.unlock == nil {
		return ErrRenewalRejected
	}
	m.mu.RLock()
	d := m.doc
	rejected := m.rejected
	m.mu.RUnlock()
	if rejected {
		return ErrRenewalRejected
	}
	info, err := m.api.Self(ctx, d.ServiceCredential)
	if err != nil {
		if errors.Is(err, ErrRenewalRejected) {
			m.mu.Lock()
			m.rejected = true
			m.mu.Unlock()
		}
		return err
	}
	if !validServiceInfo(info, m.tenant) || info.SubjectID != d.SubjectID || info.CredentialID != d.CredentialID || info.Scope != d.Scope {
		return ErrRenewalRejected
	}
	d.ServiceCredentialInfo = info
	m.mu.Lock()
	m.doc.ServiceCredentialInfo = info
	m.mu.Unlock()
	if !m.now().Before(info.EffectiveAcceptUntil) {
		return ErrRenewalRejected
	}
	if d.Operation == "" && m.now().Before(info.RenewAfter) {
		return nil
	}
	if d.Operation == "" {
		d.Operation, err = operationID()
		if err != nil {
			return err
		}
		d.OperationCredential = d.CredentialID
		d.OperationSubject = d.SubjectID
		if err = m.save(d); err != nil {
			return err
		}
		m.mu.Lock()
		m.doc = d
		m.mu.Unlock()
	}
	next, err := m.api.Renew(ctx, d.ServiceCredential, d.Operation)
	if err != nil {
		return err
	}
	if next.SubjectID != d.SubjectID || next.TenantID != d.TenantID || next.Scope != d.Scope || next.PreviousCredentialID != d.CredentialID || next.CredentialID == d.CredentialID || !m.now().Before(next.PreviousAcceptUntil) {
		return ErrRenewalRejected
	}
	checked, err := m.api.Self(ctx, next.ServiceCredential)
	if err != nil {
		return err
	}
	if !validServiceInfo(checked, m.tenant) || checked.SubjectID != d.SubjectID || checked.CredentialID != next.CredentialID || checked.Scope != d.Scope || !m.now().Before(checked.EffectiveAcceptUntil) {
		return ErrRenewalRejected
	}
	replacement := managedDocument{ServiceCredentialInfo: checked, ServiceCredential: next.ServiceCredential}
	if err = m.save(replacement); err != nil {
		return err
	}
	m.mu.Lock()
	m.doc = replacement
	m.mu.Unlock()
	return nil
}

// Run checks revocation and renewal regularly. Logs contain status codes only, never API bodies.
func (m *CredentialManager) Run(ctx context.Context, report func(string)) {
	delay := time.Duration(0)
	failures := 0
	last := ""
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		call, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := m.Step(call)
		cancel()
		code := "PEERLOOM_CREDENTIAL_HEALTHY"
		if err != nil {
			code = "PEERLOOM_CREDENTIAL_RENEWAL_PENDING"
			failures++
			if errors.Is(err, ErrRenewalRejected) {
				code = "PEERLOOM_CREDENTIAL_RENEWAL_REJECTED"
			}
			if errors.Is(err, ErrRenewalJournalConflict) || errors.Is(err, ErrRenewalUnavailable) {
				code = "PEERLOOM_CREDENTIAL_RENEWAL_REQUIRES_RECOVERY"
			}
			if errors.Is(err, ErrManagedCredentialStorage) {
				code = "PEERLOOM_CREDENTIAL_STORAGE_FAILED"
			}
		} else {
			failures = 0
		}
		if report != nil && (code != last || failures > 0) {
			report(code)
		}
		last = code
		delay = time.Minute
		if failures > 0 {
			shift := failures
			if shift > 5 {
				shift = 5
			}
			delay = time.Duration(1<<shift) * time.Second
		}
		var random [1]byte
		_, _ = rand.Read(random[:])
		delay += time.Duration(random[0]) * time.Millisecond * 20
	}
}

// CredentialHealth contains no bearer material or upstream response body.
type CredentialHealth struct {
	Status           string `json:"status"`
	SubjectID        string `json:"subject_id,omitempty"`
	CredentialID     string `json:"credential_id,omitempty"`
	RemainingSeconds int64  `json:"remaining_seconds"`
}

func (m *CredentialManager) Health() CredentialHealth {
	storageErr := m.checkStorage()
	m.mu.RLock()
	defer m.mu.RUnlock()
	status := m.status
	if status == "" {
		status = "healthy"
	}
	seconds := int64(m.doc.EffectiveAcceptUntil.Sub(m.now()).Seconds())
	if seconds <= 0 {
		status = "expired"
	} else if seconds < 3600 && status == "healthy" {
		status = "expiring"
	}
	if storageErr != nil {
		status = "storage_changed"
	}
	return CredentialHealth{status, m.doc.SubjectID, m.doc.CredentialID, seconds}
}

func (m *CredentialManager) checkStorage() error {
	if m.path == "" {
		return nil
	} // In-memory test backend, never production.
	m.storage.RLock()
	defer m.storage.RUnlock()
	f, err := openCredentialFile(m.path)
	if err != nil {
		return ErrManagedCredentialStorage
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !validManagedFile(info) {
		return ErrManagedCredentialStorage
	}
	data, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	if err != nil || len(data) > 16<<10 || !m.expected[sha256.Sum256(data)] {
		return ErrManagedCredentialStorage
	}
	return nil
}
