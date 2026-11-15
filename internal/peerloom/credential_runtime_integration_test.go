//go:build runtimeintegration && (linux || darwin)

package peerloom

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"
)

type dropCommittedRenewal struct {
	base    http.RoundTripper
	mu      sync.Mutex
	dropped bool
}

func (d *dropCommittedRenewal) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := d.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.URL.Path == "/v1/service-credentials/renew" && response.StatusCode == 200 && !d.dropped {
		d.dropped = true
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return nil, errors.New("synthetic lost response after real server commit")
	}
	return response, nil
}
func TestRealPeerloomRenewalWorker(t *testing.T) {
	directory := os.Getenv("QM_RENEWAL_RUNTIME_DIR")
	if directory == "" {
		t.Skip("requires pinned real Peerloom TLS fixture")
	}
	var meta struct {
		Origin, Schema string
		Tenant         string `json:"tenant_id"`
		Credential     string `json:"credential_id"`
		Application    string `json:"application_id"`
	}
	data, err := os.ReadFile(filepath.Join(directory, "ready.json"))
	if err != nil {
		t.Fatal("fixture metadata missing")
	}
	if json.Unmarshal(data, &meta) != nil || !regexp.MustCompile(`^qm_peerloom_renew_[0-9a-f]{32}$`).MatchString(meta.Schema) {
		t.Fatal("invalid fixture metadata")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(os.Getenv("QM_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("invalid isolated database")
	}
	config.ConnConfig.RuntimeParams["search_path"] = meta.Schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("isolated database unavailable")
	}
	defer pool.Close()
	// Only this fixture's exact initial key is aged into the production renewal window.
	tag, err := pool.Exec(ctx, "UPDATE tenant_service_credentials SET expires_at=clock_timestamp()+interval '10 minutes' WHERE id=$1 AND tenant_id=$2", meta.Credential, meta.Tenant)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("cannot prepare isolated renewal window")
	}
	ca, err := os.ReadFile(filepath.Join(directory, "ca.pem"))
	if err != nil {
		t.Fatal("CA missing")
	}
	// The fixture must fail with default roots; trusted test CA is the only TLS exception.
	untrusted := &http.Client{Timeout: 3 * time.Second}
	response, trustErr := untrusted.Get(meta.Origin + "/v1/service-credentials/self")
	if trustErr == nil {
		response.Body.Close()
		t.Fatal("fixture TLS unexpectedly trusted by default roots")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("CA invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	dropped := &dropCommittedRenewal{base: transport}
	api, err := NewRenewalClient(IdentityConfig{Origin: meta.Origin, TenantID: meta.Tenant, PCApplicationID: meta.Application, MobileApplicationID: "11111111-1111-4111-8111-111111111111"}, &http.Client{Transport: dropped})
	if err != nil {
		t.Fatal("real renewal client configuration invalid")
	}
	file := filepath.Join(directory, "connection.json")
	manager, err := NewCredentialManager(ctx, file, meta.Tenant, api)
	if err != nil {
		t.Fatal("real manager initialization failed")
	}
	old, err := manager.SnapshotCredential()
	if err != nil {
		t.Fatal("missing original snapshot")
	}
	registrationConfig := IdentityConfig{Origin: meta.Origin, TenantID: meta.Tenant, PCApplicationID: meta.Application, MobileApplicationID: "11111111-1111-4111-8111-111111111111"}
	registration, err := NewRegistrationClientWithSource(registrationConfig, manager, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal("registration adapter unavailable")
	}
	domain := registration.ReplayDomain()
	grant, err := registration.Issue(ctx, identity.PC, "runtime-cross-key-replay", 300)
	if err != nil {
		t.Fatal("initial real registration grant failed")
	}
	if manager.Step(ctx) == nil {
		t.Fatal("lost committed response did not fail")
	}
	manager.Close()
	var count int
	if pool.QueryRow(ctx, "SELECT count(*) FROM service_key_renewals WHERE previous_credential_id=$1", meta.Credential).Scan(&count) != nil || count != 1 {
		t.Fatal("expected exactly one committed successor")
	}
	// Restart with its durable operation journal, then exercise the production background worker.
	manager, err = NewCredentialManager(ctx, file, meta.Tenant, api)
	if err != nil {
		t.Fatal("journal restart failed")
	}
	worker, cancelWorker := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); manager.Run(worker, nil) }()
	changed := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, e := manager.SnapshotCredential()
		if e == nil && snapshot.Secret != old.Secret {
			if snapshot.SubjectID != old.SubjectID {
				t.Error("subject identity changed")
			}
			changed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancelWorker()
	<-done
	if !changed {
		manager.Close()
		t.Fatal("real worker did not recover committed renewal")
	}
	successor, _ := manager.SnapshotCredential()
	manager.Close()
	if pool.QueryRow(ctx, "SELECT count(*) FROM service_key_renewals WHERE previous_credential_id=$1", meta.Credential).Scan(&count) != nil || count != 1 {
		t.Fatal("retry created duplicate successor")
	}
	manager, err = NewCredentialManager(ctx, file, meta.Tenant, api)
	if err != nil {
		t.Fatal("successor restart failed")
	}
	defer manager.Close()
	restored, err := manager.SnapshotCredential()
	if err != nil || restored != successor {
		t.Fatal("durable successor mismatch")
	}
	registration, err = NewRegistrationClientWithSource(registrationConfig, manager, &http.Client{Transport: transport})
	if err != nil || registration.ReplayDomain() != domain {
		t.Fatal("stable replay domain changed across key renewal")
	}
	replayed, err := registration.Issue(ctx, identity.PC, "runtime-cross-key-replay", 300)
	if err != nil || replayed.ID != grant.ID || replayed.Grant != grant.Grant || !replayed.ExpiresAt.Equal(grant.ExpiresAt) {
		t.Fatal("real cross-key registration replay mismatch")
	}
	if pool.QueryRow(ctx, "SELECT count(*) FROM registration_grants WHERE tenant_id=$1", meta.Tenant).Scan(&count) != nil || count != 1 {
		t.Fatal("cross-key replay issued duplicate registration grant")
	}
	if _, err = pool.Exec(ctx, "UPDATE service_subjects SET revoked_at=clock_timestamp() WHERE id=$1 AND tenant_id=$2", restored.SubjectID, meta.Tenant); err != nil {
		t.Fatal("fixture revoke failed")
	}
	if !errors.Is(manager.Step(ctx), ErrRenewalRejected) {
		t.Fatal("real revoked subject still accepted")
	}
	if _, err = manager.SnapshotCredential(); err == nil {
		t.Fatal("revoked manager still exposes usable snapshot")
	}
}
