//go:build runtimeintegration

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestVerifiedDatabaseTLSAndHTTPSLifecycle(t *testing.T) {
	dsn := os.Getenv("QM_RUNTIME_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("runtimeintegration requires a dedicated *_test database with verify-full TLS")
	}
	db, err := databaseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(db.ConnConfig.Database, "_test") {
		t.Fatal("refusing non-test database")
	}
	ctx := context.Background()
	admin, err := pgxpool.NewWithConfig(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	schema := "qm_runtime_" + hex.EncodeToString(random[:])
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Error(err)
		}
	}()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid fixture DSN")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	fixtureConfig(t)
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	c.Database = u.String()
	verifyReleased := prepareReleasedRuntime(t, &c)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	c.CertificateFile = filepath.Join(dir, "server.crt")
	c.KeyFile = filepath.Join(dir, "server.key")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if os.WriteFile(c.CertificateFile, certificate, 0600) != nil || os.WriteFile(c.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}), 0600) != nil {
		t.Fatal("fixture key write failed")
	}
	if err := serve(ctx, c, true); err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	// 必需的boot去重表缺失时不得启动一个表面健康但状态上报必败的进程。
	if _, err := admin.Exec(ctx, `ALTER TABLE `+schema+`.qm_device_boots RENAME TO qm_device_boots_absent`); err != nil {
		t.Fatal(err)
	}
	missingCtx, missingCancel := context.WithTimeout(ctx, time.Second)
	missingErr := serve(missingCtx, c, false)
	missingCancel()
	if missingErr == nil || missingErr.Error() != "MIGRATION_REQUIRED" {
		t.Fatal("missing boot table did not fail closed")
	}
	if _, err := admin.Exec(ctx, `ALTER TABLE `+schema+`.qm_device_boots_absent RENAME TO qm_device_boots`); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.Address = listener.Addr().String()
	listener.Close()
	running, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { defer close(done); done <- serve(running, c, false) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("runtime cleanup failed: %v", err)
			}
		case <-time.After(16 * time.Second):
			t.Error("runtime cleanup deadline exceeded")
		}
	}()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certificate)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		response, err := client.Post("https://"+c.Address+"/qm/v1/bootstrap/pc", "application/json", strings.NewReader(`{}`))
		if err == nil {
			response.Body.Close()
			if response.StatusCode != 400 {
				t.Errorf("unexpected runtime status %d", response.StatusCode)
			}
			ready = true
			break
		}
		select {
		case err := <-done:
			t.Fatalf("server exited early: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		cancel()
		<-done
		t.Fatal("HTTPS readiness failed")
	}
	if verifyReleased != nil {
		verifyReleased(client, "https://"+c.Address)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
}
