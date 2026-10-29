package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixtureConfig(t *testing.T) {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "access-key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QM_ACCESS_KEY_FILE", keyFile)
	t.Setenv("QM_API_CONCURRENCY", "")
	values := map[string]string{
		"QM_DATABASE_URL":                "postgres://fixture:private-fixture@localhost/quickmirror_test?sslmode=verify-full",
		"QM_PEERLOOM_SERVICE_CREDENTIAL": "svc_fixture",
		"QM_PEERLOOM_ORIGIN":             "https://peerloom.example",
		"QM_TENANT_ID":                   "11111111-1111-4111-8111-111111111111",
		"QM_SERVICE_SCOPE":               "22222222-2222-4222-8222-222222222222",
		"QM_PC_APPLICATION_ID":           "33333333-3333-4333-8333-333333333333",
		"QM_MOBILE_APPLICATION_ID":       "44444444-4444-4444-8444-444444444444",
		"QM_TLS_CERT_FILE":               "fixture.crt", "QM_TLS_KEY_FILE": "fixture.key",
		"QM_LISTEN_ADDRESS": "", "QM_BOOTSTRAP_CONCURRENCY": "", "QM_BOOTSTRAP_BURST": "", "QM_BOOTSTRAP_RATE": "",
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
}

func TestConfigurationDefaultsAndValidation(t *testing.T) {
	fixtureConfig(t)
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.Address != "127.0.0.1:8443" || c.HTTP.MaxConcurrent != 16 || c.HTTP.Burst != 20 || c.HTTP.RequestsPerSecond != 2 {
		t.Fatal("unsafe default listener or incorrect request budgets")
	}
	for _, tc := range []struct{ key, value string }{{"QM_API_CONCURRENCY", "4097"}, {"QM_ACCESS_KEY_FILE", ""}, {"QM_BOOTSTRAP_RATE", "NaN"}, {"QM_BOOTSTRAP_CONCURRENCY", "0"}, {"QM_BOOTSTRAP_BURST", "100001"}, {"QM_LISTEN_ADDRESS", "invalid"}, {"QM_SERVICE_SCOPE", "bad"}, {"QM_PEERLOOM_ORIGIN", "http://peerloom.example"}, {"QM_PEERLOOM_SERVICE_CREDENTIAL", "private fixture"}, {"QM_TLS_KEY_FILE", ""}, {"QM_DATABASE_URL", ""}} {
		t.Run(tc.key, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if _, err := loadConfig(); err == nil {
				t.Fatal("invalid config accepted")
			} else if strings.Contains(err.Error(), "private") {
				t.Fatal("configuration error leaked input")
			}
		})
	}
}

func TestDatabaseRequiresVerifiedTLS(t *testing.T) {
	for _, mode := range []string{"disable", "allow", "prefer", "require", "verify-ca"} {
		if _, err := databaseConfig("postgres://fixture:private-fixture@localhost/quickmirror_test?sslmode=" + mode); err == nil {
			t.Fatalf("accepted mode %s", mode)
		}
	}
	c, err := databaseConfig("postgres://fixture:private-fixture@localhost/quickmirror_test?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxConns != 16 || c.ConnConfig.TLSConfig == nil || c.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("database TLS/pool not constrained")
	}
	if _, err := databaseConfig("postgres://%private-secret"); err == nil || strings.Contains(err.Error(), "private-secret") {
		t.Fatal("bad DSN leaked")
	}
}

func TestAccessKeyFileValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	good := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
	for _, value := range []string{good, good + "\n", good + "\r\n"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		key, err := readAccessKey(path)
		if err != nil || len(key) != 32 {
			t.Fatal("valid private key rejected")
		}
	}
	for _, value := range []string{"", "private-secret", strings.Repeat("A", 65), good + " ", good[:43], good + "\n\n", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		key, err := readAccessKey(path)
		if err == nil || key != nil || strings.Contains(err.Error(), value) && value != "" {
			t.Fatal("invalid key accepted or leaked")
		}
	}
	if _, err := readAccessKey(dir); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := readAccessKey(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("missing accepted")
	}
	if err := os.WriteFile(path, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := readAccessKey(path); err == nil {
			t.Fatal("public-readable key accepted")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readAccessKey(link); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}
