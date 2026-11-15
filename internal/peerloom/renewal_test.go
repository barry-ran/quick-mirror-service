package peerloom

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRenewalAPIContract(t *testing.T) {
	fixture := renewalFixture()
	mode := "ok"
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer old_secret" {
			t.Error("wrong credential")
		}
		if mode != "ok" {
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": mode})
			return
		}
		switch r.URL.Path {
		case "/v1/service-credentials/self":
			_ = json.NewEncoder(w).Encode(fixture.old)
		case "/v1/service-credentials/renew":
			if r.Method != "POST" || r.Header.Get("Idempotency-Key") != renewalNew || r.Header.Get("Content-Type") != "application/json" {
				t.Error("renew contract")
			}
			_ = json.NewEncoder(w).Encode(RenewalResult{fixture.new, "new_secret", renewalOld, fixture.old.ExpiresAt})
		default:
			t.Error("wrong path")
		}
	}))
	defer server.Close()
	api, err := NewRenewalClient(IdentityConfig{server.URL, renewalTenant, "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = api.Self(context.Background(), "old_secret"); err != nil {
		t.Fatal(err)
	}
	if _, err = api.Renew(context.Background(), "old_secret", renewalNew); err != nil {
		t.Fatal(err)
	}
	for code, want := range map[string]error{"RENEWAL_TOO_EARLY": ErrRenewalDeferred, "RENEWAL_ALREADY_EXISTS": ErrRenewalJournalConflict, "RENEWAL_UNAVAILABLE": ErrRenewalUnavailable} {
		mode = code
		_, err = api.Renew(context.Background(), "old_secret", renewalNew)
		if !errors.Is(err, want) {
			t.Fatal(code, err)
		}
	}
	before := calls
	if _, err = api.Renew(context.Background(), "old_secret", "invalid"); err == nil || calls != before {
		t.Fatal("invalid operation sent")
	}
}
