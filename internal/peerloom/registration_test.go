package peerloom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

func TestRegistrationPublicRequest(t *testing.T) {
	for _, role := range []identity.Role{identity.PC, identity.Mobile} {
		t.Run(string(role), func(t *testing.T) {
			var calls atomic.Int32
			expiry := time.Now().Add(time.Minute).In(time.FixedZone("fixture", 5*3600)).Truncate(time.Second)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "POST" || r.URL.Path != "/v1/registration-grants" || r.Header.Get("Authorization") != "Bearer svc_fixture" || r.Header.Get("Idempotency-Key") != "same-key-123" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("incorrect public registration request")
				}
				var body struct {
					Application string `json:"application_id"`
					TTL         int    `json:"expires_in_seconds"`
				}
				want := pcID
				if role == identity.Mobile {
					want = mobileID
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil || body.Application != want || body.TTL != 300 {
					t.Error("incorrect configured role or default TTL")
				}
				w.WriteHeader(201)
				json.NewEncoder(w).Encode(RegistrationGrant{ID: strings.ToUpper(deviceID), Grant: "reg_fixture", ExpiresAt: expiry})
			}))
			defer server.Close()
			client, err := NewRegistrationClient(config(server.URL), "svc_fixture", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				grant, err := client.Issue(context.Background(), role, "same-key-123", 0)
				if err != nil || grant.ID != deviceID || grant.Grant != "reg_fixture" || !grant.ExpiresAt.Equal(expiry) || grant.ExpiresAt.Location() != time.UTC {
					t.Fatalf("invalid grant response: %v", err)
				}
			}
			if calls.Load() != 2 {
				t.Fatal("adapter silently cached or retried request")
			}
		})
	}
}

func TestRegistrationFailureSemantics(t *testing.T) {
	valid := fmt.Sprintf(`{"id":%q,"grant":"reg_fixture","expires_at":%q}`, deviceID, time.Now().Add(time.Minute).UTC().Format(time.RFC3339))
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"conflict", 409, `{"code":"IDEMPOTENCY_CONFLICT","detail":"secret"}`, ErrIdempotencyConflict},
		{"expired receipt", 409, `{"code":"REPLAY_EXPIRED"}`, ErrReplayExpired},
		{"unrecognized conflict", 409, `{"code":"private details"}`, ErrOutcomeUnknown},
		{"unauthorized service", 401, `secret`, identity.ErrUnavailable},
		{"forbidden service", 403, `secret`, identity.ErrUnavailable},
		{"missing app", 404, `secret`, identity.ErrUnavailable},
		{"invalid setup", 422, `secret`, identity.ErrUnavailable},
		{"server failure", 500, `secret`, ErrOutcomeUnknown},
		{"busy", 429, `secret`, ErrOutcomeUnknown},
		{"wrong success", 200, valid, ErrOutcomeUnknown},
		{"invalid json", 201, `{`, ErrOutcomeUnknown},
		{"missing fields", 201, `{}`, ErrOutcomeUnknown},
		{"trailing body", 201, valid + `{}`, ErrOutcomeUnknown},
		{"oversize", 201, strings.Repeat(" ", maxIdentityResponse+1), ErrOutcomeUnknown},
		{"expired grant", 201, fmt.Sprintf(`{"id":%q,"grant":"reg_x","expires_at":"2000-01-01T00:00:00Z"}`, deviceID), ErrReplayExpired},
		{"unsafe grant", 201, strings.Replace(valid, "reg_fixture", "has space", 1), ErrOutcomeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			client, err := NewRegistrationClient(config(server.URL), "svc_fixture", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			grant, err := client.Issue(context.Background(), identity.Mobile, "request-key", 300)
			if !errors.Is(err, tc.want) || grant != (RegistrationGrant{}) {
				t.Fatalf("failure result: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatal("unexpected automatic retry")
			}
		})
	}
}

func TestRegistrationRejectInputAndRedirect(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/credential-leak")
		w.WriteHeader(307)
	}))
	defer server.Close()
	for _, credential := range []string{"", "secret\nheader", "with space", strings.Repeat("x", 513)} {
		if _, err := NewRegistrationClient(config(server.URL), credential, server.Client()); err == nil {
			t.Fatal("accepted invalid service credential")
		}
	}
	client, err := NewRegistrationClient(config(server.URL), "svc_fixture", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", "short", strings.Repeat("x", 129), "with space", "换行换行换行"} {
		if _, err := client.Issue(context.Background(), identity.PC, key, 300); !errors.Is(err, ErrInvalidRegistration) {
			t.Fatal("accepted invalid key")
		}
	}
	for _, ttl := range []int{-1, 3601} {
		if _, err := client.Issue(context.Background(), identity.PC, "valid-key", ttl); !errors.Is(err, ErrInvalidRegistration) {
			t.Fatal("accepted invalid TTL")
		}
	}
	if _, err := client.Issue(context.Background(), "admin", "valid-key", 300); !errors.Is(err, ErrInvalidRegistration) {
		t.Fatal("accepted untrusted role")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input sent upstream")
	}
	if _, err := client.Issue(context.Background(), identity.PC, "valid-key", 300); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("redirect accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("redirect forwarded credential")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Issue(ctx, identity.PC, "valid-key", 300); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("cancellation not preserved as uncertain")
	}
}

func TestRegistrationReplayDomain(t *testing.T) {
	c1, err := NewRegistrationClient(config("https://example.test"), "svc_one", nil)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := NewRegistrationClient(config("https://example.test"), "svc_two", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c1.ReplayDomain()) != 64 || c1.ReplayDomain() == c2.ReplayDomain() || strings.Contains(c1.ReplayDomain(), "svc_one") {
		t.Fatal("rotation domain not isolated")
	}
}
