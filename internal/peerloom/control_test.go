package peerloom

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

const controlSource = "44444444-4444-4444-8444-444444444444"
const controlTarget = "55555555-5555-4555-8555-555555555555"
const controlGrantID = "66666666-6666-4666-8666-666666666666"
const controlSessionID = "77777777-7777-4777-8777-777777777777"
const controlKey = "fixture-control-key"

func controlGrantPayload() ControlGrant {
	return ControlGrant{ID: controlGrantID, TenantID: tenantID, SourceDeviceID: controlSource, TargetDeviceID: controlTarget, ExpiresAt: time.Now().UTC().Add(time.Hour), ExpiryAction: "no_new_connections", MaxSessions: 1}
}
func controlTestClient(t *testing.T, h http.HandlerFunc) (*ControlClient, *httptest.Server) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	c, err := NewControlClient(config(s.URL), "fixture-only-admin", s.Client())
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}
func TestControlGrantPublicRoutes(t *testing.T) {
	var calls atomic.Int32
	c, _ := controlTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture-only-admin" {
			t.Error("missing authentication")
		}
		switch r.Method {
		case http.MethodPost:
			if r.URL.Path != "/v1/connection-grants" || r.Header.Get("Idempotency-Key") != controlKey {
				t.Error("incorrect create request")
			}
			var in struct {
				Source string `json:"source_device_id"`
				Target string `json:"target_device_id"`
				TTL    int    `json:"expires_in_seconds"`
				Action string `json:"expiry_action"`
				Max    int    `json:"max_sessions"`
			}
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.Source != controlSource || in.Target != controlTarget || in.TTL != 300 || in.Action != "no_new_connections" || in.Max != 1 {
				t.Error("incorrect grant policy")
			}
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(controlGrantPayload())
		case http.MethodGet:
			if r.URL.Path != "/v1/connection-grants/"+controlGrantID {
				t.Error("incorrect read route")
			}
			json.NewEncoder(w).Encode(controlGrantPayload())
		case http.MethodDelete:
			if r.URL.Path != "/v1/connection-grants/"+controlGrantID || r.Header.Get("Idempotency-Key") != controlKey {
				t.Error("incorrect revoke request")
			}
			json.NewEncoder(w).Encode(map[string]any{"id": controlGrantID, "revoked": true, "closed_sessions": []any{}})
		default:
			t.Error("unexpected HTTP method")
		}
	})
	if _, err := c.CreateGrant(context.Background(), controlSource, controlTarget, controlKey); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetGrant(context.Background(), controlGrantID); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeGrant(context.Background(), controlGrantID, controlKey); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatal("unexpected retry")
	}
}
func TestControlSessionUsesManagementShapeAndVerifiedGrant(t *testing.T) {
	for _, bad := range []string{"", "foreign tenant", "different peers", "wrong id", "unknown state", "missing lease", "device shape", "expired grant"} {
		t.Run(bad, func(t *testing.T) {
			c, _ := controlTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/connection-grants/"+controlGrantID {
					g := controlGrantPayload()
					if bad == "expired grant" {
						g.ExpiresAt = time.Now().Add(-time.Hour)
					}
					if bad == "foreign tenant" {
						g.TenantID = controlTarget
					}
					if bad == "different peers" {
						g.SourceDeviceID = deviceID
					}
					json.NewEncoder(w).Encode(g)
					return
				}
				// 正式v0.1.3管理GET使用id，无tenant_id；不能用设备侧Session代替。
				out := map[string]any{"id": controlSessionID, "source_device_id": controlSource, "target_device_id": controlTarget, "grant_id": controlGrantID, "state": "connecting", "source_lease_expires_at": time.Now().UTC().Add(time.Minute), "target_lease_expires_at": time.Now().UTC().Add(time.Minute)}
				if bad == "wrong id" {
					out["id"] = controlTarget
				}
				if bad == "unknown state" {
					out["state"] = "magic"
				}
				if bad == "missing lease" {
					delete(out, "target_lease_expires_at")
				}
				if bad == "device shape" {
					delete(out, "id")
					out["session_id"] = controlSessionID
					out["tenant_id"] = tenantID
				}
				json.NewEncoder(w).Encode(out)
			})
			got, err := c.GetSession(context.Background(), controlSessionID)
			if bad != "" && bad != "expired grant" {
				if !errors.Is(err, identity.ErrUnavailable) {
					t.Fatalf("expected unavailable, got %v", err)
				}
				return
			}
			if err != nil || got.ID != controlSessionID || got.TenantID != tenantID || got.GrantID != controlGrantID {
				t.Fatalf("management session not adapted: %+v %v", got, err)
			}
		})
	}
}
func TestControlRejectsInvalidMutationWithoutNetwork(t *testing.T) {
	var calls atomic.Int32
	c, _ := controlTestClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) })
	for _, key := range []string{"", "short", "bad\nkey", strings.Repeat("x", 129)} {
		if _, err := c.CreateGrant(context.Background(), controlSource, controlTarget, key); !errors.Is(err, ErrInvalidRegistration) {
			t.Fatal(err)
		}
		if err := c.RevokeGrant(context.Background(), controlGrantID, key); !errors.Is(err, ErrInvalidRegistration) {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateGrant(context.Background(), controlSource, controlSource, controlKey); !errors.Is(err, ErrInvalidRegistration) {
		t.Fatal(err)
	}
	if _, err := c.GetSession(context.Background(), "bad/id"); !errors.Is(err, ErrInvalidRegistration) {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached network")
	}
}
func TestControlFailuresRemainUnknownWithoutRetry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{{"server", 500, "internal secret"}, {"expired", 409, `{"error":{"code":"REPLAY_EXPIRED"}}`}, {"unauthorized", 401, "secret"}, {"malformed", 200, "{"}, {"trailing", 200, "{}{}"}, {"oversize", 200, strings.Repeat(" ", 256<<10+1)}} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c, _ := controlTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			})
			if _, err := c.CreateGrant(context.Background(), controlSource, controlTarget, controlKey); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("mutation: %v", err)
			}
			if _, err := c.GetGrant(context.Background(), controlGrantID); !errors.Is(err, identity.ErrUnavailable) {
				t.Fatalf("read: %v", err)
			}
			if calls.Load() != 2 {
				t.Fatal("implicit retry")
			}
		})
	}
}
func TestControlCreateRejectsWidenedGrant(t *testing.T) {
	c, _ := controlTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		g := controlGrantPayload()
		g.MaxSessions = -1
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(g)
	})
	if _, err := c.CreateGrant(context.Background(), controlSource, controlTarget, controlKey); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal(err)
	}
}
func TestControlRedirectAndReplayDomain(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer target.Close()
	c, s := controlTestClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) })
	if _, err := c.CreateGrant(context.Background(), controlSource, controlTarget, controlKey); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	if reached.Load() != 0 {
		t.Fatal("followed credential redirect")
	}
	same, _ := NewControlClient(config(s.URL), "fixture-only-admin", s.Client())
	rotated, _ := NewControlClient(config(s.URL), "fixture-rotated-admin", s.Client())
	if c.ReplayDomain() != same.ReplayDomain() || c.ReplayDomain() == rotated.ReplayDomain() {
		t.Fatal("replay domain does not bind credential")
	}
	if _, err := NewControlClient(config("http://127.0.0.1"), "fixture-only-admin", nil); err == nil {
		t.Fatal("accepted HTTP origin")
	}
	if c.identity.client.Timeout > 5*time.Second {
		t.Fatal("unbounded timeout")
	}
}
func TestControlDeviceValidation(t *testing.T) {
	for _, bad := range []bool{false, true} {
		c, _ := controlTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			d := ControlDevice{ID: controlTarget, TenantID: tenantID, ApplicationID: mobileID, Status: "active"}
			if bad {
				d.ApplicationID = ""
			}
			json.NewEncoder(w).Encode(d)
		})
		d, err := c.GetDevice(context.Background(), controlTarget)
		if bad {
			if !errors.Is(err, identity.ErrUnavailable) {
				t.Fatal(err)
			}
		} else if err != nil || d.Online != nil {
			t.Fatalf("unknown presence must remain nil: %+v %v", d, err)
		}
	}
}

func TestControlCancellationDoesNotRetryOrLeak(t *testing.T) {
	var calls atomic.Int32
	c, _ := controlTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-r.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.CreateGrant(ctx, controlSource, controlTarget, controlKey); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("mutation cancellation must remain unknown: %v", err)
	}
	if calls.Load() > 1 {
		t.Fatal("cancelled mutation retried")
	}
}

func TestControlGrantTTLConfiguration(t *testing.T) {
	for _, seconds := range []int{0, -1, 2592001} {
		if _, err := NewControlClientWithGrantTTL(config("https://example.invalid"), "fixture-only-admin", nil, seconds); err == nil {
			t.Fatalf("accepted TTL %d", seconds)
		}
	}
	for _, seconds := range []int{1, 300, 2592000} {
		c, err := NewControlClientWithGrantTTL(config("https://example.invalid"), "fixture-only-admin", nil, seconds)
		if err != nil || c.grantTTLSeconds != seconds {
			t.Fatalf("rejected TTL %d: %v", seconds, err)
		}
	}
}

func TestControlDeviceNotFoundClassification(t *testing.T) {
	for _, status := range []int{404, 401, 403, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c, _ := controlTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				w.Write([]byte(`{"code":"DEVICE_NOT_FOUND"}`))
			})
			_, err := c.GetDevice(context.Background(), controlTarget)
			want := identity.ErrUnavailable
			if status == 404 {
				want = ErrDeviceNotFound
			}
			if !errors.Is(err, want) {
				t.Fatalf("status=%d err=%v", status, err)
			}
			// A grant 404 remains unknown/unavailable, never evidence of safe release.
			_, err = c.GetGrant(context.Background(), controlGrantID)
			if !errors.Is(err, identity.ErrUnavailable) {
				t.Fatalf("grant status=%d err=%v", status, err)
			}
		})
	}
}
