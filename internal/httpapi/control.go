package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"github.com/barry-ran/quick-mirror-service/internal/control"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

type ControlIntents interface {
	Create(context.Context, identity.Principal, string, string) (control.Intent, bool, error)
	Get(context.Context, identity.Principal, string) (control.Intent, error)
	ByCommand(context.Context, identity.Principal, string) (control.Intent, error)
	Current(context.Context, identity.Principal) (*control.Intent, error)
	Close(context.Context, identity.Principal, string, string, string) (control.Intent, error)
	Bind(context.Context, identity.Principal, string, string, string, string, string, string) (control.Intent, error)
	Drained(context.Context, identity.Principal, string, string, string, string, string, string, string) (control.Intent, error)
}
type ControlHandler struct {
	access AccessVerifier
	store  ControlIntents
	active chan struct{}
}

func NewControlHandler(a AccessVerifier, s ControlIntents, limit int) (*ControlHandler, error) {
	if a == nil || s == nil || limit < 1 || limit > 4096 {
		return nil, catalog.ErrInvalidInput
	}
	return &ControlHandler{a, s, make(chan struct{}, limit)}, nil
}
func (h *ControlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// This identifier is correlation only; no request body or runtime proof is logged.
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		w.WriteHeader(503)
		return
	}
	random[6] = (random[6] & 15) | 64
	random[8] = (random[8] & 63) | 128
	requestID := fmt.Sprintf("%x-%x-%x-%x-%x", random[:4], random[4:6], random[6:8], random[8:10], random[10:])
	fail := func(status int, code string, retry bool) {
		message := "Request could not be completed"
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "zh") {
			message = "请求未能完成"
		}
		detail := map[string]any{"code": code, "message": message, "retryable": retry}
		if status == 429 {
			w.Header().Set("Retry-After", "1")
			detail["retry_after_ms"] = 1000
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"request_id": requestID, "error": detail})
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(400, "INVALID_INPUT", false)
		return
	}
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
	default:
		fail(429, "RESOURCE_EXHAUSTED", true)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		fail(401, "AUTH_INVALID", false)
		return
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > 512 {
		fail(401, "AUTH_INVALID", false)
		return
	}
	p, e := h.access.VerifyAccess(ctx, token)
	if e != nil {
		if errors.Is(e, identity.ErrInvalidCredential) {
			fail(401, "AUTH_INVALID", false)
		} else {
			fail(503, "SERVICE_UNAVAILABLE", true)
		}
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/qm/v1/")
	parts := strings.Split(path, "/")
	action, id, method := "", "", http.MethodGet
	switch {
	case path == "session-intents":
		action = "create"
		method = http.MethodPost
	case path == "device-self/session-intents/current":
		action = "current"
	case len(parts) == 3 && parts[0] == "session-intents" && parts[1] == "by-command":
		action = "by-command"
		id = parts[2]
	case len(parts) == 2 && parts[0] == "session-intents":
		action = "get"
		id = parts[1]
	case len(parts) == 3 && parts[0] == "session-intents" && parts[2] == "close":
		action = "close"
		id = parts[1]
		method = http.MethodPost
	case len(parts) == 4 && parts[0] == "device-self" && parts[1] == "session-intents" && (parts[3] == "bind" || parts[3] == "drained"):
		action = parts[3]
		id = parts[2]
		method = http.MethodPost
	default:
		fail(404, "INTENT_NOT_FOUND", false)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		fail(405, "METHOD_NOT_ALLOWED", false)
		return
	}
	if r.Body == nil {
		r.Body = http.NoBody
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decode := func(v any) error {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			return &control.Error{Code: "UNSUPPORTED_MEDIA_TYPE", Status: 415}
		}
		return decodeStrictObject(r.Body, v)
	}
	var i control.Intent
	status := 200
	switch action {
	case "create":
		var v struct {
			Command string `json:"command_id"`
			Target  string `json:"device_uuid"`
			Relay   string `json:"relay_mode"`
		}
		e = decode(&v)
		if e == nil && v.Relay != "" && v.Relay != "default" {
			e = &control.Error{Code: "RELAY_CONFIG_UNSUPPORTED", Status: 409}
		}
		if e == nil {
			var created bool
			i, created, e = h.store.Create(ctx, p, v.Target, v.Command)
			if created {
				status = 201
			}
		}
	case "get", "by-command", "current":
		var b []byte
		b, e = io.ReadAll(r.Body)
		if e == nil && len(b) > 0 {
			e = catalog.ErrInvalidInput
		}
		if e == nil {
			switch action {
			case "get":
				i, e = h.store.Get(ctx, p, id)
			case "by-command":
				i, e = h.store.ByCommand(ctx, p, id)
			case "current":
				var current *control.Intent
				current, e = h.store.Current(ctx, p)
				if e == nil && current == nil {
					w.WriteHeader(204)
					return
				}
				if current != nil {
					i = *current
				}
			}
		}
	case "close":
		var v struct {
			Command string `json:"command_id"`
			Reason  string `json:"reason"`
		}
		e = decode(&v)
		if e == nil {
			i, e = h.store.Close(ctx, p, id, v.Command, v.Reason)
			if e == nil && i.State != "released" && i.State != "failed" {
				status = 202
			}
		}
	case "bind":
		var v struct {
			Command    string `json:"command_id"`
			Generation string `json:"business_generation"`
			Session    string `json:"session_id"`
			Boot       string `json:"boot_id"`
			Proof      string `json:"runtime_proof"`
		}
		e = decode(&v)
		if e == nil {
			i, e = h.store.Bind(ctx, p, id, v.Command, v.Generation, v.Session, v.Boot, v.Proof)
		}
	case "drained":
		var v struct {
			Command    string `json:"command_id"`
			Generation string `json:"business_generation"`
			Session    string `json:"session_id"`
			Token      string `json:"drain_token"`
			Boot       string `json:"boot_id"`
			Proof      string `json:"runtime_proof"`
		}
		e = decode(&v)
		if e == nil {
			i, e = h.store.Drained(ctx, p, id, v.Command, v.Generation, v.Session, v.Token, v.Boot, v.Proof)
		}
	}
	if e != nil {
		var ce *control.Error
		var size *http.MaxBytesError
		switch {
		case errors.As(e, &ce):
			fail(ce.Status, ce.Code, ce.Status == 429 || ce.Status == 503)
		case errors.As(e, &size):
			fail(413, "REQUEST_TOO_LARGE", false)
		case errors.Is(e, catalog.ErrInvalidInput):
			fail(400, "INVALID_INPUT", false)
		case errors.Is(e, identity.ErrForbidden):
			fail(403, "FORBIDDEN", false)
		default:
			fail(503, "SERVICE_UNAVAILABLE", true)
		}
		return
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"request_id": requestID, "data": i})
}
