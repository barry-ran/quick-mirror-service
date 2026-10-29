// Package httpapi 实现独立业务 HTTP 边界，不依赖 UI 或 Peerloom 内部实现。
package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/barry-ran/quick-mirror-service/internal/bootstrap"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/barry-ran/quick-mirror-service/internal/peerloom"
)

type BootstrapIssuer interface {
	Issue(context.Context, bootstrap.Request) (peerloom.RegistrationGrant, error)
}

type BootstrapConfig struct {
	Identity     peerloom.IdentityConfig
	ServiceScope string
	// 这些是匿名注册请求的资源界限，不是设备或连接数量配额。
	MaxConcurrent     int
	Burst             int
	RequestsPerSecond float64
}

type BootstrapHandler struct {
	issuer BootstrapIssuer
	config BootstrapConfig
	active chan struct{}
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func ValidateBootstrapConfig(config BootstrapConfig) (BootstrapConfig, error) {
	scope, valid := identity.NormalizeUUID(config.ServiceScope)
	if !valid || config.MaxConcurrent < 1 || config.MaxConcurrent > 4096 || config.Burst < 1 || config.Burst > 100000 || math.IsNaN(config.RequestsPerSecond) || math.IsInf(config.RequestsPerSecond, 0) || config.RequestsPerSecond <= 0 || config.RequestsPerSecond > 100000 {
		return config, bootstrap.ErrInvalidInput
	}
	if _, err := peerloom.NewIdentityClient(config.Identity, nil); err != nil {
		return config, err
	}
	config.ServiceScope = scope
	config.Identity.PCApplicationID, _ = identity.NormalizeUUID(config.Identity.PCApplicationID)
	config.Identity.MobileApplicationID, _ = identity.NormalizeUUID(config.Identity.MobileApplicationID)
	config.Identity.Origin = strings.TrimSuffix(config.Identity.Origin, "/")
	return config, nil
}

func NewBootstrapHandler(config BootstrapConfig, issuer BootstrapIssuer) (*BootstrapHandler, error) {
	if issuer == nil {
		return nil, bootstrap.ErrInvalidInput
	}
	config, err := ValidateBootstrapConfig(config)
	if err != nil {
		return nil, err
	}
	return &BootstrapHandler{issuer: issuer, config: config, active: make(chan struct{}, config.MaxConcurrent), tokens: float64(config.Burst), last: time.Now()}, nil
}

func (h *BootstrapHandler) admit() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.tokens += now.Sub(h.last).Seconds() * h.config.RequestsPerSecond
	h.last = now
	if h.tokens > float64(h.config.Burst) {
		h.tokens = float64(h.config.Burst)
	}
	if h.tokens < 1 {
		return false
	}
	h.tokens--
	return true
}

func (h *BootstrapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	random[6] = (random[6] & 0x0f) | 0x40
	random[8] = (random[8] & 0x3f) | 0x80
	requestID := fmt.Sprintf("%x-%x-%x-%x-%x", random[:4], random[4:6], random[6:8], random[8:10], random[10:])
	fail := func(status int, code string, retry bool) {
		message := "Request could not be completed"
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "zh") {
			message = "请求未能完成"
		}
		failure := map[string]any{"code": code, "message": message, "retryable": retry}
		if status == http.StatusTooManyRequests {
			failure["retry_after_ms"] = 1000
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"request_id": requestID, "error": failure})
	}
	var role identity.Role
	var application string
	switch r.URL.Path {
	case "/qm/v1/bootstrap/pc":
		role = identity.PC
		application = h.config.Identity.PCApplicationID
	case "/qm/v1/bootstrap/mobile":
		role = identity.Mobile
		application = h.config.Identity.MobileApplicationID
	default:
		fail(404, "NOT_FOUND", false)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(405, "METHOD_NOT_ALLOWED", false)
		return
	}
	if !h.admit() {
		fail(429, "RESOURCE_EXHAUSTED", true)
		return
	}
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
	default:
		fail(429, "RESOURCE_EXHAUSTED", true)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		fail(415, "INVALID_CONTENT_TYPE", false)
		return
	}
	if r.URL.RawQuery != "" {
		fail(400, "INVALID_INPUT", false)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	request, err := decodeBootstrap(r.Body, role)
	if err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			fail(413, "REQUEST_TOO_LARGE", false)
		} else {
			fail(400, "INVALID_INPUT", false)
		}
		return
	}
	if request.Validate() != nil {
		fail(400, "INVALID_INPUT", false)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	grant, err := h.issuer.Issue(ctx, request)
	if err != nil {
		switch {
		case errors.Is(err, bootstrap.ErrInvalidInput), errors.Is(err, peerloom.ErrInvalidRegistration):
			fail(400, "INVALID_INPUT", false)
		case errors.Is(err, peerloom.ErrIdempotencyConflict):
			fail(409, "IDEMPOTENCY_CONFLICT", false)
		case errors.Is(err, peerloom.ErrReplayExpired):
			fail(409, "REPLAY_EXPIRED", false)
		case errors.Is(err, peerloom.ErrOutcomeUnknown):
			fail(503, "OUTCOME_UNKNOWN", false)
		default:
			fail(503, "SERVICE_UNAVAILABLE", true)
		}
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"request_id": requestID, "data": map[string]any{"registration_grant": grant.Grant, "expires_at": grant.ExpiresAt.UTC(), "application_id": application, "peerloom_origin": h.config.Identity.Origin, "service_scope": h.config.ServiceScope}})
}

// 显式拒绝重复键和无效 UTF-8，不能让 JSON 解码的替换字符改变请求语义。
func decodeBootstrap(reader io.Reader, role identity.Role) (bootstrap.Request, error) {
	request := bootstrap.Request{Role: role}
	data, err := io.ReadAll(reader)
	if err != nil {
		return request, err
	}
	if !utf8.Valid(data) {
		return request, bootstrap.ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return request, bootstrap.ErrInvalidInput
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return request, bootstrap.ErrInvalidInput
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return request, bootstrap.ErrInvalidInput
		}
		seen[name] = true
		var value any
		if decoder.Decode(&value) != nil {
			return request, bootstrap.ErrInvalidInput
		}
		text, ok := value.(string)
		if !ok {
			return request, bootstrap.ErrInvalidInput
		}
		switch name {
		case "install_public_label":
			request.Label = text
		case "idempotency_key":
			request.IdempotencyKey = text
		default:
			return request, bootstrap.ErrInvalidInput
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return request, bootstrap.ErrInvalidInput
	}
	if _, err := decoder.Token(); err != io.EOF {
		return request, bootstrap.ErrInvalidInput
	}
	return request, nil
}
