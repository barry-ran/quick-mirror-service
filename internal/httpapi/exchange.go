package httpapi

import (
	"bytes"
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

	"github.com/barry-ran/quick-mirror-service/internal/access"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

type CredentialExchanger interface {
	ExchangeVerified(context.Context, identity.Role, string) (access.Token, identity.Principal, error)
}

type InstallationRegistry interface {
	EnsureRegistration(context.Context, identity.Principal) error
}

// ExchangeHandler 仅交换经过正式上游认证的安装身份；不接受客户端自报主体或期限。
type ExchangeHandler struct {
	exchanger CredentialExchanger
	registry  InstallationRegistry
	active    chan struct{}
}

func NewExchangeHandler(exchanger CredentialExchanger, registry InstallationRegistry, maxConcurrent int) (*ExchangeHandler, error) {
	if exchanger == nil || registry == nil || maxConcurrent < 1 || maxConcurrent > 4096 {
		return nil, access.ErrInvalidConfig
	}
	return &ExchangeHandler{exchanger: exchanger, registry: registry, active: make(chan struct{}, maxConcurrent)}, nil
}

func (h *ExchangeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
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
		failure := map[string]any{"code": code, "message": message, "retryable": retry}
		if status == 429 {
			failure["retry_after_ms"] = 1000
			w.Header().Set("Retry-After", "1")
		}
		if status == 401 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="quickmirror"`)
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"request_id": requestID, "error": failure})
	}
	role := identity.Role("")
	switch r.URL.Path {
	case "/qm/v1/auth/pc/exchange":
		role = identity.PC
	case "/qm/v1/auth/device/exchange":
		role = identity.Mobile
	default:
		fail(404, "NOT_FOUND", false)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(405, "METHOD_NOT_ALLOWED", false)
		return
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
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		fail(401, "AUTH_INVALID", false)
		return
	}
	scheme, credential, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || len(credential) == 0 || len(credential) > 512 || strings.IndexFunc(credential, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		fail(401, "AUTH_INVALID", false)
		return
	}
	if r.Body == nil {
		r.Body = http.NoBody
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			fail(413, "REQUEST_TOO_LARGE", false)
		} else {
			fail(400, "INVALID_INPUT", false)
		}
		return
	}
	if len(data) > 0 || r.Header.Get("Content-Type") != "" {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			fail(415, "INVALID_CONTENT_TYPE", false)
			return
		}
	}
	if len(data) > 0 {
		var empty struct{}
		if decodeStrictObject(bytes.NewReader(data), &empty) != nil {
			fail(400, "INVALID_INPUT", false)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	token, principal, err := h.exchanger.ExchangeVerified(ctx, role, credential)
	if err == nil && principal.Role != role {
		err = identity.ErrForbidden
	}
	if err == nil && role == identity.Mobile {
		err = h.registry.EnsureRegistration(ctx, principal)
	}
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrInvalidCredential):
			fail(401, "AUTH_INVALID", false)
		case errors.Is(err, identity.ErrForbidden):
			fail(403, "INSTALLATION_FORBIDDEN", false)
		default:
			fail(503, "SERVICE_UNAVAILABLE", true)
		}
		return
	}
	// 主体不放进响应，不返回来源credential；目录失败时也不泄漏已生成的业务token。
	json.NewEncoder(w).Encode(map[string]any{"request_id": requestID, "data": token})
}
