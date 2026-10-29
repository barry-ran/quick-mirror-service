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
	"unicode/utf8"

	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

// AccessVerifier 仅接受业务 access token，不能误接安装凭证的 Verify 方法。
type AccessVerifier interface {
	VerifyAccess(context.Context, string) (identity.Principal, error)
}

type DeviceCatalog interface {
	ResolveBatch(context.Context, identity.Principal, []string) ([]catalog.Resolution, error)
	UpdateStatus(context.Context, identity.Principal, catalog.Status) error
}

// CatalogHandler 尚未挂到运行时，须先有真实 exchange/可信期限 adapter。
type CatalogHandler struct {
	access    AccessVerifier
	directory DeviceCatalog
	active    chan struct{}
}

func NewCatalogHandler(access AccessVerifier, directory DeviceCatalog, maxConcurrent int) (*CatalogHandler, error) {
	if access == nil || directory == nil || maxConcurrent < 1 || maxConcurrent > 4096 {
		return nil, catalog.ErrInvalidInput
	}
	return &CatalogHandler{access: access, directory: directory, active: make(chan struct{}, maxConcurrent)}, nil
}

func (h *CatalogHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	id := fmt.Sprintf("%x-%x-%x-%x-%x", random[:4], random[4:6], random[6:8], random[8:10], random[10:])
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
		json.NewEncoder(w).Encode(map[string]any{"request_id": id, "error": failure})
	}
	method := ""
	role := identity.Role("")
	switch r.URL.Path {
	case "/qm/v1/devices/resolve":
		method = http.MethodPost
		role = identity.PC
	case "/qm/v1/device-self/status":
		method = http.MethodPut
		role = identity.Mobile
	default:
		fail(404, "NOT_FOUND", false)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		fail(405, "METHOD_NOT_ALLOWED", false)
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
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || len(token) == 0 || len(token) > 4096 || strings.IndexFunc(token, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		fail(401, "AUTH_INVALID", false)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	principal, err := h.access.VerifyAccess(ctx, token)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidCredential) {
			fail(401, "AUTH_INVALID", false)
		} else if errors.Is(err, identity.ErrForbidden) {
			fail(403, "INSTALLATION_FORBIDDEN", false)
		} else {
			fail(503, "SERVICE_UNAVAILABLE", true)
		}
		return
	}
	if principal.Role != role {
		fail(403, "INSTALLATION_FORBIDDEN", false)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		fail(415, "INVALID_CONTENT_TYPE", false)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(400, "INVALID_INPUT", false)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	var data any
	if role == identity.PC {
		var input struct {
			UUIDs *[]string `json:"uuids"`
		}
		err = decodeStrictObject(r.Body, &input)
		if err == nil && (input.UUIDs == nil || len(*input.UUIDs) > catalog.BatchSize) {
			err = catalog.ErrInvalidInput
		}
		if err == nil {
			var items []catalog.Resolution
			items, err = h.directory.ResolveBatch(ctx, principal, *input.UUIDs)
			if err == nil {
				// resolve 只证明存在性；不把旧权限快照当成当前在线/可操作状态。
				result := make([]map[string]any, 0, len(items))
				for _, item := range items {
					entry := map[string]any{"uuid": item.UUID, "found": item.Found}
					if item.ErrorCode != "" {
						entry["error_code"] = item.ErrorCode
					}
					result = append(result, entry)
				}
				data = map[string]any{"items": result}
			}
		}
	} else {
		var status catalog.Status
		err = decodeStrictObject(r.Body, &status)
		if err == nil {
			err = h.directory.UpdateStatus(ctx, principal, status)
		}
		data = map[string]any{"accepted": true}
	}
	if err != nil {
		var size *http.MaxBytesError
		switch {
		case errors.As(err, &size):
			fail(413, "REQUEST_TOO_LARGE", false)
		case errors.Is(err, catalog.ErrInvalidInput):
			fail(400, "INVALID_INPUT", false)
		case errors.Is(err, catalog.ErrNotFound):
			fail(404, "DEVICE_NOT_FOUND", false)
		case errors.Is(err, catalog.ErrStaleStatus):
			fail(409, "STALE_STATUS", false)
		case errors.Is(err, identity.ErrForbidden):
			fail(403, "INSTALLATION_FORBIDDEN", false)
		default:
			fail(503, "SERVICE_UNAVAILABLE", true)
		}
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"request_id": id, "data": data})
}

// 先检查所有层级的重复键和 UTF-8，再用结构体解码拒绝未知字段；限制嵌套深度。
func decodeStrictObject(reader io.Reader, target any) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(data)
	if !utf8.Valid(data) || len(trimmed) == 0 || trimmed[0] != '{' {
		return catalog.ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	budget := 4096
	if scanJSONValue(decoder, 0, &budget) != nil {
		return catalog.ErrInvalidInput
	}
	if _, err := decoder.Token(); err != io.EOF {
		return catalog.ErrInvalidInput
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return catalog.ErrInvalidInput
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int, budget *int) error {
	*budget = *budget - 1
	if depth > 32 || *budget < 0 {
		return catalog.ErrInvalidInput
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return catalog.ErrInvalidInput
			}
			*budget = *budget - 1
			if *budget < 0 {
				return catalog.ErrInvalidInput
			}
			seen[name] = true
			if err := scanJSONValue(decoder, depth+1, budget); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return catalog.ErrInvalidInput
		}
	case json.Delim('['):
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1, budget); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return catalog.ErrInvalidInput
		}
	case json.Delim('}'), json.Delim(']'):
		return catalog.ErrInvalidInput
	}
	return nil
}
