package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/binding"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/barry-ran/quick-mirror-service/internal/peerloom"
)

type InstallationRegistry interface {
	EnsureRegistration(context.Context, identity.Principal) error
}
type Bindings interface {
	Ensure(context.Context, identity.Principal) (binding.Code, error)
	SelfCode(context.Context, identity.Principal) (binding.Code, error)
	Refresh(context.Context, identity.Principal, string) (binding.Code, error)
	Bind(context.Context, identity.Principal, string, string) (binding.Relation, error)
	List(context.Context, identity.Principal, string, int) (binding.Page, error)
	Unbind(context.Context, identity.Principal, string, string, string) (binding.Relation, error)
}
type Presence interface {
	GetDevice(context.Context, string) (peerloom.ControlDevice, error)
}
type BindingHandler struct {
	verifier identity.Verifier
	store    Bindings
	registry InstallationRegistry
	presence Presence
	active   chan struct{}
	scope    string
}

func NewBindingHandler(v identity.Verifier, s Bindings, registry InstallationRegistry, presence Presence, scope string, limit int) (*BindingHandler, error) {
	if v == nil || s == nil || registry == nil || presence == nil || limit < 1 || limit > 4096 {
		return nil, errors.New("INVALID_CONFIGURATION")
	}
	return &BindingHandler{verifier: v, store: s, registry: registry, presence: presence, active: make(chan struct{}, limit), scope: scope}, nil
}
func (h *BindingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		w.WriteHeader(503)
		return
	}
	random[6] = (random[6] & 0x0f) | 0x40
	random[8] = (random[8] & 0x3f) | 0x80
	requestID := fmt.Sprintf("%x-%x-%x-%x-%x", random[:4], random[4:6], random[6:8], random[8:10], random[10:])
	failure := func(status int, code string, retry bool) {
		if status == 401 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="quickmirror"`)
		}
		message := "Request could not be completed"
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "zh") {
			message = "请求未能完成"
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"request_id": requestID, "error": map[string]any{"code": code, "message": message, "retryable": retry}})
	}
	fail := func(err error) {
		var business *binding.Error
		switch {
		case errors.Is(err, identity.ErrInvalidCredential):
			failure(401, "AUTH_INVALID", false)
		case errors.Is(err, identity.ErrForbidden):
			failure(403, "INSTALLATION_FORBIDDEN", false)
		case errors.Is(err, identity.ErrUnavailable):
			failure(503, "UPSTREAM_UNAVAILABLE", true)
		case errors.As(err, &business):
			failure(business.Status, business.Code, business.Status >= 500)
		default:
			failure(503, "OUTCOME_UNKNOWN", true)
		}
	}
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
	default:
		failure(429, "RESOURCE_EXHAUSTED", true)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		failure(401, "AUTH_INVALID", false)
		return
	}
	scheme, credential, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || credential == "" || len(credential) > 512 || strings.IndexFunc(credential, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		failure(401, "AUTH_INVALID", false)
		return
	}
	p, err := h.verifier.Verify(ctx, credential)
	if err != nil {
		fail(err)
		return
	}
	path := r.URL.Path
	method := "POST"
	if path == "/qm/v1/binding-code/self" || path == "/qm/v1/bindings" && r.Method == "GET" {
		method = "GET"
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		failure(405, "METHOD_NOT_ALLOWED", false)
		return
	}
	if !(path == "/qm/v1/bindings" && r.Method == "GET") && (r.URL.RawQuery != "" || r.URL.ForceQuery) {
		failure(400, "INVALID_INPUT", false)
		return
	}
	if r.Body == nil {
		r.Body = http.NoBody
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	defer r.Body.Close()
	decode := func(out any) bool {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			failure(415, "INVALID_CONTENT_TYPE", false)
			return false
		}
		if decodeStrictObject(r.Body, out) != nil {
			failure(400, "INVALID_INPUT", false)
			return false
		}
		return true
	}
	key := r.Header.Get("Idempotency-Key")
	if len(r.Header.Values("Idempotency-Key")) > 1 {
		failure(400, "INVALID_INPUT", false)
		return
	}
	var data any
	switch {
	case path == "/qm/v1/installations/self/ensure":
		var empty struct{}
		if !decode(&empty) {
			return
		}
		var code binding.Code
		code, err = h.store.Ensure(ctx, p)
		if err == nil && p.Role == identity.Mobile {
			err = h.registry.EnsureRegistration(ctx, p)
		}
		// 初始化只建档，不能制造上线证据或覆盖已有boot/seq。
		data = struct {
			binding.Code
			Role         identity.Role `json:"role"`
			DeviceID     string        `json:"device_id"`
			ServiceScope string        `json:"service_scope"`
		}{code, p.Role, p.DeviceID, h.scope}
	case path == "/qm/v1/binding-code/self":
		data, err = h.store.SelfCode(ctx, p)
	case path == "/qm/v1/binding-code/self/refresh":
		var empty struct{}
		if !decode(&empty) {
			return
		}
		data, err = h.store.Refresh(ctx, p, key)
	case path == "/qm/v1/bindings" && r.Method == "POST":
		var in struct {
			Code string `json:"code"`
		}
		if !decode(&in) {
			return
		}
		data, err = h.store.Bind(ctx, p, in.Code, key)
	case path == "/qm/v1/bindings/batch":
		if p.Role != identity.PC {
			failure(403, "ROLE_MISMATCH", false)
			return
		}
		var in struct {
			Items []struct {
				ClientItemID string `json:"client_item_id"`
				Code         string `json:"code"`
				OperationKey string `json:"operation_key"`
			} `json:"items"`
		}
		if !decode(&in) {
			return
		}
		if len(in.Items) > 200 || len(in.Items) == 0 {
			failure(400, "INVALID_INPUT", false)
			return
		}
		// 先验证批次关联字段，防止执行一半才发现无法回传逐项结果。
		seen := map[string]bool{}
		for _, item := range in.Items {
			if item.ClientItemID == "" || len(item.ClientItemID) > 128 || seen[item.ClientItemID] {
				failure(400, "INVALID_INPUT", false)
				return
			}
			seen[item.ClientItemID] = true
		}
		items := make([]map[string]any, 0, len(in.Items))
		for _, item := range in.Items {
			row := map[string]any{"client_item_id": item.ClientItemID}
			relation, e := h.store.Bind(ctx, p, item.Code, item.OperationKey)
			if e == nil {
				row["binding"] = relation
			} else {
				code := "OUTCOME_UNKNOWN"
				retry := true
				var business *binding.Error
				if errors.As(e, &business) {
					code = business.Code
					retry = business.Status >= 500
				}
				row["error"] = map[string]any{"code": code, "retryable": retry}
			}
			items = append(items, row)
		}
		data = map[string]any{"items": items}
	case path == "/qm/v1/bindings" && r.Method == "GET":
		query := r.URL.Query()
		limit := 200
		for k, v := range query {
			if (k != "cursor" && k != "limit") || len(v) != 1 {
				failure(400, "INVALID_INPUT", false)
				return
			}
		}
		if raw := query.Get("limit"); raw != "" {
			limit, err = strconv.Atoi(raw)
			if err != nil || limit < 1 || limit > 200 {
				failure(400, "INVALID_INPUT", false)
				return
			}
		}
		var page binding.Page
		page, err = h.store.List(ctx, p, query.Get("cursor"), limit)
		if err == nil {
			data = h.withPresence(ctx, p, page)
		}
	case strings.HasPrefix(path, "/qm/v1/bindings/") && strings.HasSuffix(path, "/unbind"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/qm/v1/bindings/"), "/unbind")
		var in struct {
			Revision string `json:"expected_revision"`
		}
		if !decode(&in) {
			return
		}
		data, err = h.store.Unbind(ctx, p, id, in.Revision, key)
	default:
		failure(404, "NOT_FOUND", false)
		return
	}
	if err != nil {
		fail(err)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"request_id": requestID, "data": data})
}

type bindingPeer struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	Online   *bool  `json:"online"`
}
type bindingView struct {
	binding.Relation
	Peer bindingPeer `json:"peer"`
}

// 绑定列表本身权威且持久；独立presence失败显式返回unknown，绝不清空列表或伪造offline。
func (h *BindingHandler) withPresence(ctx context.Context, p identity.Principal, page binding.Page) any {
	items := make([]bindingView, len(page.Items))
	var wg sync.WaitGroup
	budget := make(chan struct{}, 8)
	for n, b := range page.Items {
		id := b.MobileID
		if p.Role == identity.Mobile {
			id = b.PCID
		}
		items[n] = bindingView{Relation: b, Peer: bindingPeer{DeviceID: id}}
		wg.Add(1)
		go func(n int, id string) {
			defer wg.Done()
			select {
			case budget <- struct{}{}:
				defer func() { <-budget }()
			case <-ctx.Done():
				return
			}
			d, e := h.presence.GetDevice(ctx, id)
			if e == nil && d.ID == id && d.TenantID == p.TenantID {
				items[n].Peer.Online = d.Online
				for _, key := range []string{"name", "device_name"} {
					if name, ok := d.Metadata[key].(string); ok && len(name) <= 256 && strings.TrimSpace(name) != "" {
						items[n].Peer.Name = name
						break
					}
				}
			}
		}(n, id)
	}
	wg.Wait()
	return struct {
		Items      []bindingView `json:"items"`
		NextCursor string        `json:"next_cursor,omitempty"`
	}{items, page.NextCursor}
}
