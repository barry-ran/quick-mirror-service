package peerloom

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

var ErrDeviceNotFound = errors.New("peerloom device not found")

// ControlClient只操作正式公开API，不自动重试变更、不读取Peerloom私表。
type ControlClient struct {
	identity           *IdentityClient
	origin, credential string
	grantTTLSeconds    int
}
type ControlGrant struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	SourceDeviceID string     `json:"source_device_id"`
	TargetDeviceID string     `json:"target_device_id"`
	ExpiresAt      time.Time  `json:"expires_at"`
	ExpiryAction   string     `json:"expiry_action"`
	MaxSessions    int        `json:"max_sessions"`
	RevokedAt      *time.Time `json:"revoked_at"`
}
type ControlSession struct {
	ID                   string    `json:"session_id"`
	TenantID             string    `json:"tenant_id"`
	SourceDeviceID       string    `json:"source_device_id"`
	TargetDeviceID       string    `json:"target_device_id"`
	GrantID              string    `json:"grant_id"`
	State                string    `json:"state"`
	SourceLeaseExpiresAt time.Time `json:"source_lease_expires_at"`
	TargetLeaseExpiresAt time.Time `json:"target_lease_expires_at"`
}
type ControlDevice struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	ApplicationID string `json:"application_id"`
	Status        string `json:"status"`
	Online        *bool  `json:"online"`
}

func NewControlClient(c IdentityConfig, credential string, client *http.Client) (*ControlClient, error) {
	return NewControlClientWithGrantTTL(c, credential, client, 300)
}

// NewControlClientWithGrantTTL固定本实例的建连窗口；不是既有session的控制时长。
func NewControlClientWithGrantTTL(c IdentityConfig, credential string, client *http.Client, seconds int) (*ControlClient, error) {
	if seconds < 1 || seconds > 30*24*3600 {
		return nil, ErrInvalidRegistration
	}
	if !visibleASCII(credential, 1, 512) {
		return nil, identity.ErrUnavailable
	}
	id, err := NewIdentityClient(c, client)
	if err != nil {
		return nil, err
	}
	return &ControlClient{identity: id, origin: strings.TrimSuffix(id.endpoint, "/v1/device-self"), credential: credential, grantTTLSeconds: seconds}, nil
}
func (c *ControlClient) ReplayDomain() string {
	b, _ := json.Marshal([]string{c.origin, c.identity.tenantID, c.credential})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (c *ControlClient) request(ctx context.Context, method, path, key string, body any, out any) error {
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return ErrInvalidRegistration
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, bytes.NewReader(raw))
	if err != nil {
		return identity.ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+c.credential)
	req.Header.Set("Accept", "application/json")
	if method != http.MethodGet || key != "" {
		if !visibleASCII(key, 8, 128) {
			return ErrInvalidRegistration
		}
		req.Header.Set("Idempotency-Key", key)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	unknown := identity.ErrUnavailable
	if method != http.MethodGet {
		unknown = ErrOutcomeUnknown
	}
	resp, err := c.identity.client.Do(req)
	if err != nil {
		return unknown
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (256<<10)+1))
	if err != nil || len(data) > 256<<10 {
		return unknown
	}
	// Only a device lookup has business not-found semantics. Grant/session
	// absence must never be interpreted as evidence that an old gate drained.
	if method == http.MethodGet && strings.HasPrefix(path, "/v1/devices/") && resp.StatusCode == http.StatusNotFound {
		return ErrDeviceNotFound
	}
	if resp.StatusCode != http.StatusOK && !(method == http.MethodPost && resp.StatusCode == http.StatusCreated) {
		return unknown
	}
	if json.Unmarshal(data, out) != nil {
		return unknown
	}
	return nil
}
func (c *ControlClient) validGrant(g ControlGrant) bool {
	_, id := identity.NormalizeUUID(g.ID)
	_, source := identity.NormalizeUUID(g.SourceDeviceID)
	_, target := identity.NormalizeUUID(g.TargetDeviceID)
	return id && source && target && g.TenantID == c.identity.tenantID && !g.ExpiresAt.IsZero() && g.SourceDeviceID != g.TargetDeviceID && (g.ExpiryAction == "terminate" || g.ExpiryAction == "no_new_connections")
}
func (c *ControlClient) CreateGrant(ctx context.Context, source, target, key string) (ControlGrant, error) {
	var g ControlGrant
	source, a := identity.NormalizeUUID(source)
	target, b := identity.NormalizeUUID(target)
	if !a || !b || source == target {
		return g, ErrInvalidRegistration
	}
	// 到期仅禁止新建连接；已建立session按公开SDK租约续期，close必须显式revoke。
	body := map[string]any{"source_device_id": source, "target_device_id": target, "expires_in_seconds": c.grantTTLSeconds, "expiry_action": "no_new_connections", "max_sessions": 1}
	if err := c.request(ctx, http.MethodPost, "/v1/connection-grants", key, body, &g); err != nil {
		return g, err
	}
	if !c.validGrant(g) || g.SourceDeviceID != source || g.TargetDeviceID != target || g.ExpiryAction != "no_new_connections" || g.MaxSessions != 1 || g.RevokedAt != nil {
		return ControlGrant{}, ErrOutcomeUnknown
	}
	return g, nil
}
func (c *ControlClient) GetGrant(ctx context.Context, id string) (ControlGrant, error) {
	var g ControlGrant
	id, ok := identity.NormalizeUUID(id)
	if !ok {
		return g, ErrInvalidRegistration
	}
	if err := c.request(ctx, http.MethodGet, "/v1/connection-grants/"+id, "", nil, &g); err != nil {
		return g, err
	}
	if !c.validGrant(g) || g.ID != id {
		return ControlGrant{}, identity.ErrUnavailable
	}
	return g, nil
}
func (c *ControlClient) RevokeGrant(ctx context.Context, id, key string) error {
	id, ok := identity.NormalizeUUID(id)
	if !ok {
		return ErrInvalidRegistration
	}
	var out struct {
		ID      string `json:"id"`
		Revoked bool   `json:"revoked"`
	}
	if err := c.request(ctx, http.MethodDelete, "/v1/connection-grants/"+id, key, nil, &out); err != nil {
		return err
	}
	if out.ID != id || !out.Revoked {
		return ErrOutcomeUnknown
	}
	return nil
}
func (c *ControlClient) GetSession(ctx context.Context, id string) (ControlSession, error) {
	var s ControlSession
	id, ok := identity.NormalizeUUID(id)
	if !ok {
		return s, ErrInvalidRegistration
	}
	// 管理GET返回id且不含tenant_id，不是设备授权接口的session_id结构。
	// 用公开grant查询再次核验租户及双方，不把配置值冒充响应中的身份事实。
	var wire struct {
		ID                   string    `json:"id"`
		SourceDeviceID       string    `json:"source_device_id"`
		TargetDeviceID       string    `json:"target_device_id"`
		GrantID              string    `json:"grant_id"`
		State                string    `json:"state"`
		SourceLeaseExpiresAt time.Time `json:"source_lease_expires_at"`
		TargetLeaseExpiresAt time.Time `json:"target_lease_expires_at"`
	}
	if err := c.request(ctx, http.MethodGet, "/v1/sessions/"+id, "", nil, &wire); err != nil {
		return s, err
	}
	_, a := identity.NormalizeUUID(wire.SourceDeviceID)
	_, b := identity.NormalizeUUID(wire.TargetDeviceID)
	_, g := identity.NormalizeUUID(wire.GrantID)
	if wire.ID != id || !a || !b || !g || wire.SourceDeviceID == wire.TargetDeviceID {
		return s, identity.ErrUnavailable
	}
	switch wire.State {
	case "requested", "authorizing", "connecting", "connected", "reconnecting", "closed":
	default:
		return s, identity.ErrUnavailable
	}
	if wire.State != "closed" && (wire.SourceLeaseExpiresAt.IsZero() || wire.TargetLeaseExpiresAt.IsZero()) {
		return s, identity.ErrUnavailable
	}
	grant, err := c.GetGrant(ctx, wire.GrantID)
	if err != nil || grant.SourceDeviceID != wire.SourceDeviceID || grant.TargetDeviceID != wire.TargetDeviceID {
		return s, identity.ErrUnavailable
	}
	return ControlSession{ID: wire.ID, TenantID: grant.TenantID, SourceDeviceID: wire.SourceDeviceID, TargetDeviceID: wire.TargetDeviceID, GrantID: wire.GrantID, State: wire.State, SourceLeaseExpiresAt: wire.SourceLeaseExpiresAt, TargetLeaseExpiresAt: wire.TargetLeaseExpiresAt}, nil
}
func (c *ControlClient) GetDevice(ctx context.Context, id string) (ControlDevice, error) {
	var d ControlDevice
	id, ok := identity.NormalizeUUID(id)
	if !ok {
		return d, ErrInvalidRegistration
	}
	if err := c.request(ctx, http.MethodGet, "/v1/devices/"+id, "", nil, &d); err != nil {
		return d, err
	}
	_, app := identity.NormalizeUUID(d.ApplicationID)
	if d.ID != id || d.TenantID != c.identity.tenantID || !app || (d.Status != "active" && d.Status != "revoked") {
		return ControlDevice{}, identity.ErrUnavailable
	}
	return d, nil
}
