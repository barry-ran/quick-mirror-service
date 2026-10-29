// Package peerloom 仅通过 Peerloom 公开 HTTP 接口集成，不引用其源码或数据库。
package peerloom

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/access"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

const maxIdentityResponse = 64 << 10

// IdentityConfig 中的 application 映射由运营部署配置提供，不能由请求方选择。
type IdentityConfig struct {
	Origin              string
	TenantID            string
	PCApplicationID     string
	MobileApplicationID string
}

type IdentityClient struct {
	endpoint            string
	tenantID            string
	pcApplicationID     string
	mobileApplicationID string
	client              *http.Client
}

// NewIdentityClient 复制 HTTP client 并禁止重定向，避免凭证被转发至其他端点。
// 允许注入具有私有 CA 信任的 Transport，不支持跳过 TLS 的生产开关。
func NewIdentityClient(config IdentityConfig, client *http.Client) (*IdentityClient, error) {
	origin, err := url.Parse(config.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, errors.New("Peerloom origin must be an HTTPS origin")
	}
	tenant, validTenant := identity.NormalizeUUID(config.TenantID)
	pc, validPC := identity.NormalizeUUID(config.PCApplicationID)
	mobile, validMobile := identity.NormalizeUUID(config.MobileApplicationID)
	if !validTenant || !validPC || !validMobile || pc == mobile {
		return nil, errors.New("distinct PC/mobile application UUIDs and tenant UUID are required")
	}
	httpClient := http.Client{Timeout: 5 * time.Second}
	if client != nil {
		httpClient = *client
		if httpClient.Timeout <= 0 || httpClient.Timeout > 5*time.Second {
			httpClient.Timeout = 5 * time.Second
		}
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	origin.Path = "/v1/device-self"
	return &IdentityClient{endpoint: origin.String(), tenantID: tenant, pcApplicationID: pc, mobileApplicationID: mobile, client: &httpClient}, nil
}

type identityResponse struct {
	Principal identity.Principal
	Expiry    json.RawMessage
}

func (c *IdentityClient) Verify(ctx context.Context, credential string) (identity.Principal, error) {
	result, err := c.fetchIdentity(ctx, credential)
	return result.Principal, err
}

// VerifyCredential 适配待发布的公开期限字段；缺字段时失败关闭，不猜测客户端期限。
// 当前仅有契约夹具验证，未挂载生产 exchange，须等待上游发布及真实联调。
func (c *IdentityClient) VerifyCredential(ctx context.Context, credential string) (access.VerifiedCredential, error) {
	var empty access.VerifiedCredential
	result, err := c.fetchIdentity(ctx, credential)
	if err != nil {
		return empty, err
	}
	var value string
	if len(result.Expiry) == 0 || json.Unmarshal(result.Expiry, &value) != nil || value == "" {
		return empty, identity.ErrUnavailable
	}
	expiry, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || expiry.IsZero() {
		return empty, identity.ErrUnavailable
	}
	// 与数据库时钟比较及15分钟上界在 access.Store 内执行，避免宿主时钟代替权威时钟。
	return access.VerifiedCredential{Principal: result.Principal, ExpiresAt: expiry.UTC()}, nil
}

func (c *IdentityClient) fetchIdentity(ctx context.Context, credential string) (identityResponse, error) {
	var empty identityResponse
	if len(credential) == 0 || len(credential) > 512 || strings.IndexFunc(credential, func(r rune) bool { return r <= ' ' || r >= 127 }) >= 0 {
		return empty, identity.ErrInvalidCredential
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return empty, identity.ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Accept", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		// 不把请求 URL、凭证或内部网络错误暴露给外部调用者。
		return empty, identity.ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		return empty, identity.ErrInvalidCredential
	}
	if response.StatusCode == http.StatusForbidden {
		return empty, identity.ErrForbidden
	}
	if response.StatusCode != http.StatusOK {
		return empty, identity.ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxIdentityResponse+1))
	if err != nil || len(data) > maxIdentityResponse {
		return empty, identity.ErrUnavailable
	}
	var device struct {
		DeviceID            string          `json:"device_id"`
		ApplicationID       string          `json:"application_id"`
		TenantID            string          `json:"tenant_id"`
		CredentialExpiresAt json.RawMessage `json:"credential_expires_at"`
	}
	if err := json.Unmarshal(data, &device); err != nil {
		return empty, identity.ErrUnavailable
	}
	id, validID := identity.NormalizeUUID(device.DeviceID)
	tenant, validTenant := identity.NormalizeUUID(device.TenantID)
	application, validApplication := identity.NormalizeUUID(device.ApplicationID)
	if !validID || !validTenant || !validApplication {
		return empty, identity.ErrUnavailable
	}
	if tenant != c.tenantID {
		return empty, identity.ErrForbidden
	}
	var role identity.Role
	switch application {
	case c.pcApplicationID:
		role = identity.PC
	case c.mobileApplicationID:
		role = identity.Mobile
	default:
		return empty, identity.ErrForbidden
	}
	return identityResponse{Principal: identity.Principal{DeviceID: id, TenantID: tenant, ApplicationID: application, Role: role}, Expiry: device.CredentialExpiresAt}, nil
}
