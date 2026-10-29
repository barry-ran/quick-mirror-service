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

var (
	ErrInvalidRegistration = errors.New("INVALID_INPUT")
	ErrIdempotencyConflict = errors.New("IDEMPOTENCY_CONFLICT")
	ErrReplayExpired       = errors.New("REPLAY_EXPIRED")
	ErrOutcomeUnknown      = errors.New("OUTCOME_UNKNOWN")
)

type RegistrationGrant struct {
	ID        string    `json:"id"`
	Grant     string    `json:"grant"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RegistrationClient 只给服务端使用。凭证须是固定租户的 admin service credential，
// 不得接受客户端传入的 application、管理凭证或目标 URL。
type RegistrationClient struct {
	endpoint   string
	credential string
	pc         string
	mobile     string
	client     *http.Client
}

// ReplayDomain 是部署/凭证/app 映射的不可逆标识，不是认证凭证。
// Peerloom 将幂等域绑定到管理凭证；轮换后旧尝试必须拒绝重发，而不能新签一个 grant。
func (c *RegistrationClient) ReplayDomain() string {
	value, _ := json.Marshal([]string{c.endpoint, c.credential, c.pc, c.mobile})
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func NewRegistrationClient(config IdentityConfig, serviceCredential string, client *http.Client) (*RegistrationClient, error) {
	if !visibleASCII(serviceCredential, 1, 512) {
		return nil, ErrInvalidRegistration
	}
	validated, err := NewIdentityClient(config, client)
	if err != nil {
		return nil, err
	}
	return &RegistrationClient{
		endpoint:   strings.TrimSuffix(validated.endpoint, "/v1/device-self") + "/v1/registration-grants",
		credential: serviceCredential, pc: validated.pcApplicationID,
		mobile: validated.mobileApplicationID, client: validated.client,
	}, nil
}

// Issue 不自动重试。结果未知时调用方只能保留原 key/参数查询或重试，不能换 key 重发。
// 公开接口的幂等窗口有期限，本 adapter 不承诺永久幂等或业务 bootstrap 的完整实现。
func (c *RegistrationClient) Issue(ctx context.Context, role identity.Role, key string, ttlSeconds int) (RegistrationGrant, error) {
	var empty RegistrationGrant
	if !visibleASCII(key, 8, 128) || ttlSeconds < 0 || ttlSeconds > 3600 {
		return empty, ErrInvalidRegistration
	}
	application := ""
	switch role {
	case identity.PC:
		application = c.pc
	case identity.Mobile:
		application = c.mobile
	default:
		return empty, ErrInvalidRegistration
	}
	if ttlSeconds == 0 {
		ttlSeconds = 300
	}
	body, err := json.Marshal(struct {
		ApplicationID    string `json:"application_id"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}{application, ttlSeconds})
	if err != nil {
		return empty, ErrInvalidRegistration
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return empty, identity.ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+c.credential)
	req.Header.Set("Idempotency-Key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		// 即使超时，服务端也可能已经提交；不暴露 URL、管理密钥或传输错误。
		return empty, ErrOutcomeUnknown
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxIdentityResponse+1))
	if err != nil || len(data) > maxIdentityResponse {
		return empty, ErrOutcomeUnknown
	}
	if response.StatusCode == http.StatusConflict {
		var failure struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(data, &failure) == nil {
			switch failure.Code {
			case "IDEMPOTENCY_CONFLICT":
				return empty, ErrIdempotencyConflict
			case "REPLAY_EXPIRED":
				return empty, ErrReplayExpired
			}
		}
	}
	if response.StatusCode != http.StatusCreated {
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusUnprocessableEntity {
			return empty, identity.ErrUnavailable
		}
		return empty, ErrOutcomeUnknown
	}
	var grant RegistrationGrant
	if json.Unmarshal(data, &grant) != nil {
		return empty, ErrOutcomeUnknown
	}
	id, valid := identity.NormalizeUUID(grant.ID)
	if !valid || !visibleASCII(grant.Grant, 1, 512) || grant.ExpiresAt.IsZero() {
		return empty, ErrOutcomeUnknown
	}
	if !grant.ExpiresAt.After(time.Now()) {
		return empty, ErrReplayExpired
	}
	grant.ID = id
	return grant, nil
}

func visibleASCII(value string, min, max int) bool {
	return len(value) >= min && len(value) <= max && strings.IndexFunc(value, func(r rune) bool { return r < 33 || r > 126 }) < 0
}
