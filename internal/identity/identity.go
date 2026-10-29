// Package identity 定义业务服务信任的安装身份，不代表原产品付费权益。
package identity

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

type Role string

const (
	PC     Role = "pc"
	Mobile Role = "mobile"
)

var (
	ErrInvalidCredential = errors.New("AUTH_INVALID")
	ErrForbidden         = errors.New("INSTALLATION_FORBIDDEN")
	ErrUnavailable       = errors.New("SERVICE_UNAVAILABLE")
	uuidPattern          = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// Principal 只能由可信安装凭证校验结果构造，不能从客户端角色字段填充。
type Principal struct {
	DeviceID      string
	ApplicationID string
	TenantID      string
	Role          Role
}

type Verifier interface {
	Verify(context.Context, string) (Principal, error)
}

func NormalizeUUID(value string) (string, bool) {
	if !uuidPattern.MatchString(value) {
		return "", false
	}
	return strings.ToLower(value), true
}
