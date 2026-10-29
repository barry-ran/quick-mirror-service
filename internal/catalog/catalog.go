// Package catalog 保存业务设备目录，不把权限快照或最后更新时间视为在线证据。
package catalog

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

const BatchSize = 200

var (
	ErrInvalidInput = errors.New("INVALID_INPUT")
	ErrNotFound     = errors.New("DEVICE_NOT_FOUND")
	ErrStaleStatus  = errors.New("STALE_STATUS")
)

type Permissions struct {
	Projection    bool `json:"projection"`
	Accessibility bool `json:"accessibility"`
	IME           bool `json:"ime"`
}

type Capability struct {
	Supported bool   `json:"supported"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type Status struct {
	BootID       string                `json:"boot_id"`
	Sequence     int64                 `json:"seq"`
	AppVersion   string                `json:"app_version"`
	Permissions  Permissions           `json:"permissions"`
	Capabilities map[string]Capability `json:"capabilities"`
}

type Device struct {
	UUID         string                `json:"uuid"`
	AppVersion   string                `json:"app_version"`
	Permissions  Permissions           `json:"permissions"`
	Capabilities map[string]Capability `json:"capabilities"`
}

type Resolution struct {
	UUID      string  `json:"uuid"`
	Found     bool    `json:"found"`
	Device    *Device `json:"device,omitempty"`
	ErrorCode string  `json:"error_code,omitempty"`
}

func validVersion(version string) bool {
	return utf8.ValidString(version) && len(version) <= 128 && !strings.ContainsRune(version, 0)
}

func (s Status) validate() error {
	if _, ok := identity.NormalizeUUID(s.BootID); !ok || s.Sequence <= 0 || !validVersion(s.AppVersion) || len(s.Capabilities) > 64 {
		return ErrInvalidInput
	}
	for name, capability := range s.Capabilities {
		if name == "" || len(name) > 64 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) || !utf8.ValidString(capability.Reason) || len(capability.Reason) > 256 || strings.ContainsRune(capability.Reason, 0) || (capability.Available && !capability.Supported) {
			return ErrInvalidInput
		}
	}
	return nil
}

func encodeCapabilities(capabilities map[string]Capability) ([]byte, error) {
	if capabilities == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(capabilities)
}
