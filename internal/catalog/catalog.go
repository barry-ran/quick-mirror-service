// Package catalog 保存业务设备目录，不把权限快照或最后更新时间视为在线证据。
package catalog

import (
	"crypto/sha256"
	"encoding/base64"
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

// NavigationActions 保留缺省与显式空列表的区别，拒绝 null 和非字符串元素。
type NavigationActions []string

func (a *NavigationActions) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if string(data) == "null" || json.Unmarshal(data, &raw) != nil || raw == nil {
		return ErrInvalidInput
	}
	result := make(NavigationActions, 0, len(raw))
	for _, item := range raw {
		var action string
		if string(item) == "null" || json.Unmarshal(item, &action) != nil {
			return ErrInvalidInput
		}
		result = append(result, action)
	}
	*a = result
	return nil
}

type Capability struct {
	Supported bool               `json:"supported"`
	Available bool               `json:"available"`
	Reason    string             `json:"reason,omitempty"`
	Actions   *NavigationActions `json:"actions,omitempty"`
}

type Status struct {
	RuntimeProof string                `json:"runtime_proof,omitempty"`
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
	if s.RuntimeProof != "" {
		if _, ok := RuntimeProofHash(s.RuntimeProof); !ok {
			return ErrInvalidInput
		}
	}
	if _, ok := identity.NormalizeUUID(s.BootID); !ok || s.Sequence <= 0 || !validVersion(s.AppVersion) || len(s.Capabilities) > 64 {
		return ErrInvalidInput
	}
	for name, capability := range s.Capabilities {
		if name == "" || len(name) > 64 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) || !utf8.ValidString(capability.Reason) || len(capability.Reason) > 256 || strings.ContainsRune(capability.Reason, 0) || (capability.Available && !capability.Supported) {
			return ErrInvalidInput
		}
	}
	return s.ValidateNavigationActions()
}

func (s Status) ValidateNavigationActions() error {
	for name, c := range s.Capabilities {
		if c.Actions == nil {
			continue
		}
		if name != "navigation_v1" || len(*c.Actions) > 6 {
			return ErrInvalidInput
		}
		seen := map[string]bool{}
		for _, action := range *c.Actions {
			switch action {
			case "back", "home", "recents", "volume_up", "volume_down", "notifications":
			default:
				return ErrInvalidInput
			}
			if seen[action] {
				return ErrInvalidInput
			}
			seen[action] = true
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

// RuntimeProofHash接受32字节随机URL-safe凭证；调用者不得记录或回显原值。
func RuntimeProofHash(proof string) ([]byte, bool) {
	b, e := base64.RawURLEncoding.DecodeString(proof)
	if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != proof {
		return nil, false
	}
	h := sha256.Sum256(b)
	return h[:], true
}
