package peerloom

import (
	"encoding/json"
	"errors"
	"io"

	"path/filepath"
	"strings"
)

var ErrCredentialUnavailable = errors.New("PEERLOOM_CREDENTIAL_UNAVAILABLE")

// CredentialSource returns a bounded credential snapshot. It never caches a failed read.
type CredentialSource interface{ Read() (string, error) }

type fileCredential struct{ path string }

// NewFileCredentialSource validates the initial file without retaining its secret.
// Operators replace a file atomically inside a mounted directory, not a file bind mount.
func NewFileCredentialSource(path string) (CredentialSource, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrCredentialUnavailable
	}
	s := &fileCredential{path: path}
	if _, err := s.Read(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *fileCredential) Read() (string, error) {
	f, err := openCredentialFile(s.path)
	if err != nil {
		return "", ErrCredentialUnavailable
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", ErrCredentialUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	if err != nil || len(data) > 16<<10 {
		return "", ErrCredentialUnavailable
	}
	// device-admin setup/issue output can be mounted directly, without extracting secrets.
	if strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		var result struct {
			ServiceCredential string `json:"service_credential"`
		}
		if json.Unmarshal(data, &result) != nil || !visibleASCII(result.ServiceCredential, 1, 512) {
			return "", ErrCredentialUnavailable
		}
		return result.ServiceCredential, nil
	}
	// Accept one conventional line ending, never embedded whitespace or extra lines.
	value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if !visibleASCII(value, 1, 512) {
		return "", ErrCredentialUnavailable
	}
	return value, nil
}
