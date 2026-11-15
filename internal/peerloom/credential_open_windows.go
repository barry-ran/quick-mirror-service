//go:build windows

package peerloom

import (
	"os"
	"strings"
)

func openCredentialFile(path string) (*os.File, error) {
	// Restrict to trusted local filesystem paths, not UNC devices or named pipes.
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") {
		return nil, ErrCredentialUnavailable
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrCredentialUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, ErrCredentialUnavailable
	}
	return f, nil
}
