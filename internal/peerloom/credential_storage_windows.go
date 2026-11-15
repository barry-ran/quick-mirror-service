//go:build windows

package peerloom

import "os"

func lockCredentialDirectory(string) (func(), error) { return nil, ErrManagedCredentialUnsupported }
func persistCredential(string, []byte) error         { return ErrManagedCredentialUnsupported }

func validManagedFile(os.FileInfo) bool { return false }
