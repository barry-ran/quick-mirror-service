//go:build linux || darwin

package peerloom

import (
	"os"
	"syscall"
)

func openCredentialFile(path string) (*os.File, error) {
	// A replacement FIFO must not block and the final path may not be a symlink.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	return os.NewFile(uintptr(fd), path), nil
}
