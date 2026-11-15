//go:build linux || darwin

package peerloom

import (
	"os"
	"path/filepath"
	"syscall"
)

func lockCredentialDirectory(path string) (func(), error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrManagedCredentialStorage
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, ErrManagedCredentialStorage
	}
	fd, err := syscall.Open(filepath.Join(path, ".qm-renewal.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrManagedCredentialStorage
	}
	file := os.NewFile(uintptr(fd), "credential lock")
	st, e := file.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !ownedFile(st) || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		file.Close()
		return nil, ErrManagedCredentialStorage
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); file.Close() }, nil
}
func persistCredential(path string, data []byte) error {
	directory := filepath.Dir(path)
	f, err := os.CreateTemp(directory, ".qm-credential-*")
	if err != nil {
		return ErrManagedCredentialStorage
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return ErrManagedCredentialStorage
	}
	if os.Rename(name, path) != nil {
		return ErrManagedCredentialStorage
	}
	dir, err := os.Open(directory)
	if err != nil {
		return ErrManagedCredentialStorage
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return ErrManagedCredentialStorage
	}
	return nil
}

func ownedFile(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}

func validManagedFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0 && ownedFile(info)
}
