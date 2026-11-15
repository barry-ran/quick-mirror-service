//go:build linux || darwin

package peerloom

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCredentialAtomicReplacementAndSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("svc_old"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := NewFileCredentialSource(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("svc_new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if value, err := source.Read(); err != nil || value != "svc_new" {
		t.Fatal("rename not observed")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileCredentialSource(link); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatal("symlink accepted")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileCredentialSource(fifo); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatal("fifo accepted")
	}
}
