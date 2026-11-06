//go:build linux || darwin

package vpn

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func syncDirectory(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// GenerateKey exclusively creates a raw 32-byte PSK (mode 0600). Existing paths,
// including symlinks, are never overwritten. Use a trusted private directory.
func GenerateKey(path string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	n, err := f.Write(key)
	if err != nil {
		return err
	}
	if n != len(key) {
		return io.ErrShortWrite
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = syncDirectory(path); err != nil {
		return err
	}
	ok = true
	return nil
}
func ReadKey(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() != 32 {
		return nil, errors.New("key must be a regular raw 32-byte file with mode 0600")
	}
	key := make([]byte, 32)
	if _, err = io.ReadFull(f, key); err != nil {
		return nil, err
	}
	return key, nil
}
