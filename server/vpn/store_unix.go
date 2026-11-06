//go:build linux || darwin

package vpn

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
)

// FileStore is an exclusive, append-only, key-bound durable session ledger.
// IDs are reserved and fsynced before the first server GCM nonce is used. A
// restart rejects all IDs in the ledger rather than ever resetting sequences.
// Corruption/full storage fails closed. Never delete this ledger with the same
// PSK, including when a client cannot connect; rotate the PSK and ledger together.
type FileStore struct {
	mu       sync.Mutex
	f        *os.File
	key      []byte
	used     map[uint64]struct{}
	limit    int
	poisoned bool
}

func OpenFileStore(path string, psk []byte, limit int) (*FileStore, error) {
	if len(psk) != 32 || limit < 1 || limit > 65536 {
		return nil, errors.New("invalid ledger key/capacity")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return nil, errors.New("ledger must be regular file mode 0600")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("ledger already locked: %w", err)
	}
	// Refresh metadata after locking: another initializer could have completed
	// between our first stat and lock acquisition. Never treat its ledger as empty.
	st, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return nil, errors.New("ledger permissions changed")
	}
	hash := sha256.Sum256(psk)
	header := append([]byte("IVP1IDS2"), hash[:]...)
	if st.Size() == 0 {
		if _, err = f.Write(header); err != nil {
			return nil, err
		}
		if err = f.Sync(); err != nil {
			return nil, err
		}
		if err = syncDirectory(path); err != nil {
			return nil, err
		}
	} else {
		if st.Size() < 40 || (st.Size()-40)%40 != 0 || st.Size() > 40+65536*40 {
			return nil, errors.New("invalid/truncated session ledger")
		}
		got := make([]byte, 40)
		if _, err = f.ReadAt(got, 0); err != nil {
			return nil, err
		}
		if !bytes.Equal(got, header) {
			return nil, errors.New("ledger key binding mismatch")
		}
	}
	s := &FileStore{f: f, key: append([]byte(nil), psk...), used: make(map[uint64]struct{}), limit: limit}
	if _, err = f.Seek(40, io.SeekStart); err != nil {
		return nil, err
	}
	var record [40]byte
	for {
		_, err = io.ReadFull(f, record[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if !hmac.Equal(record[8:], ledgerTag(psk, record[:8])) {
			return nil, errors.New("session ledger record authentication failed")
		}
		id := binary.BigEndian.Uint64(record[:8])
		if _, dup := s.used[id]; id == 0 || dup {
			return nil, errors.New("invalid/duplicate ledger ID")
		}
		s.used[id] = struct{}{}
	}
	ok = true
	return s, nil
}
func (s *FileStore) Reserve(id uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned {
		return errors.New("session ledger write previously failed")
	}
	if id == 0 {
		return errors.New("zero session")
	}
	if _, ok := s.used[id]; ok {
		return ErrSessionUsed
	}
	if len(s.used) >= s.limit {
		return ErrSessionCapacity
	}
	var b [40]byte
	binary.BigEndian.PutUint64(b[:8], id)
	copy(b[8:], ledgerTag(s.key, b[:8]))
	n, err := s.f.Write(b[:])
	if err != nil || n != len(b) {
		s.poisoned = true
		if err == nil {
			err = io.ErrShortWrite
		}
		return fmt.Errorf("session ledger write: %w", err)
	}
	// Mark before Sync so even an fsync error cannot cause a nonce reuse retry.
	s.used[id] = struct{}{}
	if err = s.f.Sync(); err != nil {
		s.poisoned = true
		return fmt.Errorf("session ledger sync: %w", err)
	}
	return nil
}
func ledgerTag(psk, id []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("icmp-vpn-v1/session-ledger/"))
	mac.Write(id)
	return mac.Sum(nil)
}
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.poisoned = true
	return s.f.Close()
}
