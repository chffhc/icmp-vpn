//go:build linux || darwin

package vpn

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyGenerationAndLoading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := GenerateKey(path); err != nil {
		t.Fatal(err)
	}
	a, err := ReadKey(path)
	if err != nil || len(a) != 32 {
		t.Fatalf("read key %v", err)
	}
	if err = GenerateKey(path); err == nil {
		t.Fatal("overwrote key")
	}
	b, _ := ReadKey(path)
	if !bytes.Equal(a, b) {
		t.Fatal("key changed")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadKey(path); err == nil {
		t.Fatal("insecure key accepted")
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadKey(link); err == nil {
		t.Fatal("symlink key accepted")
	}
	if err = GenerateKey(link); err == nil {
		t.Fatal("overwrote symlink")
	}
}
func TestDurableSessionLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions")
	s, err := OpenFileStore(path, testKey, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Reserve(100); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenFileStore(path, testKey, 2); err == nil {
		t.Fatal("concurrent ledger open")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenFileStore(path, testKey, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Reserve(100); !errors.Is(err, ErrSessionUsed) {
		t.Fatalf("restart reused nonce %v", err)
	}
	if err = s.Reserve(101); err != nil {
		t.Fatal(err)
	}
	if err = s.Reserve(102); !errors.Is(err, ErrSessionCapacity) {
		t.Fatalf("capacity %v", err)
	}
	s.Close()
	if _, err = OpenFileStore(path, bytes.Repeat([]byte{1}, 32), 2); err == nil {
		t.Fatal("wrong key bound ledger")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{1})
	f.Close()
	if _, err = OpenFileStore(path, testKey, 2); err == nil {
		t.Fatal("truncated record accepted")
	}
}
func TestLedgerPermissionsAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path, testKey, 2); err == nil {
		t.Fatal("insecure ledger accepted")
	}
	link := filepath.Join(dir, "link")
	os.Symlink(path, link)
	if _, err := OpenFileStore(link, testKey, 2); err == nil {
		t.Fatal("symlink ledger accepted")
	}
}
