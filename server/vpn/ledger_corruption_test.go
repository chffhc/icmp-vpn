//go:build linux || darwin

package vpn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLedgerRejectsBitCorruption(t *testing.T) {
	for _, offset := range []int{40, 47, 48, 79} {
		dir := t.TempDir()
		path := filepath.Join(dir, "sessions")
		s, err := OpenFileStore(path, testKey, 4)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Reserve(123); err != nil {
			t.Fatal(err)
		}
		s.Close()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw[offset] ^= 1
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = OpenFileStore(path, testKey, 4); err == nil {
			t.Fatalf("corrupt record byte %d accepted", offset)
		}
	}
}
