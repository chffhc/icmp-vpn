package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeygenCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := run([]string{"keygen", "--key-file", path}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"keygen", "--key-file", path}); err == nil {
		t.Fatal("keygen overwrote existing file")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || len(after) != 32 {
		t.Fatal("key altered")
	}
}
func TestCLIRejectsQueueOptionsBeforeKeyOrNetwork(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--queue-discipline", "unknown"}, "queue discipline"},
		{[]string{"--queue-discipline", "FIFO"}, "queue discipline"},
		{[]string{"--queue-discipline", ""}, "queue discipline"},
		{[]string{"--queue-limit", "0"}, "queue limit"},
		{[]string{"--queue-limit", "-1"}, "queue limit"},
		{[]string{"--queue-limit", "4097"}, "queue limit"},
	} {
		args := append([]string{"serve", "--key-file", filepath.Join(t.TempDir(), "missing")}, tc.args...)
		err := run(args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: %v, want %q", args, err, tc.want)
		}
	}
	// Recognized values proceed past validation to key reading, not network I/O.
	for _, discipline := range []string{"fifo", "fq-codel"} {
		err := run([]string{"serve", "--key-file", filepath.Join(t.TempDir(), "missing"), "--queue-discipline", discipline, "--queue-limit", "4096"})
		if err == nil || !strings.HasPrefix(err.Error(), "key:") {
			t.Fatalf("%q: %v", discipline, err)
		}
	}
}

func TestCLIRejectsArgumentsBeforeNetwork(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"keygen"}, {"serve"}, {"serve", "--key-file", "nope", "--listen", "::1"}, {"serve", "--key-file", "nope", "--listen", "example.com"}} {
		if err := run(args); err == nil {
			t.Fatalf("accepted %+v", args)
		}
	}
}
