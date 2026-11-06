//go:build linux || darwin

package vpn

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestEngineRestartRejectsOldHello(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions")
	src := netip.MustParseAddr("192.0.2.1")
	now := time.Now()
	request := frame(t, 123, 1, Hello, nil)
	store, err := OpenFileStore(path, testKey, 4)
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := NewEngine(testKey, Options{Store: store})
	first, err := engine.Handle(src, request, now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Open(testKey, ServerToClient, first.Reply)
	if err != nil || a.Sequence != 1 {
		t.Fatal("initial nonce", err)
	}
	repeat, err := engine.Handle(src, frame(t, 123, 2, Hello, nil), now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(testKey, ServerToClient, repeat.Reply)
	if err != nil || b.Sequence != 2 {
		t.Fatal("repeat HELLO reset nonce", err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenFileStore(path, testKey, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine, _ = NewEngine(testKey, Options{Store: store})
	got, err := engine.Handle(src, request, now)
	if !errors.Is(err, ErrSessionUsed) || got.Reply != nil {
		t.Fatalf("restart replay produced reply: %x %v", got.Reply, err)
	}
	got, err = engine.Handle(src, frame(t, 124, 1, Hello, nil), now)
	if err != nil {
		t.Fatal("fresh session after restart", err)
	}
	m, _ := Open(testKey, ServerToClient, got.Reply)
	if m.SessionID != 124 || m.Sequence != 1 {
		t.Fatal("fresh session nonce")
	}
}

type brokenStore struct{}

func (brokenStore) Reserve(uint64) error { return errors.New("injected storage failure") }
func TestReservationFailureNoReplyOrSession(t *testing.T) {
	engine, _ := NewEngine(testKey, Options{Store: brokenStore{}})
	got, err := engine.Handle(netip.MustParseAddr("192.0.2.1"), frame(t, 1, 1, Hello, nil), time.Now())
	if !errors.Is(err, ErrSessionStore) || got.Reply != nil || engine.Stats().Active {
		t.Fatalf("storage failure did not fail closed: %+v %v", got, err)
	}
}
func TestLedgerWriteFailurePoisoned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions")
	s, err := OpenFileStore(path, testKey, 4)
	if err != nil {
		t.Fatal(err)
	}
	s.f.Close() // inject descriptor/storage failure before first reservation
	if err = s.Reserve(1); err == nil {
		t.Fatal("closed descriptor write accepted")
	}
	if err = s.Reserve(2); err == nil {
		t.Fatal("poisoned ledger continued")
	}
}
