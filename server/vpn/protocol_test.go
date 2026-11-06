package vpn

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

var testKey = bytes.Repeat([]byte{0x42}, 32)

func frame(t *testing.T, sid, seq uint64, kind Kind, p []byte) []byte {
	t.Helper()
	b, err := Seal(testKey, ClientToServer, Message{SessionID: sid, Sequence: seq, Kind: kind, Payload: p})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func ipPacket(src, dst string) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	a := netip.MustParseAddr(src).As4()
	b := netip.MustParseAddr(dst).As4()
	copy(p[12:16], a[:])
	copy(p[16:20], b[:])
	binary.BigEndian.PutUint16(p[24:26], 8)
	binary.BigEndian.PutUint16(p[10:12], Checksum(p[:20]))
	return p
}
func TestProtocolAuthentication(t *testing.T) {
	b := frame(t, 42, 1, Hello, nil)
	m, err := Open(testKey, ClientToServer, b)
	if err != nil || m.SessionID != 42 || m.Sequence != 1 {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := Open(testKey, ServerToClient, b); err == nil {
		t.Fatal("reflection authenticated")
	}
	for i := range b {
		c := append([]byte(nil), b...)
		c[i] ^= 1
		if _, err := Open(testKey, ClientToServer, c); err == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
	for _, c := range [][]byte{b[:len(b)-1], append(append([]byte(nil), b...), 0), nil} {
		if _, err := Open(testKey, ClientToServer, c); err == nil {
			t.Fatal("invalid length accepted")
		}
	}
	for _, m := range []Message{{42, 0, Hello, nil}, {0, 1, Hello, nil}, {42, 1, Kind(4), nil}, {42, 1, Poll, []byte{1}}, {42, 1, Close, []byte{1}}, {42, 1, IP, make([]byte, 1201)}} {
		if _, err := Seal(testKey, ClientToServer, m); err == nil {
			t.Fatalf("invalid message accepted: %+v", m)
		}
	}
}
func TestReplay(t *testing.T) {
	var w ReplayWindow
	for _, n := range []uint64{1, 3, 2, 32772, 32771, 5} {
		if !w.Accept(n) {
			t.Fatalf("reject %d", n)
		}
	}
	for _, n := range []uint64{0, 1, 2, 3, 4, 5, 32771, 32772} {
		if w.Accept(n) {
			t.Fatalf("accept replay %d", n)
		}
	}
	if !w.Accept(6) || !w.Accept(100000) || w.Accept(6) {
		t.Fatal("shift handling")
	}
}
func TestEngineSessionIsolationAndQueue(t *testing.T) {
	for _, discipline := range []QueueDiscipline{QueueFIFO, QueueFQCoDel} {
		t.Run(string(discipline), func(t *testing.T) {
			now := time.Unix(1000, 0)
			a := netip.MustParseAddr("192.0.2.1")
			b := netip.MustParseAddr("192.0.2.2")
			e, err := NewEngine(testKey, Options{QueueDiscipline: discipline, QueueLimit: 2, MaxSessions: 2})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = e.Handle(a, frame(t, 1, 1, Poll, nil), now); err == nil {
				t.Fatal("poll before hello")
			}
			r, err := e.Handle(a, frame(t, 1, 1, Hello, nil), now)
			if err != nil {
				t.Fatal(err)
			}
			m, err := Open(testKey, ServerToClient, r.Reply)
			if err != nil || string(m.Payload) != HelloConfig || m.Sequence != 1 {
				t.Fatalf("hello %+v %v", m, err)
			}
			down := ipPacket("8.8.8.8", "10.77.0.2")
			if err = e.Enqueue(down, now); err != nil {
				t.Fatal(err)
			}
			if _, err = e.Handle(a, frame(t, 1, 1, Hello, nil), now); err == nil {
				t.Fatal("replay accepted")
			}
			if _, err = e.Handle(b, frame(t, 1, 2, Poll, nil), now); err == nil {
				t.Fatal("migration accepted")
			}
			if _, err = e.Handle(b, frame(t, 2, 1, Hello, nil), now); err == nil {
				t.Fatal("takeover accepted")
			}
			r, err = e.Handle(a, frame(t, 1, 2, Poll, nil), now)
			if err != nil {
				t.Fatal(err)
			}
			m, err = Open(testKey, ServerToClient, r.Reply)
			if err != nil || m.Kind != IP || !bytes.Equal(m.Payload, down) || m.Sequence != 2 {
				t.Fatalf("queue changed %+v %v", m, err)
			}
			r, err = e.Handle(a, frame(t, 1, 3, Hello, nil), now)
			if err != nil {
				t.Fatal(err)
			}
			m, _ = Open(testKey, ServerToClient, r.Reply)
			if m.Sequence != 3 {
				t.Fatal("hello reset nonce")
			}
			up := ipPacket("10.77.0.2", "8.8.8.8")
			r, err = e.Handle(a, frame(t, 1, 4, IP, up), now)
			if err != nil || !bytes.Equal(r.Upstream, up) {
				t.Fatalf("IP forwarding %v", err)
			}
			if _, err = e.Handle(a, frame(t, 1, 5, Close, nil), now); err != nil {
				t.Fatal(err)
			}
			if _, err = e.Handle(a, frame(t, 1, 6, Hello, nil), now); err == nil {
				t.Fatal("closed session reused")
			}
			if _, err = e.Handle(a, frame(t, 2, 1, Hello, nil), now); err != nil {
				t.Fatal(err)
			}
			if _, err = e.Handle(a, frame(t, 3, 1, Hello, nil), now.Add(121*time.Second)); err == nil {
				t.Fatal("tombstone capacity bypass")
			}
		})
	}
}
func TestIPv4ValidationAndReplayNotPoisoned(t *testing.T) {
	for _, discipline := range []QueueDiscipline{QueueFIFO, QueueFQCoDel} {
		t.Run(string(discipline), func(t *testing.T) {
			now := time.Unix(1000, 0)
			a := netip.MustParseAddr("192.0.2.1")
			e, _ := NewEngine(testKey, Options{QueueDiscipline: discipline})
			e.Handle(a, frame(t, 1, 1, Hello, nil), now)
			good := ipPacket("10.77.0.2", "8.8.8.8")
			mutations := []func([]byte){func(p []byte) { p[0] = 0x65 }, func(p []byte) { p[0] = 0x44 }, func(p []byte) { p[0] = 0x4f }, func(p []byte) { p[2] = 1 }, func(p []byte) { p[12] = 11 }, func(p []byte) { p[6] = 0x20 }, func(p []byte) { p[7] = 1 }, func(p []byte) { p[6] = 0x80 }}
			for i, f := range mutations {
				p := append([]byte(nil), good...)
				f(p)
				if _, err := e.Handle(a, frame(t, 1, 2, IP, p), now); err == nil {
					t.Fatalf("bad IP %d accepted", i)
				}
			}
			bad := frame(t, 1, 999, Poll, nil)
			bad[len(bad)-1] ^= 1
			if _, err := e.Handle(a, bad, now); err == nil {
				t.Fatal("bad auth")
			}
			if _, err := e.Handle(a, frame(t, 1, 2, IP, good), now); err != nil {
				t.Fatalf("validation poisoned replay: %v", err)
			}
			opts := make([]byte, 32)
			copy(opts, good[:20])
			opts[0] = 0x46
			binary.BigEndian.PutUint16(opts[2:4], 32)
			copy(opts[24:], good[20:])
			if err := ValidateIPv4(opts, ClientIP, true); err != nil {
				t.Fatalf("options rejected %v", err)
			}
		})
	}
}
func TestExpiryQueueBoundsAndSequenceExhaustion(t *testing.T) {
	for _, discipline := range []QueueDiscipline{QueueFIFO, QueueFQCoDel} {
		t.Run(string(discipline), func(t *testing.T) {
			now := time.Unix(1000, 0)
			a := netip.MustParseAddr("192.0.2.1")
			e, _ := NewEngine(testKey, Options{QueueDiscipline: discipline, QueueLimit: 2})
			e.Handle(a, frame(t, 1, 1, Hello, nil), now)
			down := ipPacket("8.8.8.8", "10.77.0.2")
			for i := 0; i < 3; i++ {
				if err := e.Enqueue(down, now); err != nil {
					t.Fatal(err)
				}
			}
			if s := e.Stats(); s.QueueDropped != 1 || s.Queued != 2 {
				t.Fatalf("stats %+v", s)
			}
			if _, err := e.Handle(a, frame(t, 1, 2, Poll, nil), now.Add(120*time.Second)); err == nil {
				t.Fatal("idle session live")
			}
			if _, err := e.Handle(a, frame(t, 1, 3, Hello, nil), now.Add(120*time.Second)); err == nil {
				t.Fatal("expired session reused")
			}
			if err := e.Enqueue(down, now); err == nil {
				t.Fatal("enqueue no session")
			}
			e.Handle(a, frame(t, 2, 1, Hello, nil), now)
			e.active.nextSend = ^uint64(0)
			r, err := e.Handle(a, frame(t, 2, 2, Poll, nil), now)
			if err != nil {
				t.Fatal(err)
			}
			m, _ := Open(testKey, ServerToClient, r.Reply)
			if m.Sequence != ^uint64(0) {
				t.Fatal("last seq")
			}
			if _, err = e.Handle(a, frame(t, 2, 3, Poll, nil), now); err == nil {
				t.Fatal("wrap allowed")
			}
			if _, err = e.Handle(a, frame(t, 2, 4, Hello, nil), now); err == nil {
				t.Fatal("exhausted session reused")
			}
		})
	}
}
func TestICMPVariableIHLAndChecksum(t *testing.T) {
	payload := frame(t, 1, 1, Hello, nil)
	icmp, err := BuildEcho(8, 0x1234, 0x5678, payload)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 24+len(icmp))
	p[0] = 0x46
	p[9] = 1
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{192, 0, 2, 1})
	copy(p[24:], icmp)
	q, err := ParseRawEcho(p)
	if err != nil || q.Identifier != 0x1234 || q.Sequence != 0x5678 || !bytes.Equal(q.Payload, payload) {
		t.Fatalf("parse %+v %v", q, err)
	}
	reply, _ := BuildEcho(0, q.Identifier, q.Sequence, q.Payload)
	if Checksum(reply) != 0 {
		t.Fatal("reply checksum")
	}
	for _, i := range []int{24, 25, len(p) - 1} {
		b := append([]byte(nil), p...)
		b[i] ^= 1
		if _, err := ParseRawEcho(b); err == nil {
			t.Fatalf("bad checksum byte %d", i)
		}
	}
	p[6] = 0x20
	if _, err := ParseRawEcho(p); err == nil {
		t.Fatal("outer fragment")
	}
}
