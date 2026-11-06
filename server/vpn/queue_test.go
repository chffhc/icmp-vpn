package vpn

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestDefaultFIFOCompatibility(t *testing.T) {
	e, err := NewEngine(testKey, Options{})
	if err != nil {
		t.Fatal(err)
	}
	q, ok := e.queue.(*fifoQueue)
	if !ok || len(q.pkts) != 256 {
		t.Fatalf("default is not FIFO256: %T", e.queue)
	}
	now := time.Unix(1000, 0)
	for n := 0; n < 257; n++ {
		q.enqueue([]byte{byte(n >> 8), byte(n)}, now)
	}
	if queued, overflow, aqm := q.metrics(); queued != 256 || overflow != 1 || aqm != 0 {
		t.Fatalf("metrics %d/%d/%d", queued, overflow, aqm)
	}
	// FIFO is intentionally age-independent, including RTTs up to two seconds.
	for n := 1; n < 257; n++ {
		want := []byte{byte(n >> 8), byte(n)}
		if got := q.dequeue(now.Add(2 * time.Second)); !bytes.Equal(got, want) {
			t.Fatalf("order %d: %v", n, got)
		}
	}
	if q.dequeue(now) != nil {
		t.Fatal("empty queue")
	}
	p := []byte{42}
	q.enqueue(p, now)
	p[0] = 0
	if got := q.dequeue(now); !bytes.Equal(got, []byte{42}) {
		t.Fatal("queue did not copy payload")
	}
	q.enqueue(p, now)
	q.reset()
	if queued, overflow, aqm := q.metrics(); queued != 0 || overflow != 1 || aqm != 0 {
		t.Fatal("reset lost counters/retained packets")
	}
	for _, p := range q.pkts {
		if p != nil {
			t.Fatal("reset retained buffer")
		}
	}
}

func TestQueueOptions(t *testing.T) {
	for _, discipline := range []QueueDiscipline{"", QueueFIFO, QueueFQCoDel} {
		for _, limit := range []int{0, 1, 256, 4096} {
			if _, err := NewEngine(testKey, Options{QueueDiscipline: discipline, QueueLimit: limit}); err != nil {
				t.Fatalf("%q/%d: %v", discipline, limit, err)
			}
		}
	}
	for _, opts := range []Options{{QueueDiscipline: "unknown"}, {QueueDiscipline: "FIFO"}, {QueueLimit: -1}, {QueueLimit: 4097}} {
		if _, err := NewEngine(testKey, opts); err == nil {
			t.Fatalf("accepted %+v", opts)
		}
	}
	e, err := NewEngine(testKey, Options{QueueDiscipline: QueueFQCoDel})
	if err != nil {
		t.Fatal(err)
	}
	if q, ok := e.queue.(*fqCoDel); !ok || q.limit != 256 {
		t.Fatalf("opt-in %T", e.queue)
	}
}

func TestEngineExpandedReplayBothQueues(t *testing.T) {
	for _, discipline := range []QueueDiscipline{QueueFIFO, QueueFQCoDel} {
		t.Run(string(discipline), func(t *testing.T) {
			now := time.Unix(1000, 0)
			a := netip.MustParseAddr("192.0.2.1")
			other := netip.MustParseAddr("192.0.2.2")
			e, err := NewEngine(testKey, Options{QueueDiscipline: discipline, QueueLimit: 2})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = e.Handle(a, frame(t, 1, 1, Hello, nil), now); err != nil {
				t.Fatal(err)
			}
			// This is beyond the legacy 256-slot window, but inside the expanded window.
			if _, err = e.Handle(a, frame(t, 1, 20000, Poll, nil), now); err != nil {
				t.Fatal(err)
			}
			down := ipPacket("8.8.8.8", "10.77.0.2")
			for i := 0; i < 3; i++ {
				if err = e.Enqueue(down, now); err != nil {
					t.Fatal(err)
				}
			}
			before := e.Stats()
			bad := frame(t, 1, 100000, Poll, nil)
			bad[len(bad)-1] ^= 1
			for _, request := range []struct {
				source netip.Addr
				frame  []byte
			}{
				{a, bad}, {other, frame(t, 1, 100000, Poll, nil)},
				{a, frame(t, 1, 100000, IP, ipPacket("10.77.0.9", "8.8.8.8"))},
				{a, frame(t, 1, 20000, Poll, nil)},
			} {
				replay := e.active.replay
				nextSend := e.active.nextSend
				if _, err = e.Handle(request.source, request.frame, now); err == nil {
					t.Fatal("invalid request accepted")
				}
				if e.active.replay != replay || e.active.nextSend != nextSend || e.Stats().Queued != before.Queued {
					t.Fatal("invalid request changed replay/nonce/queue")
				}
			}
			r, err := e.Handle(a, frame(t, 1, 2, Poll, nil), now)
			if err != nil {
				t.Fatalf("long reorder rejected: %v", err)
			}
			m, err := Open(testKey, ServerToClient, r.Reply)
			if err != nil || m.Kind != IP || !bytes.Equal(m.Payload, down) || m.Sequence != 3 {
				t.Fatalf("reply %+v %v", m, err)
			}
			if _, err = e.Handle(a, frame(t, 1, 32771, Hello, nil), now); err != nil {
				t.Fatal(err)
			}
			if _, err = e.Handle(a, frame(t, 1, 3, Poll, nil), now); !errors.Is(err, ErrReplay) {
				t.Fatalf("stale boundary: %v", err)
			}
			if _, err = e.Handle(a, frame(t, 1, 4, Poll, nil), now); err != nil {
				t.Fatalf("inclusive boundary: %v", err)
			}
			// The last unsigned sequence is valid; wrapping to a low value is not.
			if _, err = e.Handle(a, frame(t, 1, ^uint64(0), Poll, nil), now); err != nil {
				t.Fatal(err)
			}
			if _, err = e.Handle(a, frame(t, 1, 5, Poll, nil), now); !errors.Is(err, ErrReplay) {
				t.Fatalf("wrap: %v", err)
			}
			if _, err = e.Handle(a, frame(t, 1, ^uint64(0)-1, Close, nil), now); err != nil {
				t.Fatal(err)
			}
			if e.Stats().Active || e.Stats().Queued != 0 || e.Stats().QueueDropped != 1 {
				t.Fatal("close/reset metrics")
			}
			if _, err = e.Handle(a, frame(t, 1, ^uint64(0)-2, Hello, nil), now); !errors.Is(err, ErrSessionUsed) {
				t.Fatalf("tombstone lost: %v", err)
			}
		})
	}
}
