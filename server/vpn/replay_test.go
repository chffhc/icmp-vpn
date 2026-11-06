package vpn

import (
	"math/rand"
	"testing"
)

func TestReplayInclusiveBoundary(t *testing.T) {
	const high = uint64(100000)
	var w ReplayWindow
	if w.Accept(0) || !w.Accept(high) || w.Accept(high) {
		t.Fatal("zero/high/duplicate")
	}
	if !w.Accept(high-32767) || w.Accept(high-32767) || w.Accept(high-32768) {
		t.Fatal("window must include distances 0..32767, not 32768")
	}
	if !w.Accept(high+1) || w.Accept(high-32767) || !w.Accept(high-32766) {
		t.Fatal("moving inclusive boundary")
	}
}

func TestReplayLongReorderAndCircularReuse(t *testing.T) {
	var w ReplayWindow
	const high = uint64(32768)
	if !w.Accept(high) {
		t.Fatal("highest rejected")
	}
	for n := high - 1; n != 0; n-- {
		if !w.Accept(n) || w.Accept(n) {
			t.Fatalf("reorder/duplicate %d", n)
		}
	}
	// Advance through several complete ring rotations, including word boundaries.
	for n := high + 1; n <= high*5; n++ {
		if !w.Accept(n) || w.Accept(n) {
			t.Fatalf("circular slot reuse %d", n)
		}
	}
	if w.Accept(high) || w.Accept(high*5-32768) {
		t.Fatal("stale ring slots accepted")
	}
}

func TestReplayUnsignedHighAndWrapRejection(t *testing.T) {
	var w ReplayWindow
	const max = ^uint64(0)
	for _, n := range []uint64{1, (uint64(1) << 63) - 1, (uint64(1) << 63) + 70, max - 100, max, max - 32767} {
		if !w.Accept(n) || w.Accept(n) {
			t.Fatalf("unsigned sequence %d", n)
		}
	}
	for _, n := range []uint64{0, 1, 2, max - 32768, uint64(1) << 63} {
		if w.Accept(n) {
			t.Fatalf("stale/wrapped sequence %d", n)
		}
	}
	if !w.Accept(max - 1) {
		t.Fatal("valid high-end reorder rejected")
	}
}

func TestReplayMatchesReference(t *testing.T) {
	// Compare the circular bitmap to a simple unbounded reference set.
	rng := rand.New(rand.NewSource(42))
	for _, start := range []uint64{100000, (uint64(1) << 63) - 50000, ^uint64(0) - 500000000} {
		var w ReplayWindow
		highest := uint64(0)
		seen := make(map[uint64]bool)
		cursor := start
		for i := 0; i < 10000; i++ {
			var seq uint64
			switch i % 5 {
			case 0:
				cursor += uint64(rng.Intn(70000) + 1)
				seq = cursor
			case 1:
				cursor++
				seq = cursor
			case 2:
				seq = cursor - uint64(rng.Intn(40000))
			case 3:
				seq = cursor
			default:
				seq = 0
			}
			want := seq != 0 && !seen[seq] && (seq > highest || highest-seq < 32768)
			if got := w.Accept(seq); got != want {
				t.Fatalf("start=%d i=%d seq=%d highest=%d got=%v want=%v", start, i, seq, highest, got, want)
			}
			if want {
				seen[seq] = true
				if seq > highest {
					highest = seq
				}
			}
		}
	}
}

func BenchmarkReplayInOrder(b *testing.B) {
	var w ReplayWindow
	for i := 0; i < b.N; i++ {
		w.Accept(uint64(i) + 1)
	}
}

func BenchmarkReplayLongReorder(b *testing.B) {
	var w ReplayWindow
	var high uint64
	for i := 0; i < b.N; i++ {
		offset := uint64(i % ReplayWindowSize)
		if offset == 0 {
			high += ReplayWindowSize
		}
		w.Accept(high - offset)
	}
}
