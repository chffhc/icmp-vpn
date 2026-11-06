package vpn

import (
	"hash/maphash"
	"math"
	"time"
)

// Experimental downstream queue inspired by FQ-CoDel (RFC 8290 / RFC 8289).
// This simplified implementation is not RFC-conformant: it adds a 300ms
// sojourn backstop (leaving the last packet) and uses 30ms/200ms target/interval.
// FIFO256 remains the default; this discipline requires explicit opt-in.
//
// The ICMP transport can only return one queued packet per client request, so
// whenever downstream demand exceeds the request rate packets wait here. A
// single FIFO lets one bulk flow (a download) delay every other flow (pings,
// DNS, TCP ACKs of an upload, a game) by the whole queue depth. Here each
// inner flow gets its own queue served by deficit round robin, new/sparse flows
// first, and CoDel keeps each flow's standing queue near Target by dropping at
// the head, which makes responsive (TCP/QUIC) senders slow down early.
const (
	FQBuckets     = 64
	FQQuantum     = MaxPlaintext
	CoDelTarget   = 30 * time.Millisecond
	CoDelInterval = 200 * time.Millisecond
	// MaxSojourn is a hard backstop for unresponsive senders that CoDel's
	// gradual drop rate cannot tame quickly: older packets are discarded.
	MaxSojourn = 300 * time.Millisecond
)

type queuedPacket struct {
	data []byte
	at   time.Time
}

type coDel struct {
	firstAbove time.Time
	dropNext   time.Time
	count      int
	lastCount  int
	dropping   bool
}

const (
	listNone = iota
	listNew
	listOld
)

type flowQueue struct {
	pkts    []queuedPacket
	bytes   int
	deficit int
	list    int
	codel   coDel
}

type fqCoDel struct {
	flows        [FQBuckets]flowQueue
	newFlows     []int
	oldFlows     []int
	total        int
	limit        int
	seed         maphash.Seed
	overflow     uint64
	codelDropped uint64
}

func newFQCoDel(limit int) *fqCoDel {
	return &fqCoDel{limit: limit, seed: maphash.MakeSeed()}
}

// flowBucket hashes the remote end of a downstream IPv4 packet. Callers have
// already validated the header (no fragments), so L4 ports are present for a
// full TCP/UDP header.
func (q *fqCoDel) flowBucket(p []byte) int {
	var key [9]byte
	key[0] = p[9]
	copy(key[1:5], p[12:16]) // remote source address
	ihl := int(p[0]&15) * 4
	if (p[9] == 6 || p[9] == 17) && len(p) >= ihl+4 {
		copy(key[5:9], p[ihl:ihl+4]) // source + destination ports
	}
	return int(maphash.Bytes(q.seed, key[:]) % FQBuckets)
}

func (q *fqCoDel) reset() {
	*q = fqCoDel{limit: q.limit, seed: q.seed, overflow: q.overflow, codelDropped: q.codelDropped}
}

func (q *fqCoDel) enqueue(p []byte, now time.Time) {
	idx := q.flowBucket(p)
	f := &q.flows[idx]
	f.pkts = append(f.pkts, queuedPacket{data: append([]byte(nil), p...), at: now})
	f.bytes += len(p)
	q.total++
	if f.list == listNone {
		f.list = listNew
		f.deficit = FQQuantum
		q.newFlows = append(q.newFlows, idx)
	}
	if q.total > q.limit {
		// Drop from the head of the flow with the largest backlog, never
		// from a sparse flow that happens to be enqueuing right now.
		fat := 0
		for i := range q.flows {
			if q.flows[i].bytes > q.flows[fat].bytes {
				fat = i
			}
		}
		q.pop(&q.flows[fat])
		q.overflow++
	}
}

func (q *fqCoDel) pop(f *flowQueue) *queuedPacket {
	if len(f.pkts) == 0 {
		return nil
	}
	p := f.pkts[0]
	f.pkts[0] = queuedPacket{}
	f.pkts = f.pkts[1:]
	if len(f.pkts) == 0 {
		f.pkts = nil // release the backing array of a drained flow
	}
	f.bytes -= len(p.data)
	q.total--
	return &p
}

func (q *fqCoDel) shouldDrop(f *flowQueue, p *queuedPacket, now time.Time) bool {
	c := &f.codel
	if p == nil {
		c.firstAbove = time.Time{}
		return false
	}
	if now.Sub(p.at) < CoDelTarget || f.bytes <= MaxPlaintext {
		c.firstAbove = time.Time{}
		return false
	}
	if c.firstAbove.IsZero() {
		c.firstAbove = now.Add(CoDelInterval)
		return false
	}
	return !now.Before(c.firstAbove)
}

func controlLaw(t time.Time, count int) time.Time {
	return t.Add(time.Duration(float64(CoDelInterval) / math.Sqrt(float64(count))))
}

// codelDequeue applies simplified CoDel plus the non-RFC sojourn backstop.
func (q *fqCoDel) codelDequeue(f *flowQueue, now time.Time) *queuedPacket {
	c := &f.codel
	for len(f.pkts) > 1 && now.Sub(f.pkts[0].at) > MaxSojourn {
		q.pop(f)
		q.codelDropped++
	}
	p := q.pop(f)
	okToDrop := q.shouldDrop(f, p, now)
	if c.dropping {
		if !okToDrop {
			c.dropping = false
		}
		for c.dropping && !now.Before(c.dropNext) {
			q.codelDropped++
			c.count++
			p = q.pop(f)
			if !q.shouldDrop(f, p, now) {
				c.dropping = false
			} else {
				c.dropNext = controlLaw(c.dropNext, c.count)
			}
		}
	} else if okToDrop {
		q.codelDropped++
		p = q.pop(f)
		q.shouldDrop(f, p, now)
		c.dropping = true
		delta := c.count - c.lastCount
		c.count = 1
		if delta > 1 && now.Sub(c.dropNext) < 16*CoDelInterval {
			c.count = delta
		}
		c.dropNext = controlLaw(now, c.count)
		c.lastCount = c.count
	}
	return p
}

// dequeue returns the next packet to send, or nil when every flow is empty.
func (q *fqCoDel) dequeue(now time.Time) []byte {
	for {
		var list *[]int
		switch {
		case len(q.newFlows) > 0:
			list = &q.newFlows
		case len(q.oldFlows) > 0:
			list = &q.oldFlows
		default:
			return nil
		}
		idx := (*list)[0]
		f := &q.flows[idx]
		if f.deficit <= 0 {
			f.deficit += FQQuantum
			*list = (*list)[1:]
			f.list = listOld
			q.oldFlows = append(q.oldFlows, idx)
			continue
		}
		p := q.codelDequeue(f, now)
		if p == nil {
			*list = (*list)[1:]
			if list == &q.newFlows && len(q.oldFlows) > 0 {
				// RFC 8290: an emptied new flow goes to the old list so a
				// flow cannot stay "new" forever by sending bursts.
				f.list = listOld
				q.oldFlows = append(q.oldFlows, idx)
			} else {
				f.list = listNone
			}
			continue
		}
		f.deficit -= len(p.data)
		return p.data
	}
}
