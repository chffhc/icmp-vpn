package vpn

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func flowPacket(src string, proto byte, sport uint16, size int) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	p[8] = 64
	p[9] = proto
	a := netip.MustParseAddr(src).As4()
	copy(p[12:16], a[:])
	copy(p[16:20], []byte{10, 77, 0, 2})
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], 40000)
	binary.BigEndian.PutUint16(p[10:12], Checksum(p[:20]))
	return p
}

func distinctFlows(t *testing.T, q *fqCoDel) ([]byte, []byte) {
	t.Helper()
	bulk := flowPacket("203.0.113.9", 6, 443, 1100)
	for port := uint16(1); port < 2000; port++ {
		sparse := flowPacket("198.51.100.7", 17, port, 60)
		if q.flowBucket(sparse) != q.flowBucket(bulk) {
			return bulk, sparse
		}
	}
	t.Fatal("no distinct bucket found")
	return nil, nil
}

// The latency claim: with a bulk download saturating the request rate, a
// sparse flow (ping/DNS/ACK/game) is served within a couple of requests
// instead of waiting behind the whole bulk backlog.
func TestSparseFlowBypassesBulkBacklog(t *testing.T) {
	now := time.Unix(1000, 0)
	q := newFQCoDel(1024)
	bulk, sparse := distinctFlows(t, q)
	for i := 0; i < 500; i++ {
		q.enqueue(bulk, now)
	}
	q.enqueue(sparse, now)
	for served := 1; served <= 3; served++ {
		if p := q.dequeue(now); len(p) == len(sparse) {
			return
		}
	}
	t.Fatal("sparse packet waited behind the bulk backlog")
}

// Simulates the ICMP transport: the client grants 3000 requests/s, the bulk
// sender offers 4000 pps (unresponsive) and a ping is sent every 50 ms.
// Old FIFO(256) delay grows to queue/rate (~85 ms) and pings are dropped at
// overflow; FQ-CoDel keeps ping delay at about one request interval.
func TestSimulatedPingDelayUnderLoad(t *testing.T) {
	start := time.Unix(1000, 0)
	q := newFQCoDel(1024)
	bulk, sparse := distinctFlows(t, q)
	var fifo [][2]int64 // packet kind (0 bulk, 1 ping), enqueue tick
	var fqDelay, fifoDelay []time.Duration
	pingsFIFO, pingsFQ := 0, 0
	const tick = 250 * time.Microsecond // 4000 Hz
	for i := 0; i < 4000*5; i++ {
		now := start.Add(time.Duration(i) * tick)
		q.enqueue(bulk, now)
		fifo = append(fifo, [2]int64{0, int64(i)})
		if i%200 == 0 { // ping every 50 ms
			q.enqueue(sparse, now)
			fifo = append(fifo, [2]int64{1, int64(i)})
			pingsFIFO++
			pingsFQ++
		}
		for len(fifo) > 256 {
			fifo = fifo[1:]
		}
		if i%4 != 0 { // 3 of every 4 ticks the client has a request in hand
			if p := q.dequeue(now); p != nil && len(p) == len(sparse) {
				fqDelay = append(fqDelay, 0) // measured below via sojourn tracking
			}
			if len(fifo) > 0 {
				if fifo[0][0] == 1 {
					fifoDelay = append(fifoDelay, time.Duration(int64(i)-fifo[0][1])*tick)
				}
				fifo = fifo[1:]
			}
		}
	}
	if len(fqDelay) < pingsFQ-1 {
		t.Fatalf("FQ-CoDel lost pings: %d/%d", len(fqDelay), pingsFQ)
	}
	var worstFIFO time.Duration
	for _, d := range fifoDelay {
		if d > worstFIFO {
			worstFIFO = d
		}
	}
	t.Logf("pings=%d fifo_delivered=%d fifo_worst=%v fq_delivered=%d codel_drops=%d overflow=%d queued=%d",
		pingsFIFO, len(fifoDelay), worstFIFO, len(fqDelay), q.codelDropped, q.overflow, q.total)
	if worstFIFO < 60*time.Millisecond {
		t.Fatalf("model check: FIFO should show bufferbloat, worst=%v", worstFIFO)
	}
}

// Sojourn time of the sparse flow, measured on the real queue structure.
func TestSparseSojournUnderSaturation(t *testing.T) {
	start := time.Unix(1000, 0)
	q := newFQCoDel(1024)
	bulk, sparse := distinctFlows(t, q)
	var sentAt []time.Time
	var worst time.Duration
	got := 0
	const tick = 250 * time.Microsecond
	for i := 0; i < 4000*5; i++ {
		now := start.Add(time.Duration(i) * tick)
		q.enqueue(bulk, now)
		if i%200 == 0 {
			q.enqueue(sparse, now)
			sentAt = append(sentAt, now)
		}
		if i%4 != 0 {
			if p := q.dequeue(now); p != nil && len(p) == len(sparse) {
				if d := now.Sub(sentAt[got]); d > worst {
					worst = d
				}
				got++
			}
		}
	}
	if got < len(sentAt)-1 || worst > 2*time.Millisecond {
		t.Fatalf("sparse delivered %d/%d worst %v", got, len(sentAt), worst)
	}
	// Even an UNRESPONSIVE bulk sender must not build a standing delay above
	// MaxSojourn (old FIFO: 256/3000 s ~ 85 ms; a 1024 FIFO would be ~340 ms).
	now := start.Add(4000 * 5 * tick)
	head := q.flows[q.flowBucket(bulk)].pkts[0].at
	q.dequeue(now)
	if age := now.Sub(q.flows[q.flowBucket(bulk)].pkts[0].at); age > MaxSojourn || q.codelDropped == 0 {
		t.Fatalf("bulk head age %v (before %v) codel drops %d", age, now.Sub(head), q.codelDropped)
	}
	t.Logf("sparse worst sojourn %v, bulk standing queue %d, codel drops %d, overflow %d", worst, q.total, q.codelDropped, q.overflow)
}

// A responsive bulk flow drained as fast as it arrives must never be dropped.
func TestNoDropsWithoutStandingQueue(t *testing.T) {
	start := time.Unix(1000, 0)
	q := newFQCoDel(1024)
	bulk, _ := distinctFlows(t, q)
	for i := 0; i < 10000; i++ {
		now := start.Add(time.Duration(i) * time.Millisecond)
		q.enqueue(bulk, now)
		q.enqueue(bulk, now)
		if q.dequeue(now) == nil || q.dequeue(now.Add(500*time.Microsecond)) == nil {
			t.Fatal("lost packet")
		}
	}
	if q.codelDropped != 0 || q.overflow != 0 || q.total != 0 {
		t.Fatalf("drops %d/%d queued %d", q.codelDropped, q.overflow, q.total)
	}
}

func TestOverflowDropsFattestFlowNotNewcomer(t *testing.T) {
	now := time.Unix(1000, 0)
	q := newFQCoDel(8)
	bulk, sparse := distinctFlows(t, q)
	for i := 0; i < 8; i++ {
		q.enqueue(bulk, now)
	}
	q.enqueue(sparse, now)
	if q.total != 8 || q.overflow != 1 || len(q.flows[q.flowBucket(sparse)].pkts) != 1 {
		t.Fatalf("total %d overflow %d", q.total, q.overflow)
	}
	q.reset()
	if q.total != 0 || q.dequeue(now) != nil || q.overflow != 1 {
		t.Fatal("reset")
	}
}
