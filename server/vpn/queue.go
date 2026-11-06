package vpn

import (
	"fmt"
	"time"
)

// QueueDiscipline selects local downstream scheduling without changing IVP1.
type QueueDiscipline string

const (
	QueueFIFO         QueueDiscipline = "fifo"
	QueueFQCoDel      QueueDiscipline = "fq-codel" // Experimental; requires explicit opt-in.
	DefaultQueueLimit                 = 256
	MaxQueueLimit                     = 4096
)

// ValidateQueueOptions can be called before opening a key, ledger or network.
// Empty discipline and zero limit select FIFO and 256 respectively, as in Options.
func ValidateQueueOptions(discipline QueueDiscipline, limit int) error {
	switch discipline {
	case "", QueueFIFO, QueueFQCoDel:
	default:
		return fmt.Errorf("unknown queue discipline %q (want fifo or fq-codel)", discipline)
	}
	if limit < 0 || limit > MaxQueueLimit {
		return fmt.Errorf("invalid queue limit %d (want 1..%d, or zero for default)", limit, MaxQueueLimit)
	}
	return nil
}

type downstreamQueue interface {
	enqueue([]byte, time.Time)
	dequeue(time.Time) []byte
	reset()
	metrics() (queued int, overflow, aqmDropped uint64)
}

// fifoQueue retains the compatibility policy: bounded FIFO, drop oldest on
// overflow, and no age-based/AQM drops. The ring avoids shifting packet slots.
type fifoQueue struct {
	pkts     [][]byte
	head     int
	count    int
	overflow uint64
}

func newFIFO(limit int) *fifoQueue {
	return &fifoQueue{pkts: make([][]byte, limit)}
}

func (q *fifoQueue) enqueue(p []byte, _ time.Time) {
	packet := append([]byte(nil), p...)
	if q.count == len(q.pkts) {
		q.pkts[q.head] = packet
		q.head = (q.head + 1) % len(q.pkts)
		q.overflow++
		return
	}
	q.pkts[(q.head+q.count)%len(q.pkts)] = packet
	q.count++
}

func (q *fifoQueue) dequeue(_ time.Time) []byte {
	if q.count == 0 {
		return nil
	}
	p := q.pkts[q.head]
	q.pkts[q.head] = nil
	q.head = (q.head + 1) % len(q.pkts)
	q.count--
	return p
}

func (q *fifoQueue) reset() {
	clear(q.pkts)
	q.head, q.count = 0, 0
}

func (q *fifoQueue) metrics() (int, uint64, uint64) {
	return q.count, q.overflow, 0
}

func (q *fqCoDel) metrics() (int, uint64, uint64) {
	return q.total, q.overflow, q.codelDropped
}
