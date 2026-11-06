package vpn

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const IdleTimeout = 120 * time.Second

var (
	ErrSessionUsed     = errors.New("session ID already used (rotate connection session)")
	ErrSessionCapacity = errors.New("session tombstone capacity exhausted (rotate key and ledger)")
	ErrSessionStore    = errors.New("durable session reservation failed")
	ErrNoSession       = errors.New("no live authenticated session")
	ErrReplay          = errors.New("duplicate or stale sequence")
)

// SessionStore must atomically and durably reject a previously reserved ID.
// Runtime must use FileStore; MemoryStore is for tests/in-process simulations.
type SessionStore interface{ Reserve(uint64) error }
type MemoryStore struct {
	mu    sync.Mutex
	used  map[uint64]struct{}
	limit int
}

func NewMemoryStore(limit int) *MemoryStore {
	return &MemoryStore{used: make(map[uint64]struct{}), limit: limit}
}
func (s *MemoryStore) Reserve(id uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == 0 {
		return errors.New("zero session")
	}
	if _, ok := s.used[id]; ok {
		return ErrSessionUsed
	}
	if len(s.used) >= s.limit {
		return ErrSessionCapacity
	}
	s.used[id] = struct{}{}
	return nil
}

type Options struct {
	Store           SessionStore
	QueueDiscipline QueueDiscipline // Default FIFO; FQ-CoDel is opt-in experimental.
	QueueLimit      int             // Default 256; maximum 4096.
	MaxSessions     int
}
type Result struct {
	Reply    []byte
	Upstream []byte
}
type Statistics struct {
	Accepted     uint64
	Rejected     uint64
	Upstream     uint64
	Downstream   uint64
	QueueDropped uint64 // overflow drops (hard limit)
	CoDelDropped uint64 // Experimental AQM/backstop drops; always zero in FIFO.
	Expired      uint64
	Queued       int
	Active       bool
}
type session struct {
	id       uint64
	source   netip.Addr
	replay   ReplayWindow
	nextSend uint64
	lastSeen time.Time
}
type Engine struct {
	mu     sync.Mutex
	key    []byte
	store  SessionStore
	queue  downstreamQueue
	active *session
	stats  Statistics
}

func NewEngine(psk []byte, opts Options) (*Engine, error) {
	if len(psk) != 32 {
		return nil, errors.New("PSK must be exactly 32 bytes")
	}
	if opts.QueueDiscipline == "" {
		opts.QueueDiscipline = QueueFIFO
	}
	if err := ValidateQueueOptions(opts.QueueDiscipline, opts.QueueLimit); err != nil {
		return nil, err
	}
	if opts.QueueLimit == 0 {
		opts.QueueLimit = DefaultQueueLimit
	}
	if opts.MaxSessions == 0 {
		opts.MaxSessions = 4096
	}
	if opts.MaxSessions < 1 || opts.MaxSessions > 65536 {
		return nil, errors.New("invalid bounded session limit")
	}
	if opts.Store == nil {
		opts.Store = NewMemoryStore(opts.MaxSessions)
	}
	var queue downstreamQueue
	if opts.QueueDiscipline == QueueFQCoDel {
		queue = newFQCoDel(opts.QueueLimit)
	} else {
		queue = newFIFO(opts.QueueLimit)
	}
	return &Engine{key: append([]byte(nil), psk...), store: opts.Store, queue: queue}, nil
}
func (e *Engine) expire(now time.Time) {
	if e.active != nil && now.Sub(e.active.lastSeen) >= IdleTimeout {
		e.active = nil
		e.queue.reset()
		e.stats.Expired++
	}
}

// Tick removes idle sessions/queued data even when there are no new requests.
func (e *Engine) Tick(now time.Time) { e.mu.Lock(); defer e.mu.Unlock(); e.expire(now) }

// Handle authenticates, validates IPv4 and session/source binding, then commits
// replay state. It returns exactly one frame per validated request. The caller
// writes Upstream to TUN before replying; failures must not reset server state.
func (e *Engine) Handle(source netip.Addr, frame []byte, now time.Time) (result Result, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		if err != nil {
			e.stats.Rejected++
		}
	}()
	e.expire(now)
	if !source.Is4() {
		return result, errors.New("outer source must be IPv4")
	}
	m, err := Open(e.key, ClientToServer, frame)
	if err != nil {
		return result, err
	}
	if e.active != nil && (e.active.id != m.SessionID || e.active.source != source) {
		return result, errors.New("session/source does not match active session")
	}
	if m.Kind == IP {
		if err = ValidateIPv4(m.Payload, ClientIP, true); err != nil {
			return result, err
		}
	}
	if e.active == nil {
		if m.Kind != Hello {
			return result, ErrNoSession
		}
		if err = e.store.Reserve(m.SessionID); err != nil {
			if errors.Is(err, ErrSessionUsed) || errors.Is(err, ErrSessionCapacity) {
				return result, err
			}
			return result, fmt.Errorf("%w: %w", ErrSessionStore, err)
		}
		e.active = &session{id: m.SessionID, source: source, nextSend: 1, lastSeen: now}
	}
	s := e.active
	if s.nextSend == 0 {
		e.active = nil
		e.queue.reset()
		return result, errors.New("server sequence exhausted; fresh session required")
	}
	if !s.replay.Accept(m.Sequence) {
		return result, ErrReplay
	}
	reply := Message{SessionID: s.id, Sequence: s.nextSend, Kind: Poll}
	switch m.Kind {
	case Hello:
		reply.Kind = Hello
		reply.Payload = []byte(HelloConfig)
	case Close:
		reply.Kind = Close
	default:
		if p := e.queue.dequeue(now); p != nil {
			reply.Kind = IP
			reply.Payload = p
			e.stats.Downstream++
		}
	}
	result.Reply, err = Seal(e.key, ServerToClient, reply)
	if err != nil {
		return Result{}, err
	}
	s.nextSend++
	s.lastSeen = now
	e.stats.Accepted++
	if m.Kind == IP {
		result.Upstream = m.Payload
		e.stats.Upstream++
	}
	if m.Kind == Close {
		e.active = nil
		e.queue.reset()
	}
	return result, nil
}

// Enqueue validates a TUN packet and copies it into the live client's bounded
// downstream queue. FIFO (default) drops oldest on overflow; experimental
// FQ-CoDel drops from the head of the fattest flow and applies its AQM policy.
func (e *Engine) Enqueue(packet []byte, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expire(now)
	if err := ValidateIPv4(packet, ClientIP, false); err != nil {
		return err
	}
	if e.active == nil {
		return ErrNoSession
	}
	e.queue.enqueue(packet, now)
	return nil
}
func (e *Engine) Stats() Statistics {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.stats
	s.Queued, s.QueueDropped, s.CoDelDropped = e.queue.metrics()
	s.Active = e.active != nil
	return s
}
