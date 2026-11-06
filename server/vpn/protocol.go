// Package vpn implements the fixed IVP1 wire protocol and single-client engine.
// It has no network side effects. Runtime transport is in cmd/icmpvpn.
package vpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	HeaderSize   = 24
	MaxPlaintext = 1200
	MaxICMPSize  = 8 + HeaderSize + MaxPlaintext + 16
	HelloConfig  = "10.77.0.2|1200"
)

type Kind uint8

const (
	Poll Kind = iota
	IP
	Hello
	Close
)

type Direction uint8

const (
	ClientToServer Direction = iota
	ServerToClient
)

type Message struct {
	SessionID uint64
	Sequence  uint64
	Kind      Kind
	Payload   []byte
}

func validate(m Message, direction Direction) error {
	if direction > ServerToClient || m.SessionID == 0 || m.Sequence == 0 || m.Kind > Close || len(m.Payload) > MaxPlaintext {
		return errors.New("invalid message header")
	}
	switch m.Kind {
	case Poll, Close:
		if len(m.Payload) != 0 {
			return errors.New("nonempty control message")
		}
	case Hello:
		if direction == ClientToServer && len(m.Payload) != 0 {
			return errors.New("nonempty client HELLO")
		}
		if direction == ServerToClient && string(m.Payload) != HelloConfig {
			return errors.New("invalid server HELLO configuration")
		}
	case IP:
		if len(m.Payload) == 0 {
			return errors.New("empty IP packet")
		}
	}
	return nil
}
func AEAD(psk []byte, direction Direction, session uint64) (cipher.AEAD, error) {
	if len(psk) != 32 || direction > ServerToClient || session == 0 {
		return nil, errors.New("invalid key/direction/session")
	}
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("icmp-vpn-v1/"))
	mac.Write([]byte{byte(direction)})
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], session)
	mac.Write(id[:])
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func nonce(seq uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// Seal produces a header followed by GCM ciphertext/tag. Callers must never
// reuse a sequence for the same key/session/direction, including across restarts.
func Seal(psk []byte, direction Direction, m Message) ([]byte, error) {
	if err := validate(m, direction); err != nil {
		return nil, err
	}
	a, err := AEAD(psk, direction, m.SessionID)
	if err != nil {
		return nil, err
	}
	h := make([]byte, HeaderSize)
	copy(h, "IVP1")
	h[4] = 1
	h[5] = byte(m.Kind)
	binary.BigEndian.PutUint64(h[6:14], m.SessionID)
	binary.BigEndian.PutUint64(h[14:22], m.Sequence)
	binary.BigEndian.PutUint16(h[22:24], uint16(len(m.Payload)))
	return a.Seal(h, nonce(m.Sequence), m.Payload, h), nil
}

// Open authenticates before returning plaintext and enforces direction-specific
// message semantics. It does not mutate replay state.
func Open(psk []byte, direction Direction, b []byte) (Message, error) {
	var m Message
	if len(b) < HeaderSize+16 || len(b) > HeaderSize+MaxPlaintext+16 {
		return m, errors.New("invalid frame length")
	}
	if string(b[:4]) != "IVP1" || b[4] != 1 || Kind(b[5]) > Close {
		return m, errors.New("unknown protocol/version/kind")
	}
	m.SessionID = binary.BigEndian.Uint64(b[6:14])
	m.Sequence = binary.BigEndian.Uint64(b[14:22])
	m.Kind = Kind(b[5])
	n := int(binary.BigEndian.Uint16(b[22:24]))
	if m.SessionID == 0 || m.Sequence == 0 || n > MaxPlaintext || len(b) != HeaderSize+n+16 {
		return Message{}, errors.New("invalid frame fields/length")
	}
	a, err := AEAD(psk, direction, m.SessionID)
	if err != nil {
		return Message{}, err
	}
	m.Payload, err = a.Open(nil, nonce(m.Sequence), b[HeaderSize:], b[:HeaderSize])
	if err != nil {
		return Message{}, fmt.Errorf("authentication: %w", err)
	}
	if err = validate(m, direction); err != nil {
		return Message{}, err
	}
	return m, nil
}

// ReplayWindowSize counts the highest sequence and 32767 preceding sequences.
// It is local replay policy, not a wire-format field or negotiation parameter.
const ReplayWindowSize = 32768

// ReplayWindow accepts unseen nonzero sequences at distances 0..32767 from
// the highest seen. Sequence comparisons are unsigned; counters never wrap.
// Call Accept only after authentication, source binding and semantic checks.
// Bits are indexed by sequence modulo the window size: advancing clears only
// recycled slots, rather than shifting the bitmap on every packet.
type ReplayWindow struct {
	highest uint64
	bits    [ReplayWindowSize / 64]uint64
}

func (w *ReplayWindow) Accept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	if seq > w.highest {
		d := seq - w.highest
		if d >= ReplayWindowSize {
			clear(w.bits[:])
		} else {
			// highest < seq, so highest+1 cannot overflow uint64 here.
			w.clearSlots(int((w.highest+1)%ReplayWindowSize), int(d))
		}
		w.highest = seq
	} else if w.highest-seq >= ReplayWindowSize {
		return false
	}
	idx := seq % ReplayWindowSize
	mask := uint64(1) << (idx % 64)
	if w.bits[idx/64]&mask != 0 {
		return false
	}
	w.bits[idx/64] |= mask
	return true
}

// clearSlots clears a circular range word-by-word. An in-order increment
// touches one word; a larger jump touches at most the 512 bitmap words plus
// its partial boundary word. No work is proportional to every bit on receive.
func (w *ReplayWindow) clearSlots(start, count int) {
	for count > 0 {
		offset := start % 64
		n := min(count, 64-offset)
		mask := (^uint64(0) >> (64 - n)) << offset
		w.bits[start/64] &^= mask
		start = (start + n) % ReplayWindowSize
		count -= n
	}
}
