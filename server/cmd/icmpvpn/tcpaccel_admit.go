package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Connect-before-accept admission for the split-TCP proxy.
//
// The client's SYN is held in an NFQUEUE while the proxy dials the real
// destination. Only if that dial succeeds is the SYN released to the REDIRECT
// rule (the proxy then completes the client handshake and reuses the
// pre-dialed upstream connection). If the dial fails, the SYN is released with
// a bypass mark: it skips REDIRECT and is forwarded directly, so the client
// sees exactly what it would see without the proxy (timeout, RST or ICMP
// unreachable) instead of "connected, then reset".

type flowKey struct {
	sport uint16
	dst   netip.AddrPort
}

type admitDecision int

const (
	admitDrop   admitDecision = iota // duplicate SYN while the dial is pending
	admitAccept                      // continue to REDIRECT (proxy)
	admitBypass                      // forward directly, no proxy
	admitDial                        // caller must dial, then call dialDone
)

type admitEntry struct {
	pending bool
	conn    net.Conn
	until   time.Time
}

type admission struct {
	mu       sync.Mutex
	flows    map[flowKey]*admitEntry
	failed   map[netip.AddrPort]time.Time
	failTTL  time.Duration
	pendTTL  time.Duration // > dial timeout
	holdTTL  time.Duration // pre-dialed conn waits this long for the client handshake
	maxFlows int
	now      func() time.Time
}

func newAdmission(dialTO, failTTL time.Duration, maxFlows int) *admission {
	return &admission{
		flows: map[flowKey]*admitEntry{}, failed: map[netip.AddrPort]time.Time{},
		failTTL: failTTL, pendTTL: dialTO + 5*time.Second, holdTTL: 60 * time.Second,
		maxFlows: maxFlows, now: time.Now,
	}
}

func (a *admission) onSYN(k flowKey) admitDecision {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if until, ok := a.failed[k.dst]; ok {
		if now.Before(until) {
			return admitBypass
		}
		delete(a.failed, k.dst)
	}
	if e := a.flows[k]; e != nil && now.Before(e.until) {
		if e.pending {
			return admitDrop
		}
		return admitAccept
	}
	if len(a.flows) >= a.maxFlows {
		a.sweepLocked(now)
		if len(a.flows) >= a.maxFlows {
			return admitBypass
		}
	}
	a.flows[k] = &admitEntry{pending: true, until: now.Add(a.pendTTL)}
	return admitDial
}

// abandon drops a pending flow the caller could not dial (e.g. too many
// concurrent dials); the SYN is bypassed.
func (a *admission) abandon(k flowKey) {
	a.mu.Lock()
	delete(a.flows, k)
	a.mu.Unlock()
}

func (a *admission) dialDone(k flowKey, c net.Conn, err error) admitDecision {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	e := a.flows[k]
	if err != nil {
		delete(a.flows, k)
		if len(a.failed) >= 8192 {
			a.failed = map[netip.AddrPort]time.Time{}
		}
		a.failed[k.dst] = now.Add(a.failTTL)
		return admitBypass
	}
	if e == nil || !e.pending {
		c.Close()
		return admitBypass
	}
	e.pending, e.conn, e.until = false, c, now.Add(a.holdTTL)
	return admitAccept
}

// take hands the pre-dialed upstream connection to the accepted client conn.
func (a *admission) take(k flowKey) net.Conn {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.flows[k]; e != nil && e.conn != nil {
		c := e.conn
		e.conn = nil
		return c
	}
	return nil
}

func (a *admission) sweep() {
	a.mu.Lock()
	a.sweepLocked(a.now())
	a.mu.Unlock()
}

func (a *admission) sweepLocked(now time.Time) {
	for k, e := range a.flows {
		if now.After(e.until) {
			if e.conn != nil {
				e.conn.Close()
			}
			delete(a.flows, k)
		}
	}
	for d, until := range a.failed {
		if now.After(until) {
			delete(a.failed, d)
		}
	}
}

// synKey extracts the flow key from an IPv4 TCP SYN (no ACK); ok=false otherwise.
func synKey(p []byte) (flowKey, bool) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 {
		return flowKey{}, false
	}
	ihl := int(p[0]&15) * 4
	if ihl < 20 || len(p) < ihl+14 || binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
		return flowKey{}, false
	}
	t := p[ihl:]
	if t[13]&0x12 != 0x02 { // SYN set, ACK clear
		return flowKey{}, false
	}
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[16:20])), binary.BigEndian.Uint16(t[2:4]))
	return flowKey{sport: binary.BigEndian.Uint16(t[0:2]), dst: dst}, true
}

// --- nfnetlink_queue wire format (host byte order = little endian; amd64/arm64) ---

const (
	nfnlSubsysQueue    = 3
	nfqnlMsgPacket     = 0
	nfqnlMsgVerdict    = 1
	nfqnlMsgConfig     = 2
	nfqaPacketHdr      = 1
	nfqaVerdictHdr     = 2
	nfqaMark           = 3
	nfqaPayload        = 10
	nfqaCfgCmd         = 1
	nfqaCfgParams      = 2
	nfqaCfgQueueMaxlen = 3
	nfqaCfgMask        = 4
	nfqaCfgFlags       = 5
	nfqnlCfgCmdBind    = 1
	nfqnlCopyPacket    = 2
	nfqaCfgFFailOpen   = 1
	nlmsgError         = 2
	nlmFRequest        = 1
	nlmFAck            = 4
	nfDrop             = 0
	nfAccept           = 1
)

func nlAttr(b []byte, typ uint16, val []byte) []byte {
	b = binary.LittleEndian.AppendUint16(b, uint16(4+len(val)))
	b = binary.LittleEndian.AppendUint16(b, typ)
	b = append(b, val...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func nfqMsg(msgType, flags uint16, seq uint32, queue uint16, attrs []byte) []byte {
	b := make([]byte, 16, 20+len(attrs))
	binary.LittleEndian.PutUint16(b[4:], nfnlSubsysQueue<<8|msgType)
	binary.LittleEndian.PutUint16(b[6:], flags)
	binary.LittleEndian.PutUint32(b[8:], seq)
	b = append(b, 2 /* AF_INET */, 0)
	b = binary.BigEndian.AppendUint16(b, queue)
	b = append(b, attrs...)
	binary.LittleEndian.PutUint32(b[0:], uint32(len(b)))
	return b
}

func nfqBindMsgs(queue uint16, maxLen uint32) [][]byte {
	bind := nlAttr(nil, nfqaCfgCmd, []byte{nfqnlCfgCmdBind, 0, 0, 2})
	params := nlAttr(nil, nfqaCfgParams, append(be32(128), nfqnlCopyPacket))
	params = nlAttr(params, nfqaCfgQueueMaxlen, be32(maxLen))
	params = nlAttr(params, nfqaCfgMask, be32(nfqaCfgFFailOpen))
	params = nlAttr(params, nfqaCfgFlags, be32(nfqaCfgFFailOpen))
	return [][]byte{
		nfqMsg(nfqnlMsgConfig, nlmFRequest|nlmFAck, 1, queue, bind),
		nfqMsg(nfqnlMsgConfig, nlmFRequest|nlmFAck, 2, queue, params),
	}
}

func nfqVerdictMsg(queue uint16, id, verdict uint32, setMark bool, mark uint32) []byte {
	a := nlAttr(nil, nfqaVerdictHdr, append(be32(verdict), be32(id)...))
	if setMark {
		a = nlAttr(a, nfqaMark, be32(mark))
	}
	return nfqMsg(nfqnlMsgVerdict, nlmFRequest, 0, queue, a)
}

type nfqPacket struct {
	id      uint32
	mark    uint32
	payload []byte
}

// parseNFQ splits a netlink datagram into queued packets and the first
// NLMSG_ERROR code (0 = ack) with its sequence number.
func parseNFQ(b []byte) (pkts []nfqPacket, errSeq uint32, errno int32, hasErr bool) {
	for len(b) >= 16 {
		l := int(binary.LittleEndian.Uint32(b[0:4]))
		if l < 16 || l > len(b) {
			return
		}
		typ := binary.LittleEndian.Uint16(b[4:6])
		m := b[:l]
		switch {
		case typ == nlmsgError && l >= 20 && !hasErr:
			errno = int32(binary.LittleEndian.Uint32(m[16:20]))
			if l >= 36 {
				errSeq = binary.LittleEndian.Uint32(m[28:32])
			}
			hasErr = true
		case typ == nfnlSubsysQueue<<8|nfqnlMsgPacket && l >= 20:
			var p nfqPacket
			okHdr := false
			for a := m[20:]; len(a) >= 4; {
				al := int(binary.LittleEndian.Uint16(a[0:2]))
				at := binary.LittleEndian.Uint16(a[2:4]) & 0x3fff
				if al < 4 || al > len(a) {
					break
				}
				v := a[4:al]
				switch at {
				case nfqaPacketHdr:
					if len(v) >= 4 {
						p.id, okHdr = binary.BigEndian.Uint32(v[0:4]), true
					}
				case nfqaMark:
					if len(v) >= 4 {
						p.mark = binary.BigEndian.Uint32(v)
					}
				case nfqaPayload:
					p.payload = v
				}
				adv := (al + 3) &^ 3
				if adv > len(a) {
					break
				}
				a = a[adv:]
			}
			if okHdr {
				pkts = append(pkts, p)
			}
		}
		b = b[(l+3)&^3:]
		if len(b) < 16 {
			break
		}
	}
	return
}
