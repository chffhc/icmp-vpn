package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func synPacket(sport, dport uint16, dst [4]byte, flags byte) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	p[9] = 6
	copy(p[12:16], []byte{10, 77, 0, 2})
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:], sport)
	binary.BigEndian.PutUint16(p[22:], dport)
	p[33] = flags
	return p
}

func TestSynKey(t *testing.T) {
	k, ok := synKey(synPacket(40000, 443, [4]byte{1, 2, 3, 4}, 0x02))
	if !ok || k.sport != 40000 || k.dst != netip.MustParseAddrPort("1.2.3.4:443") {
		t.Fatal(k, ok)
	}
	for _, f := range []byte{0x12, 0x10, 0x00} {
		if _, ok := synKey(synPacket(1, 2, [4]byte{1, 2, 3, 4}, f)); ok {
			t.Errorf("flags %#x accepted", f)
		}
	}
	if _, ok := synKey([]byte{0x45}); ok {
		t.Error("short packet accepted")
	}
	frag := synPacket(1, 2, [4]byte{1, 2, 3, 4}, 0x02)
	frag[7] = 1
	if _, ok := synKey(frag); ok {
		t.Error("fragment accepted")
	}
}

type fakeConn struct {
	net.Conn
	closed bool
}

func (f *fakeConn) Close() error { f.closed = true; return nil }

func TestAdmissionLifecycle(t *testing.T) {
	now := time.Unix(1000, 0)
	a := newAdmission(15*time.Second, 60*time.Second, 2)
	a.now = func() time.Time { return now }
	k := flowKey{40000, netip.MustParseAddrPort("1.2.3.4:443")}
	if d := a.onSYN(k); d != admitDial {
		t.Fatal("first SYN must dial", d)
	}
	if d := a.onSYN(k); d != admitDrop {
		t.Fatal("retransmit while pending must drop", d)
	}
	c := &fakeConn{}
	if d := a.dialDone(k, c, nil); d != admitAccept {
		t.Fatal("success must accept", d)
	}
	if d := a.onSYN(k); d != admitAccept {
		t.Fatal("retransmit after success must accept", d)
	}
	if got := a.take(k); got != c || a.take(k) != nil {
		t.Fatal("take must hand over once")
	}
	// failure => bypass, and the destination stays bypassed for fail-ttl
	k2 := flowKey{40001, netip.MustParseAddrPort("8.8.8.8:443")}
	a.onSYN(k2)
	if d := a.dialDone(k2, nil, errors.New("timeout")); d != admitBypass {
		t.Fatal("failure must bypass", d)
	}
	k3 := flowKey{40002, k2.dst}
	if d := a.onSYN(k3); d != admitBypass {
		t.Fatal("known-failed dst must bypass", d)
	}
	now = now.Add(61 * time.Second)
	if d := a.onSYN(k3); d != admitDial {
		t.Fatal("fail-ttl expiry must retry", d)
	}
	// unclaimed pre-dialed conns are closed by sweep
	k4 := flowKey{40003, netip.MustParseAddrPort("9.9.9.9:80")}
	a.onSYN(k4)
	c4 := &fakeConn{}
	a.dialDone(k4, c4, nil)
	now = now.Add(2 * time.Minute)
	a.sweep()
	if !c4.closed || len(a.flows) != 0 {
		t.Fatal("sweep must close stale pre-dialed conns", c4.closed, len(a.flows))
	}
}

func TestAdmissionCapacityBypasses(t *testing.T) {
	a := newAdmission(time.Second, time.Minute, 1)
	a.onSYN(flowKey{1, netip.MustParseAddrPort("1.1.1.1:1")})
	if d := a.onSYN(flowKey{2, netip.MustParseAddrPort("1.1.1.1:1")}); d != admitBypass {
		t.Fatal("over capacity must bypass, not block", d)
	}
}

func TestNFQWire(t *testing.T) {
	v := nfqVerdictMsg(7011, 42, nfAccept, true, 0x10000000)
	if binary.LittleEndian.Uint32(v) != uint32(len(v)) || binary.LittleEndian.Uint16(v[4:]) != 3<<8|1 {
		t.Fatal("header")
	}
	if binary.BigEndian.Uint16(v[18:20]) != 7011 {
		t.Fatal("queue id must be big endian res_id")
	}
	// attrs: verdict hdr (len 12) then mark (len 8)
	if binary.LittleEndian.Uint16(v[20:]) != 12 || binary.BigEndian.Uint32(v[24:]) != nfAccept || binary.BigEndian.Uint32(v[28:]) != 42 {
		t.Fatal("verdict attr")
	}
	if binary.LittleEndian.Uint16(v[34:]) != nfqaMark || binary.BigEndian.Uint32(v[36:]) != 0x10000000 {
		t.Fatal("mark attr")
	}
	// round-trip a synthetic packet message through the parser
	pl := synPacket(5, 6, [4]byte{1, 2, 3, 4}, 0x02)
	attrs := nlAttr(nil, nfqaPacketHdr, []byte{0, 0, 0, 9, 8, 0, 3})
	attrs = nlAttr(attrs, nfqaMark, be32(0x5))
	attrs = nlAttr(attrs, nfqaPayload, pl)
	m := nfqMsg(nfqnlMsgPacket, 0, 0, 7011, attrs)
	pk, _, _, hasErr := parseNFQ(append(m, m...))
	if hasErr || len(pk) != 2 || pk[0].id != 9 || pk[0].mark != 5 || string(pk[0].payload) != string(pl) {
		t.Fatalf("parse %+v", pk)
	}
	for _, b := range nfqBindMsgs(7011, 4096) {
		if binary.LittleEndian.Uint32(b) != uint32(len(b)) {
			t.Fatal("bind msg len")
		}
	}
}
