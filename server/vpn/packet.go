package vpn

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ClientIP = netip.MustParseAddr("10.77.0.2")

// ValidateIPv4 checks complete packet boundaries and the authorized endpoint.
// Fragments (MF, offset, reserved flag) are rejected; DF is allowed. The inner
// checksum is left to the IP stack (and may be offloaded on TUN reads).
func ValidateIPv4(p []byte, endpoint netip.Addr, source bool) error {
	if len(p) < 20 || len(p) > MaxPlaintext || p[0]>>4 != 4 {
		return errors.New("invalid IPv4 size/version")
	}
	ihl := int(p[0]&15) * 4
	if ihl < 20 || ihl > len(p) || int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
		return errors.New("invalid IPv4 IHL/total length")
	}
	if binary.BigEndian.Uint16(p[6:8])&0xbfff != 0 {
		return errors.New("fragmented/reserved IPv4 not supported")
	}
	off := 16
	if source {
		off = 12
	}
	addr := netip.AddrFrom4([4]byte(p[off : off+4]))
	if addr != endpoint {
		return errors.New("unauthorized inner IPv4 endpoint")
	}
	return nil
}

// Checksum is the RFC 1071 one's-complement checksum; a valid received ICMP
// message (including its checksum field) returns zero.
func Checksum(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) == 1 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

type Echo struct {
	Source     netip.Addr
	Identifier uint16
	Sequence   uint16
	Payload    []byte
}

// ParseRawEcho accepts a Linux raw IPv4 receive (variable IHL followed by ICMP).
// The raw socket is dedicated to protocol echo requests, so other types fail.
func ParseRawEcho(p []byte) (Echo, error) {
	var e Echo
	if len(p) < 20 || p[0]>>4 != 4 {
		return e, errors.New("invalid outer IPv4")
	}
	ihl := int(p[0]&15) * 4
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if ihl < 20 || ihl > len(p) || total != len(p) || p[9] != 1 {
		return e, errors.New("invalid outer IHL/length/protocol")
	}
	if binary.BigEndian.Uint16(p[6:8])&0xbfff != 0 {
		return e, errors.New("outer IPv4 fragment")
	}
	body := p[ihl:]
	if len(body) < 8 || len(body) > MaxICMPSize || body[0] != 8 || body[1] != 0 || Checksum(body) != 0 {
		return e, errors.New("invalid ICMP request/checksum")
	}
	e.Source = netip.AddrFrom4([4]byte(p[12:16]))
	e.Identifier = binary.BigEndian.Uint16(body[4:6])
	e.Sequence = binary.BigEndian.Uint16(body[6:8])
	e.Payload = append([]byte(nil), body[8:]...)
	return e, nil
}
func BuildEcho(typ byte, id, seq uint16, payload []byte) ([]byte, error) {
	if (typ != 0 && typ != 8) || len(payload) > MaxICMPSize-8 {
		return nil, errors.New("invalid echo type/size")
	}
	b := make([]byte, 8+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], payload)
	binary.BigEndian.PutUint16(b[2:4], Checksum(b))
	return b, nil
}
