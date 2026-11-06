"""Host-native real-Internet probe of the DEPLOYED server (no Docker, no TUN).

Docker Desktop on macOS does not forward container ICMP faithfully (userspace
network stack), so this runs directly on the Mac with an unprivileged ICMP
datagram socket. It performs the IVP1 HELLO, then injects hand-built inner IPv4
packets from 10.77.0.2 (UDP DNS query, TCP SYN) and waits for the server's
NAT'd replies inside authenticated ICMP echo replies.
Proves: WAN ICMP transport + server auth + TUN + NAT + return path.
Does NOT prove Android behaviour.
"""
import argparse
import json
import os
import secrets
import socket
import struct
import time

from linux_client import Codec, checksum

CLIENT = socket.inet_aton('10.77.0.2')


def ipv4(proto, dst, payload, ident):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, CLIENT, dst)
    hdr = hdr[:10] + struct.pack('!H', checksum(hdr)) + hdr[12:]
    return hdr + payload


def udp(dst, sport, dport, data):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    pseudo = CLIENT + dst + struct.pack('!BBH', 0, 17, len(seg))
    c = checksum(pseudo + seg) or 0xFFFF
    return seg[:6] + struct.pack('!H', c) + seg[8:]


def tcp_syn(dst, sport, dport, seq):
    opts = struct.pack('!BBH', 2, 4, 1160)  # MSS 1160, same clamp as Android client
    seg = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, (5 + 1) << 4, 0x02, 64240, 0, 0) + opts
    pseudo = CLIENT + dst + struct.pack('!BBH', 0, 6, len(seg))
    c = checksum(pseudo + seg)
    return seg[:16] + struct.pack('!H', c) + seg[18:]


def dns_query(name, qid):
    q = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    q += b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'
    return q + struct.pack('!HH', 1, 1)


class Tunnel:
    def __init__(self, server, key):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        self.sock.connect((server, 0))
        self.sock.settimeout(0.02)
        self.codec = Codec(key, secrets.randbits(64) or 1)
        self.stats = dict(sent=0, auth_ok=0, rejected_unauth=0)

    def send(self, kind, payload=b''):
        frame = self.codec.encode(kind, payload)
        icmp = struct.pack('!BBHHH', 8, 0, 0, os.getpid() & 0xFFFF, self.codec.seq & 0xFFFF) + frame
        icmp = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
        self.sock.send(icmp)
        self.stats['sent'] += 1

    def recv(self):
        try:
            pkt = self.sock.recv(4096)
        except socket.timeout:
            return None
        # Darwin ICMP datagram sockets deliver the IPv4 header; Linux does not.
        if pkt and pkt[0] >> 4 == 4:
            pkt = pkt[(pkt[0] & 15) * 4:]
        if len(pkt) < 8 or pkt[0] != 0:
            return None
        try:
            kind, plain = self.codec.decode(pkt[8:])
        except Exception:
            self.stats['rejected_unauth'] += 1  # e.g. the kernel's own plain echo reply
            return None
        self.stats['auth_ok'] += 1
        return kind, plain

    def exchange(self, kind, payload, match, timeout):
        """Send payload, then keep polling until match(inner_ip) or timeout."""
        # Paced like the real clients: one request per 20 ms, never one per reply
        # (the server kernel also auto-answers each echo, so per-reply sending
        # would double traffic every round trip). Resend the payload every 1 s,
        # like a real TCP/DNS stack retransmitting a lost packet.
        end = time.monotonic() + timeout
        next_payload = 0.0
        next_poll = 0.0
        while time.monotonic() < end:
            now = time.monotonic()
            if now >= next_payload:
                self.send(kind, payload)
                next_payload = now + 1.0
                next_poll = now + 0.02
            elif now >= next_poll:
                self.send(0)  # POLL to pull queued downstream packets
                next_poll = now + 0.02
            r = self.recv()
            if r and r[0] == 1 and match(r[1]):
                return r[1]
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', required=True)
    ap.add_argument('--key-file', required=True)
    a = ap.parse_args()
    with open(a.key_file, 'rb') as fh:
        key = fh.read()
    assert len(key) == 32, 'key must be 32 raw bytes'
    t = Tunnel(a.server, key)
    try:
        run(t)
    finally:
        # Always release the server's single active slot, even on failure;
        # otherwise the next connection is refused until the 120 s idle timeout.
        try:
            t.send(3)
        except Exception:
            pass


def run(t):
    out = {'evidence': 'real_internet_macos_unprivileged_icmp_socket_to_deployed_server_not_android'}

    start = time.monotonic()
    hello = None
    while time.monotonic() - start < 10 and not hello:
        t.send(2)
        r = t.recv()
        if r and r[0] == 2:
            hello = r[1]
    assert hello == b'10.77.0.2|1200', 'HELLO failed: %r stats=%r' % (hello, t.stats)
    out['hello_reply'] = hello.decode()
    out['hello_rtt_ms'] = round((time.monotonic() - start) * 1000, 1)

    results = {}
    for resolver, name in [('223.5.5.5', 'www.baidu.com'), ('1.1.1.1', 'example.com')]:
        dst = socket.inet_aton(resolver)
        qid = secrets.randbits(16)
        sport = 40000 + secrets.randbelow(20000)
        pkt = ipv4(17, dst, udp(dst, sport, 53, dns_query(name, qid)), secrets.randbits(16))
        reply = t.exchange(1, pkt, lambda p: p[9] == 17 and p[12:16] == dst and p[(p[0] & 15) * 4 + 2:(p[0] & 15) * 4 + 4] == struct.pack('!H', sport), 8)
        assert reply, 'no DNS reply from %s via tunnel' % resolver
        body = reply[(reply[0] & 15) * 4 + 8:]
        assert body[:2] == struct.pack('!H', qid), 'DNS id mismatch'
        results['udp_dns_%s_%s_answers' % (resolver, name)] = struct.unpack('!H', body[6:8])[0]
    out.update(results)

    # 1.1.1.1:443 is unreachable from this cloud server even without the tunnel
    # (verified with curl on the server), so use targets the server can reach.
    for host, port in [('223.5.5.5', 443), ('220.181.111.1', 443)]:
        dst = socket.inet_aton(host)
        sport = 40000 + secrets.randbelow(20000)
        seq = secrets.randbits(32)
        pkt = ipv4(6, dst, tcp_syn(dst, sport, port, seq), secrets.randbits(16))
        t0 = time.monotonic()
        reply = t.exchange(1, pkt, lambda p: p[9] == 6 and p[12:16] == dst and p[(p[0] & 15) * 4 + 2:(p[0] & 15) * 4 + 4] == struct.pack('!H', sport), 8)
        assert reply, 'no TCP reply from %s:%d via tunnel' % (host, port)
        th = reply[(reply[0] & 15) * 4:]
        flags = th[13]
        ack = struct.unpack('!I', th[8:12])[0]
        assert flags & 0x12 == 0x12 and ack == (seq + 1) & 0xFFFFFFFF, 'not a matching SYN-ACK'
        out['tcp_synack_%s_%d_ms' % (host, port)] = round((time.monotonic() - t0) * 1000, 1)
        # Politely reset the half-open connection on the remote end.
        rst = struct.pack('!HHIIBBHHH', sport, port, (seq + 1) & 0xFFFFFFFF, 0, 5 << 4, 0x04, 0, 0, 0)
        c = checksum(CLIENT + dst + struct.pack('!BBH', 0, 6, len(rst)) + rst)
        t.send(1, ipv4(6, dst, rst[:16] + struct.pack('!H', c) + rst[18:], secrets.randbits(16)))

    out['tunnel_stats'] = t.stats
    out['status'] = 'PASS'
    print(json.dumps(out, indent=2), flush=True)


if __name__ == '__main__':
    main()
