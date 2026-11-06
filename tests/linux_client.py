"""Independent Linux ping-socket/TUN interop client, NOT the Android app.
Drops all UID privileges before opening its ICMP socket. Setup is container-only.
"""
import argparse
import collections
import fcntl
import hashlib
import hmac
import os
import secrets
import select
import socket
import struct
import subprocess
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


class Codec:
    def __init__(self, key, sid):
        self.sid, self.seq, self.high = sid, 0, 0
        self.replay_window = 32768
        self.seen = bytearray(self.replay_window)
        self.keys = [AESGCM(hmac.new(key, b'icmp-vpn-v1/' + bytes([d]) + struct.pack('!Q', sid), hashlib.sha256).digest()) for d in (0, 1)]

    def encode(self, kind, payload=b''):
        self.seq += 1
        header = struct.pack('!4sBBQQH', b'IVP1', 1, kind, self.sid, self.seq, len(payload))
        return header + self.keys[0].encrypt(bytes(4) + struct.pack('!Q', self.seq), payload, header)

    def decode(self, frame):
        if len(frame) < 40:
            raise ValueError('short')
        magic, version, kind, sid, seq, size = struct.unpack('!4sBBQQH', frame[:24])
        if magic != b'IVP1' or version != 1 or kind > 3 or sid != self.sid or not seq or size > 1200 or len(frame) != 40 + size:
            raise ValueError('header')
        plain = self.keys[1].decrypt(bytes(4) + struct.pack('!Q', seq), frame[24:], frame[:24])
        if (kind in (0, 3) and plain) or seq <= self.high - self.replay_window:
            raise ValueError('semantic/replay')
        if seq > self.high:
            delta = seq-self.high
            if delta >= self.replay_window:
                self.seen = bytearray(self.replay_window)
            else:
                for i in range(self.high+1, seq+1):
                    self.seen[i & (self.replay_window-1)] = 0
            self.high = seq
        slot = seq & (self.replay_window-1)
        if self.seen[slot]:
            raise ValueError('duplicate')
        self.seen[slot] = 1
        return kind, plain


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', required=True)
    ap.add_argument('--target')
    ap.add_argument('--java-controller', action='store_true')
    ap.add_argument('--leak-guard', action='store_true', help='reject ALL eth0 egress except the server')
    ap.add_argument('--key-file', required=True)
    args = ap.parse_args()
    with open(args.key_file, 'rb') as fh:
        key = fh.read()  # same 32 raw-byte key format as the server
    if len(key) != 32:
        raise ValueError('key size')
    fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', b'clienttun0', 0x1001))
    def ip(*a):
        subprocess.run(['ip', *a], check=True)
    ip('addr', 'add', '10.77.0.2/32', 'dev', 'clienttun0')
    ip('link', 'set', 'clienttun0', 'mtu', '1200', 'up')
    ip('route', 'add', args.server + '/32', 'dev', 'eth0')
    if args.target:
        ip('route', 'replace', args.target + '/32', 'dev', 'clienttun0', 'src', '10.77.0.2')
    ip('route', 'replace', 'default', 'dev', 'clienttun0', 'src', '10.77.0.2')
    # A direct eth0 false-positive must fail rather than pass this test.
    if args.target:
        subprocess.run(['iptables', '-A', 'OUTPUT', '-d', args.target, '-o', 'eth0', '-j', 'REJECT'], check=True)
    if args.leak_guard:
        subprocess.run(['iptables', '-A', 'OUTPUT', '-o', 'eth0', '!', '-d', args.server, '-j', 'REJECT'], check=True)
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    sock.connect((args.server, 0))
    sock.setblocking(False)
    codec = Codec(key, secrets.randbits(64) or 1)
    queue = collections.deque(maxlen=256)
    established = False
    flow = None
    if args.java_controller:
        from throughput_probe import JavaFlow
        flow = JavaFlow()
    start = start_all = last_rx = time.monotonic()
    next_tx = 0.0
    stats = dict(authenticated=0, invalid=0, up=0, down=0)
    # Diagnostic per-second trace (not a protocol change): request/reply rates,
    # controller state, TUN backlog and time spent in the Java IPC bridge.
    tr = dict(req=0, rep=0, data=0, empty=0, tun_in=0, qdrop=0, ipc=0.0, ipc_n=0, busy=0.0)
    trace_at = time.monotonic() + 1
    if flow:
        _call = flow.call
        def timed(*a):
            t0 = time.perf_counter()
            try:
                return _call(*a)
            finally:
                tr['ipc'] += time.perf_counter() - t0; tr['ipc_n'] += 1
        flow.call = timed
    print('UNROOTED_PING_SOCKET uid=%s cap_eff=%s' % (os.getuid(), [x.strip() for x in open('/proc/self/status') if x.startswith('CapEff:')][0]), flush=True)
    while True:
        now = time.monotonic()
        if now - last_rx > 60:
            raise TimeoutError('no authenticated server reply in 60 seconds')
        for burst in range(16 if flow and established else 1):
            if flow and established:
                if not flow.should_send(now, bool(queue)): break
            elif now < next_tx: break
            kind, payload = (1, queue.popleft()) if established and queue else (0 if established else 2, b'')
            frame = codec.encode(kind, payload)
            icmp = struct.pack('!BBHHH', 8, 0, 0, 0, codec.seq & 65535) + frame
            icmp = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
            sock.send(icmp)
            tr['req'] += 1
            if flow: flow.on_sent(codec.seq & 65535, now)
            if kind == 1:
                stats['up'] += 1
            next_tx = now + 0.02
        if flow and established: flow.reap(now)
        wait = flow.poll_timeout(time.monotonic()) if flow and established else max(0, min(0.02, next_tx-time.monotonic()))
        t_sel = time.perf_counter()
        readable, _, _ = select.select([sock, fd] if established else [sock], [], [], wait)
        t_after = time.perf_counter()
        if established and time.monotonic() >= trace_at:
            print('TRACE t=%.0f req=%d rep=%d data=%d empty=%d tun_in=%d qdrop=%d qlen=%d win=%s inflight=%s srtt=%.0f lost=%s ipc_ms=%.0f ipc_n=%d' % (
                time.monotonic()-start_all, tr['req'], tr['rep'], tr['data'], tr['empty'], tr['tun_in'], tr['qdrop'], len(queue),
                getattr(flow,'window','-'), getattr(flow,'inflight','-'), getattr(flow,'srtt',0)*1000, getattr(flow,'lost','-'),
                tr['ipc']*1000, tr['ipc_n']), flush=True)
            for k in tr: tr[k] = 0 if k not in ('ipc',) else 0.0
            trace_at = time.monotonic() + 1
        if fd in readable:
            packet = os.read(fd, 65535)
            if packet and packet[0] >> 4 == 4 and len(packet) <= 1200:
                if len(queue) == queue.maxlen: tr['qdrop'] += 1
                queue.append(packet)
                tr['tun_in'] += 1
                next_tx = 0
        if sock in readable:
            packet = sock.recv(4096)
            try:
                if len(packet) < 8 or packet[0] != 0 or packet[1] != 0 or checksum(packet) != 0:
                    raise ValueError('icmp')
                kind, plain = codec.decode(packet[8:])
                stats['authenticated'] += 1
                last_rx = time.monotonic()
                tr['rep'] += 1
                tr['data' if kind == 1 else 'empty'] += 1
                if flow: flow.on_reply(struct.unpack('!H',packet[6:8])[0], kind == 1, last_rx)
                if kind == 2:
                    if plain != b'10.77.0.2|1200':
                        raise ValueError('hello config')
                    if not established:
                        established = True
                        print('READY encrypted ICMP + TUN handshake', flush=True)
                elif kind == 1:
                    if not established or len(plain) < 20 or plain[0] >> 4 != 4 or plain[16:20] != socket.inet_aton('10.77.0.2'):
                        raise ValueError('IP destination')
                    os.write(fd, plain)
                    stats['down'] += 1
                    next_tx = 0
            except Exception:
                stats['invalid'] += 1
        if time.monotonic() - start > 60:
            print('STATS', stats, flush=True)
            start = time.monotonic()


if __name__ == '__main__':
    main()
