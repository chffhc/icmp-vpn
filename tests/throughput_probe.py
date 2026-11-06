"""A/B downstream throughput over the REAL deployed server (host-native ICMP socket).

mode=pingpong reproduces the old Android scheduler (timer every 20 ms, plus one
immediate request after each data reply => ~1 request outstanding).
mode=window mirrors the new Android FlowControl.java (adaptive outstanding
requests, slow start/AIMD, 20 ms idle poll). Not an Android measurement.
"""
import argparse
import atexit
import json
import os
import subprocess
import secrets
import socket
import struct
import time

from host_wan_probe import Tunnel, ipv4, udp

MIN_W, MAX_W, INIT_W, IDLE, SLOTS = 2, 256, 4, 0.020, 4096
SERVER_TUN = socket.inet_aton('10.77.0.1')


class Flow:
    """Line-for-line port of android/.../FlowControl.java (seconds instead of ms)."""

    def __init__(self):
        self.sent_at = [0.0] * SLOTS
        self.inflight = 0
        self.window = float(INIT_W)
        self.ssthresh = float(MAX_W)
        self.srtt = 0.0
        self.next_idle = 0.0
        self.next_packet = 0.0
        self.sent_sequence = [0] * SLOTS
        self.burst_until = 0.0
        self.last_backoff = -1e9
        self.lost = 0

    def should_send(self, now, upload):
        if now < self.next_packet or self.inflight >= MAX_W:
            return False
        if upload:
            return True
        if now < self.burst_until and self.inflight < int(self.window):
            return True
        return now >= self.next_idle

    def on_sent(self, seq, now):
        slot = seq & (SLOTS - 1)
        if self.sent_at[slot]:
            self.inflight -= 1
            self.lost += 1
            self._backoff(now)
        self.sent_at[slot] = now
        self.sent_sequence[slot] = seq & 65535
        self.next_packet = now + 0.001
        self.inflight += 1
        self.next_idle = now + IDLE

    def on_reply(self, seq, data, now):
        slot = seq & (SLOTS - 1)
        sent = self.sent_at[slot]
        if not sent or self.sent_sequence[slot] != (seq & 65535):
            return
        if sent:
            self.sent_at[slot] = 0.0
            self.inflight -= 1
            sample = max(0.001, now - sent)
            self.srtt = sample if not self.srtt else (7 * self.srtt + sample) / 8
        if data:
            self.window = min(MAX_W, self.window + 1 if self.window < self.ssthresh else self.window + 1 / self.window)
            self.burst_until = now + min(1.0, max(0.040, 2 * self.srtt + IDLE))
        else:
            self.burst_until = 0.0

    def reap(self, now):
        limit = min(3.0, max(1.0, 4 * self.srtt))
        any_lost = False
        for i, t in enumerate(self.sent_at):
            if t and now - t > limit:
                self.sent_at[i] = 0.0
                self.inflight -= 1
                self.lost += 1
                any_lost = True
        if any_lost:
            self._backoff(now)

    def _backoff(self, now):
        if now - self.last_backoff <= max(self.srtt, IDLE):
            return
        self.ssthresh = max(MIN_W, self.window / 2)
        self.window = self.ssthresh
        self.last_backoff = now


class JavaFlow:
    """Run the exact shipping FlowControl.java in a persistent JVM subprocess."""
    def __init__(self):
        self.proc = subprocess.Popen([os.environ['IVPN_JAVA'], '-cp', os.environ['IVPN_JAVA_CLASSES'],
                                      'FlowControlHarness'], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, bufsize=1)
        self.inflight = self.window = self.lost = 0
        self.srtt = 0.0
        atexit.register(self.close)

    def call(self, cmd, now, *args):
        line = ' '.join([cmd, str(int(now * 1000))] + [str(x).lower() for x in args])
        self.proc.stdin.write(line + '\n')
        self.proc.stdin.flush()
        fields = self.proc.stdout.readline().split()
        if len(fields) != 6:
            raise RuntimeError('Java controller failed')
        ready, timeout, self.inflight, self.window, srtt_ms, self.lost = fields
        self.inflight, self.window, self.lost = int(self.inflight), int(self.window), int(self.lost)
        self.srtt = int(srtt_ms) / 1000.0
        return ready == 'true', int(timeout) / 1000.0

    def should_send(self, now, upload):
        return self.call('Q', now, upload)[0]

    def poll_timeout(self, now):
        return self.call('Q', now, False)[1]

    def on_sent(self, seq, now):
        self.call('S', now, seq)

    def on_reply(self, seq, data, now):
        self.call('R', now, seq, data)

    def reap(self, now):
        self.call('E', now)

    def close(self):
        if self.proc.poll() is None:
            self.proc.stdin.close()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def recv_seq(t):
    """Like Tunnel.recv, but also returns the mirrored ICMP echo sequence."""
    try:
        pkt = t.sock.recv(4096)
    except (socket.timeout, BlockingIOError):
        return None
    if pkt and pkt[0] >> 4 == 4:
        pkt = pkt[(pkt[0] & 15) * 4:]
    if len(pkt) < 8 or pkt[0] != 0:
        return None
    seq = struct.unpack('!H', pkt[6:8])[0]
    try:
        kind, plain = t.codec.decode(pkt[8:])
    except Exception:
        t.stats['rejected_unauth'] += 1  # e.g. the server kernel's own plain echo reply
        return None
    t.stats['auth_ok'] += 1
    return seq, kind, plain


def send_seq(t, seq, kind, payload=b''):
    from linux_client import checksum
    frame = t.codec.encode(kind, payload)
    icmp = struct.pack('!BBHHH', 8, 0, 0, 0, seq) + frame
    icmp = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
    t.sock.send(icmp)
    t.stats['sent'] += 1


def run(t, mode, count, size, rate, duration, controller="python"):
    run_id = secrets.randbits(31)
    sport = 40000 + secrets.randbelow(20000)
    go = ipv4(17, SERVER_TUN, udp(SERVER_TUN, sport, 47000, b'GO' + struct.pack('!IIIi', count, size, rate, run_id)), secrets.randbits(16))
    flow = JavaFlow() if controller == "java" and mode == "window" else Flow()
    echo = 0
    got = set()
    first = last = None
    go_sent = 0
    next_go = 0.0
    next_tick = 0.0  # pingpong timer
    t.sock.settimeout(0.002)
    start = time.monotonic()
    while time.monotonic() - start < duration and len(got) < count:
        now = time.monotonic()
        upload = None
        if not got and now >= next_go and go_sent < 5:  # GO, retried like a real stack
            upload = go
            go_sent += 1
            next_go = now + 1.0
        if mode == 'window':
            sent = 0
            while sent < 16 and flow.should_send(now, upload is not None):
                echo = (echo + 1) & 0xFFFF
                send_seq(t, echo, 1 if upload else 0, upload or b'')
                flow.on_sent(echo, now)
                upload = None
                sent += 1
            flow.reap(now)
        else:
            if upload is not None or now >= next_tick:
                echo = (echo + 1) & 0xFFFF
                send_seq(t, echo, 1 if upload else 0, upload or b'')
                next_tick = now + IDLE
        now = time.monotonic()
        if isinstance(flow, JavaFlow):
            wait = flow.poll_timeout(now)
        elif mode == 'window':
            if flow.inflight >= MAX_W:
                wait = IDLE
            elif flow.should_send(now, False):
                wait = 0.0
            elif now < flow.burst_until and flow.inflight < int(flow.window):
                wait = min(IDLE, max(0.0, flow.next_packet - now))
            else:
                wait = min(IDLE, max(0.0, max(flow.next_idle, flow.next_packet) - now))
        else:
            wait = min(IDLE, max(0.0, next_tick - now))
        t.sock.settimeout(wait)
        # Drain everything queued (Android reads up to 32 per poll wakeup).
        for _ in range(64):
            r = recv_seq(t)
            if not r:
                break
            t.sock.settimeout(0)
            seq, kind, plain = r
            now = time.monotonic()
            if mode == 'window':
                flow.on_reply(seq, kind == 1, now)
            elif kind == 1:
                next_tick = min(next_tick, now + 0.001)  # old Android: immediate re-request after data
            if kind == 1 and plain[9] == 17 and plain[12:16] == SERVER_TUN:
                body = plain[(plain[0] & 15) * 4 + 8:]
                if len(body) >= 8 and struct.unpack('!i', body[:4])[0] == run_id:
                    got.add(struct.unpack('!I', body[4:8])[0])
                    first = first or now
                    last = now
        t.sock.settimeout(0.002)
    span = (last - first) if first and last and last > first else None
    if isinstance(flow, JavaFlow):
        flow.close()
    return {
        'mode': mode,
        'controller': controller if mode == 'window' else 'old_python_scheduler',
        'offered_packets': count,
        'offered_rate_pps': rate,
        'packet_bytes': size,
        'received': len(got),
        'delivery_pct': round(100 * len(got) / count, 1),
        'goodput_kbyte_s': round(len(got) * size / span / 1000, 1) if span else 0,
        'seconds': round(span, 2) if span else None,
        'final_window': int(flow.window) if mode == 'window' else 1,
        'srtt_ms': round(flow.srtt * 1000, 1) if mode == 'window' else None,
        'requests_lost': flow.lost if mode == 'window' else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', required=True)
    ap.add_argument('--key-file', required=True)
    ap.add_argument('--controller', choices=['python', 'java'], default='python')
    ap.add_argument('--count', type=int, default=1500)
    ap.add_argument('--size', type=int, default=1100)
    ap.add_argument('--rate', type=int, default=1000)
    a = ap.parse_args()
    with open(a.key_file, 'rb') as fh:
        key = fh.read()
    results = []
    for mode in ['pingpong', 'window']:
        t = Tunnel(a.server, key)
        t.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:  # HELLO
                send_seq(t, 1, 2)
                r = recv_seq(t)
                if r and r[1] == 2:
                    break
            else:
                raise SystemExit('HELLO failed for ' + mode)
            results.append(run(t, mode, a.count, a.size, a.rate, 25, a.controller))
        finally:
            try:
                send_seq(t, 2, 3)  # CLOSE: free the single client slot
            except Exception:
                pass
            t.sock.close()
        time.sleep(1)
    print(json.dumps({'evidence': 'real_internet_macos_icmp_socket_to_deployed_server_old_vs_new_scheduler_not_android',
                      'results': results}, indent=2), flush=True)


if __name__ == '__main__':
    main()
