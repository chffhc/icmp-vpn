"""Loaded-latency probe over the REAL deployed server (host-native ICMP socket).

Uses the exact shipping FlowControl.java (JavaFlow) as the request scheduler.
Phases: idle -> bulk download offered ABOVE tunnel capacity (like a TCP flow
that fills every buffer) -> idle again. Throughout, small UDP pings (b'PG')
travel through the tunnel to the temporary server-side echo in udp_blaster.py
and their round-trip times are recorded per phase.
Not an Android measurement.
"""
import argparse
import json
import secrets
import socket
import statistics
import struct
import time

from host_wan_probe import Tunnel, ipv4, udp
from throughput_probe import JavaFlow, SERVER_TUN, recv_seq, send_seq


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    return round(s[min(len(s) - 1, int(p / 100 * len(s)))], 1)


def summarize(rtts, sent):
    return {
        'pings_sent': sent,
        'pings_back': len(rtts),
        'p50_ms': pct(rtts, 50),
        'p90_ms': pct(rtts, 90),
        'max_ms': round(max(rtts), 1) if rtts else None,
        'mean_ms': round(statistics.mean(rtts), 1) if rtts else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', required=True)
    ap.add_argument('--key-file', required=True)
    ap.add_argument('--bulk-rate', type=int, default=4000)
    ap.add_argument('--bulk-seconds', type=float, default=8)
    ap.add_argument('--size', type=int, default=1100)
    a = ap.parse_args()
    with open(a.key_file, 'rb') as fh:
        key = fh.read()
    t = Tunnel(a.server, key)
    t.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    flow = JavaFlow()
    out = {'evidence': 'real_internet_macos_icmp_socket_to_deployed_server_java_flowcontrol_not_android'}
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            send_seq(t, 1, 2)
            r = recv_seq(t)
            if r and r[1] == 2:
                break
        else:
            raise SystemExit('HELLO failed')
        echo = 1
        sport = 40000 + secrets.randbelow(20000)
        ping_port = sport + 1
        run_id = secrets.randbits(31)
        count = int(a.bulk_rate * a.bulk_seconds)
        go = ipv4(17, SERVER_TUN, udp(SERVER_TUN, sport, 47000, b'GO' + struct.pack('!IIIi', count, a.size, a.bulk_rate, run_id)), secrets.randbits(16))
        pending = {}           # ping id -> send time
        rtts = {'idle_before': [], 'loaded': [], 'idle_after': []}
        sent = {k: 0 for k in rtts}
        bulk_got = set()
        upload = []
        t0 = time.monotonic()
        phase_end = {'idle_before': 3.0, 'loaded': 3.0 + a.bulk_seconds + 1.0, 'idle_after': 3.0 + a.bulk_seconds + 5.0}
        go_sent = False
        next_ping = 0.0
        ping_id = 0
        t.sock.settimeout(0)
        while True:
            now = time.monotonic()
            el = now - t0
            phase = 'idle_before' if el < phase_end['idle_before'] else 'loaded' if el < phase_end['loaded'] else 'idle_after'
            if el >= phase_end['idle_after']:
                break
            if phase == 'loaded' and not go_sent:
                upload.append(go)
                go_sent = True
            if now >= next_ping:
                ping_id += 1
                pending[ping_id] = (now, phase)
                sent[phase] += 1
                upload.append(ipv4(17, SERVER_TUN, udp(SERVER_TUN, ping_port, 47000, b'PG' + struct.pack('!I', ping_id)), secrets.randbits(16)))
                next_ping = now + 0.05
            n = 0
            while n < 16 and flow.should_send(now, bool(upload)):
                echo = (echo + 1) & 0xFFFF
                payload = upload.pop(0) if upload else b''
                send_seq(t, echo, 1 if payload else 0, payload)
                flow.on_sent(echo, now)
                n += 1
            flow.reap(now)
            t.sock.settimeout(min(0.02, flow.poll_timeout(time.monotonic()) if not upload else 0) or 0.0005)
            for _ in range(64):
                r = recv_seq(t)
                if not r:
                    break
                t.sock.settimeout(0)
                seq, kind, plain = r
                rnow = time.monotonic()
                flow.on_reply(seq, kind == 1, rnow)
                if kind != 1 or plain[9] != 17 or plain[12:16] != SERVER_TUN:
                    continue
                ihl = (plain[0] & 15) * 4
                dport = struct.unpack('!H', plain[ihl + 2:ihl + 4])[0]
                body = plain[ihl + 8:]
                if dport == ping_port and body[:2] == b'PG':
                    pid = struct.unpack('!I', body[2:6])[0]
                    if pid in pending:
                        st, ph = pending.pop(pid)
                        rtts[ph].append((rnow - st) * 1000)
                elif dport == sport and len(body) >= 8 and struct.unpack('!i', body[:4])[0] == run_id:
                    bulk_got.add(struct.unpack('!I', body[4:8])[0])
        for ph in rtts:
            out[ph] = summarize(rtts[ph], sent[ph])
        out['bulk'] = {'offered_pps': a.bulk_rate, 'offered': count, 'received': len(bulk_got),
                       'goodput_mbps': round(len(bulk_got) * a.size * 8 / a.bulk_seconds / 1e6, 1)}
        out['controller'] = {'final_window': flow.window, 'srtt_ms': round(flow.srtt * 1000, 1), 'requests_lost': flow.lost}
    finally:
        try:
            send_seq(t, 2, 3)
        except Exception:
            pass
        flow.close()
        t.sock.close()
    print(json.dumps(out, indent=1), flush=True)


if __name__ == '__main__':
    main()
