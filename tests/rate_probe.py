"""Find the ICMP echo rate the path sustains: send authenticated POLLs at fixed
rates for 2 s each and count authenticated replies. Real deployed server."""
import argparse
import json
import os
import socket
import time

from host_wan_probe import Tunnel
from throughput_probe import recv_seq, send_seq


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', required=True)
    ap.add_argument('--key-file', required=True)
    a = ap.parse_args()
    with open(a.key_file, 'rb') as fh:
        key = fh.read()
    t = Tunnel(a.server, key)
    out = []
    try:
        end = time.monotonic() + 10
        while time.monotonic() < end:
            send_seq(t, 1, 2)
            r = recv_seq(t)
            if r and r[1] == 2:
                break
        else:
            raise SystemExit('HELLO failed')
        t.sock.settimeout(0.0005)
        seq = 1
        for rate in [int(x) for x in os.environ.get('IVPN_RATES', '100,250,500,1000,1500,2000').split(',')]:
            sent = got = 0
            start = time.monotonic()
            while time.monotonic() - start < 2.0:
                now = time.monotonic()
                while sent < int((now - start) * rate):
                    seq = (seq + 1) & 0xFFFF
                    send_seq(t, seq, 0)
                    sent += 1
                if recv_seq(t):
                    got += 1
            drain = time.monotonic() + 0.5
            while time.monotonic() < drain:
                if recv_seq(t):
                    got += 1
            out.append({'rate_pps': rate, 'sent': sent, 'auth_replies': got, 'loss_pct': round(100 * (sent - got) / sent, 1)})
            time.sleep(0.5)
    finally:
        try:
            send_seq(t, 3, 3)
        except Exception:
            pass
    print(json.dumps(out, indent=1))


if __name__ == '__main__':
    main()
