"""Real kernel TCP bulk download timeline through the tunnel (Linux, not Android).
Fresh connection per size; reports connect, first byte, milestones and goodput.
"""
import argparse
import json
import socket
import time

ap = argparse.ArgumentParser()
ap.add_argument('--target', required=True)
ap.add_argument('--server', required=True)
ap.add_argument('--sizes', default='131072,1048576,4194304')
ap.add_argument('--deadline', type=float, default=150)
a = ap.parse_args()
results = []
for size in [int(x) for x in a.sizes.split(',')]:
    t0 = time.monotonic()
    s = socket.create_connection((a.target, 8080), timeout=a.deadline)
    t_conn = time.monotonic() - t0
    cc = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 16).rstrip(b'\0').decode()
    s.sendall(b'GET /bytes/%d HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n' % size)
    got, first, marks, buf = 0, None, {}, b''
    header_done = False
    end = t0 + a.deadline
    while True:
        s.settimeout(max(0.1, end - time.monotonic()))
        try:
            d = s.recv(262144)
        except socket.timeout:
            break
        if not d:
            break
        now = time.monotonic() - t0
        if not header_done:
            buf += d
            i = buf.find(b'\r\n\r\n')
            if i < 0:
                continue
            header_done = True
            first = now
            d = buf[i+4:]
        got += len(d)
        for m in (65536, 262144, 1048576, 4194304):
            if got >= m and m not in marks and m <= size:
                marks[m] = round(now, 2)
    total = time.monotonic() - t0
    s.close()
    body_time = total - (first or total)
    results.append({'size': size, 'received': got, 'complete': got == size, 'cc': cc,
                    'connect_s': round(t_conn, 2), 'first_byte_s': round(first or -1, 2),
                    'milestones_s': marks, 'total_s': round(total, 2),
                    'avg_mbps': round(got * 8 / total / 1e6, 3),
                    'body_mbps': round(got * 8 / body_time / 1e6, 3) if body_time > 0 else None})
print(json.dumps({'tcp_bulk': results}))
