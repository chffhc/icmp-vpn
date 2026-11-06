"""Connect-before-accept behaviour through the tunnel (Linux client, not Android).

Unreachable destinations must look like the direct path (refused / timeout /
unreachable), never "connected then reset". Reachable ones must still work.
"""
import argparse
import errno
import json
import socket
import time

ap = argparse.ArgumentParser()
ap.add_argument('--server')
ap.add_argument('--target', required=True)
ap.add_argument('--blackhole', help='address in the allowed net with no host (default: target net .250)')
ap.add_argument('--timeout', type=float, default=25)
a = ap.parse_args()
a.blackhole = a.blackhole or '.'.join(a.target.split('.')[:3] + ['250'])
out = {'evidence': 'linux_client_not_android'}


def attempt(host, port):
    t0 = time.monotonic()
    s = socket.socket()
    s.settimeout(a.timeout)
    try:
        s.connect((host, port))
    except socket.timeout:
        return 'timeout', time.monotonic() - t0
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno)), time.monotonic() - t0
    # connected: does the peer immediately reset us (old proxy behaviour)?
    s.settimeout(3)
    try:
        s.sendall(b'GET /bytes/16 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n')
        d = s.recv(64)
        r = 'connected_data' if d else 'connected_then_eof'
    except ConnectionResetError:
        r = 'connected_then_reset'
    except socket.timeout:
        r = 'connected_no_data'
    finally:
        s.close()
    return r, time.monotonic() - t0


for name, host, port in [('reachable', a.target, 8080), ('closed_port', a.target, 8089),
                         ('blackhole', a.blackhole, 443), ('blackhole_again', a.blackhole, 443),
                         ('reachable_again', a.target, 8080)]:
    r, sec = attempt(host, port)
    out[name] = {'result': r, 'seconds': round(sec, 2)}

ok = (out['reachable']['result'] == 'connected_data'
      and out['reachable_again']['result'] == 'connected_data'
      and out['closed_port']['result'] == 'ECONNREFUSED'
      and not out['blackhole']['result'].startswith('connected')
      and not out['blackhole_again']['result'].startswith('connected'))
out['status'] = 'PASS' if ok else 'FAIL'
print(json.dumps(out, indent=2))
raise SystemExit(0 if ok else 1)
