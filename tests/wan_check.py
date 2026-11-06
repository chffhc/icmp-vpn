"""Real-Internet checks through the tunnel (run as UID 65534 inside the client container)."""
import argparse
import hashlib
import json
import socket
import ssl
import struct
import time
import urllib.request


def dns_a(server, name):
    q = struct.pack('!HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
    q += b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0' + struct.pack('!HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(8)
    s.sendto(q, (server, 53))
    r, _ = s.recvfrom(1500)
    s.close()
    assert r[:2] == q[:2] and struct.unpack('!H', r[6:8])[0] > 0, 'no DNS answer'
    return struct.unpack('!H', r[6:8])[0]


def fetch(url, limit):
    req = urllib.request.Request(url, headers={'User-Agent': 'icmpvpn-wan-test'})
    t = time.monotonic()
    with urllib.request.urlopen(req, timeout=60, context=ssl.create_default_context()) as r:
        body = r.read(limit)
    return body, time.monotonic() - t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--expect-exit', required=True)
    a = ap.parse_args()
    out = {'evidence': 'real_internet_via_icmp_tunnel_linux_client_not_android'}
    out['dns_udp_223.5.5.5_answers'] = dns_a('223.5.5.5', 'www.baidu.com')
    out['dns_udp_1.1.1.1_answers'] = dns_a('1.1.1.1', 'example.com')
    body, _ = fetch('https://ifconfig.me/ip', 100)
    out['https_exit_ip'] = body.decode().strip()
    assert out['https_exit_ip'] == a.expect_exit, 'exit IP mismatch: ' + out['https_exit_ip']
    body, sec = fetch('https://speed.cloudflare.com/__down?bytes=2000000', 2000000)
    out['https_download_bytes'] = len(body)
    out['https_download_seconds'] = round(sec, 2)
    out['https_download_mbit_s'] = round(len(body) * 8 / sec / 1e6, 2)
    out['download_sha256_prefix'] = hashlib.sha256(body).hexdigest()[:16]
    assert len(body) == 2000000, 'short download'
    out['status'] = 'PASS'
    print(json.dumps(out, indent=2), flush=True)


if __name__ == '__main__':
    main()
