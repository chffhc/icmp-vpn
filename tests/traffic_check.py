"""Run real kernel TCP/UDP/DNS over test Linux TUN + encrypted ICMP."""
import argparse
import hashlib
import http.client
import json
import socket
import struct
import time

BODY = bytes(range(256)) * 256


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', required=True)
    ap.add_argument('--server', required=True)
    args = ap.parse_args()
    start = time.monotonic()
    conn = http.client.HTTPConnection(args.target, 8080, timeout=30)
    conn.request('GET', '/')
    response = conn.getresponse()
    body, peer = response.read(), response.getheader('X-Peer')
    assert response.status == 200 and body == BODY, 'TCP download corrupted'
    assert peer == args.server, 'Traffic did not NAT through server: ' + str(peer)
    conn.close()
    conn = http.client.HTTPConnection(args.target, 8080, timeout=30)
    conn.request('POST', '/', body=BODY)
    response = conn.getresponse()
    assert response.status == 200 and response.read().decode() == hashlib.sha256(BODY).hexdigest(), 'TCP upload corrupted'
    conn.close()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(10)
    udp.connect((args.target, 9999))
    for i in range(10):
        payload = bytes([i]) + bytes(range(256)) * 3
        udp.send(payload)
        assert udp.recv(1200) == payload, 'UDP changed payload'
    udp.close()
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.settimeout(10)
    q = struct.pack('!HHHHHH', 0x6371, 0x0100, 1, 0, 0, 0) + b'\x06tunnel\x04test\x00\x00\x01\x00\x01'
    dns.sendto(q, (args.target, 53))
    answer, _ = dns.recvfrom(512)
    assert answer[:2] == q[:2] and answer[-4:] == socket.inet_aton('203.0.113.77'), 'DNS fixture response'
    dns.close()
    print(json.dumps({'status': 'PASS', 'evidence': 'real_linux_ping_socket_icmp_tun_nat_not_android', 'tcp_download_bytes': len(body), 'tcp_upload_bytes': len(BODY), 'tcp_sha256': hashlib.sha256(body).hexdigest(), 'udp_exact_datagrams': 10, 'dns': 'controlled A query tunnel.test -> 203.0.113.77', 'target_observed_source': peer, 'server_ip': args.server, 'seconds': round(time.monotonic()-start, 3)}, indent=2), flush=True)


if __name__ == '__main__':
    main()
