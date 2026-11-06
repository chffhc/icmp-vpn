"""Controlled HTTP/UDP/DNS fixture endpoints for isolated container tests."""
import hashlib
import http.server
import socket
import struct
import threading

BODY = bytes(range(256)) * 256


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/bytes/'):
            size = int(self.path.split('/')[2])
            if not 0 < size <= 64 << 20:
                self.send_error(400)
                return
            self.send_response(200)
            self.send_header('Content-Length', str(size))
            self.end_headers()
            chunk = bytes(range(256)) * 256
            left = size
            while left:
                n = min(left, len(chunk))
                self.wfile.write(chunk[:n])
                left -= n
            return
        self.send_response(200)
        self.send_header('Content-Length', str(len(BODY)))
        self.send_header('X-Peer', self.client_address[0])
        self.end_headers()
        self.wfile.write(BODY)

    def do_POST(self):
        size = int(self.headers.get('Content-Length', '0'))
        if not 0 <= size <= 1048576:
            self.send_error(400)
            return
        data = self.rfile.read(size)
        answer = hashlib.sha256(data).hexdigest().encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(answer)))
        self.send_header('X-Peer', self.client_address[0])
        self.end_headers()
        self.wfile.write(answer)


def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', 9999))
    while True:
        data, peer = s.recvfrom(2048)
        s.sendto(data, peer)


def dns_fixture():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', 53))
    while True:
        data, peer = s.recvfrom(512)
        if len(data) < 17:
            continue
        # One controlled A question; this is not an upstream DNS claim.
        header = data[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('203.0.113.77')
        s.sendto(header + data[12:] + answer, peer)


if __name__ == '__main__':
    threading.Thread(target=udp_echo, daemon=True).start()
    threading.Thread(target=dns_fixture, daemon=True).start()
    print('TARGET_READY HTTP:8080 UDP:9999 DNS:53', flush=True)
    http.server.ThreadingHTTPServer(('0.0.0.0', 8080), HTTP).serve_forever()
