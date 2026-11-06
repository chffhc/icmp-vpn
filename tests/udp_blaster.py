"""TEMPORARY server-side test source. Binds ONLY to the tunnel address 10.77.0.1.

- b'GO' + (count,size,rate,run): sends `count` UDP datagrams of `size` bytes back
  to the requester at `rate` packets/s from a background thread (bulk download).
- b'PG' + anything (<=64 bytes): echoed back immediately (latency probe).
- b'STOP' from 10.77.0.1 itself: exit.
Each run id is served once (retransmitted GO requests are ignored).
"""
import socket
import struct
import threading
import time

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
s.bind(('10.77.0.1', 47000))
served = set()


def blast(peer, count, size, rate, run):
    pad = b'\0' * (size - 8)
    start = time.monotonic()
    for i in range(count):
        delay = start + i / rate - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        s.sendto(struct.pack('!iI', run, i) + pad, peer)
    print('SERVED run=%d count=%d size=%d rate=%d in %.2fs' % (run, count, size, rate, time.monotonic() - start), flush=True)


print('BLASTER_READY 10.77.0.1:47000', flush=True)
while True:
    data, peer = s.recvfrom(2048)
    if peer[0] == '10.77.0.1' and data == b'STOP':
        print('BLASTER_STOPPED', flush=True)
        break
    if peer[0] != '10.77.0.2':
        continue
    if data[:2] == b'PG' and len(data) <= 64:
        s.sendto(data, peer)
        continue
    if len(data) != 18 or data[:2] != b'GO':
        continue
    count, size, rate, run = struct.unpack('!IIIi', data[2:])
    if run in served or not (1 <= count <= 40000 and 16 <= size <= 1150 and 1 <= rate <= 8000):
        continue
    served.add(run)
    threading.Thread(target=blast, args=(peer, count, size, rate, run), daemon=True).start()
