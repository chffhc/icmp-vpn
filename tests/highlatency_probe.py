"""Real Linux ICMP/AEAD/TUN loaded UDP with the shipping Java controller.
Runs only in disposable containers; tc netem supplies actual packet delay.
This is not Android network/runtime or aircraft-network evidence.
"""
import argparse
import json
import time
from host_wan_probe import Tunnel
from throughput_probe import run, send_seq, recv_seq

ap=argparse.ArgumentParser()
ap.add_argument('--server', required=True)
ap.add_argument('--key-file', required=True)
ap.add_argument('--rate', type=int, default=2000)
ap.add_argument('--count', type=int, default=40000)
a=ap.parse_args()
with open(a.key_file,'rb') as fh:
    t=Tunnel(a.server,fh.read())
t.sock.setsockopt(__import__('socket').SOL_SOCKET,__import__('socket').SO_RCVBUF,4<<20)
try:
    start=time.monotonic();deadline=start+20;seq=0;next_send=0
    while time.monotonic()<deadline:
        now=time.monotonic()
        if now>=next_send:
            seq+=1;send_seq(t,seq,2);next_send=now+0.1
        r=recv_seq(t)
        if r and r[1]==2:
            break
    else:
        raise RuntimeError('HELLO failed')
    handshake=time.monotonic()-start
    result=run(t,'window',a.count,1100,a.rate,50,'java')
    result['handshake_seconds']=round(handshake,3)
    result['evidence']='real_linux_ping_socket_aead_tun_netem_exact_java_controller_not_android'
    print(json.dumps(result),flush=True)
finally:
    send_seq(t,60000,3);time.sleep(2.5);t.sock.close()
