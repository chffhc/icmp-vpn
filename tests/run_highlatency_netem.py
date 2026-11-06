#!/usr/bin/env python3
"""Isolated real Linux/ICMP/AEAD/TUN with tc netem (not mock / not Android).
No host/VPS firewall/sysctl changes, private ephemeral random test PSK.
Executes the exact baseline03 and candidate Java FlowControl via JVM.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
JAVA='/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home/bin'

def run(*cmd, timeout=120):
    p=subprocess.run(list(cmd),text=True,capture_output=True,timeout=timeout)
    if p.returncode:
        raise RuntimeError('command failed rc=%d: %s\n%s' % (p.returncode,' '.join(cmd[:4]),(p.stderr or p.stdout)[-1500:]))
    return p.stdout.strip()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',default='build/highlatency-netem.json')
    ap.add_argument('--cases',default='baseline:2000:0:0,candidate:500:0:0,candidate:1000:0:0,candidate:2000:0:0,candidate:2000:200:0.5')
    a=ap.parse_args();suffix=uuid.uuid4().hex[:10]
    network='ivpn-lat-'+suffix;server='ivpn-lats-'+suffix;client='ivpn-latc-'+suffix
    containers=[];processes=[];results=[]
    def ex(name,*cmd,timeout=120):return run('docker','exec',name,*cmd,timeout=timeout)
    with tempfile.TemporaryDirectory(prefix='ivpn-netem-',dir=os.environ['TMPDIR']) as td:
        td=Path(td);key=td/'key';key.write_bytes(secrets.token_bytes(32));key.chmod(0o600)
        for name,path in [('baseline',ROOT/'tests/baseline03/FlowControl.java'),('candidate',ROOT/'android/app/src/main/java/org/nousresearch/icmpvpn/FlowControl.java')]:
            run(JAVA+'/javac','--release','17','-d',str(td/name),str(path),str(ROOT/'tests/java/FlowControlHarness.java'))
        try:
            run('docker','network','create',network)
            for name in [server,client]:
                run('docker','run','-d','--name',name,'--network',network,'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--cap-add','CHOWN','--device','/dev/net/tun','--sysctl','net.ipv4.ping_group_range=0 2147483647','--mount',f'type=bind,src={ROOT},dst=/work,readonly','--mount',f'type=bind,src={td},dst=/fixtures,readonly','icmp-vpn-highlatency:local','sleep','infinity')
                containers.append(name)
                ex(name,'mkdir','-m','0700','/run/icmpvpn');ex(name,'cp','/fixtures/key','/run/icmpvpn/key');ex(name,'chown','0:0','/run/icmpvpn/key');ex(name,'chmod','0600','/run/icmpvpn/key')
            ip=json.loads(run('docker','inspect',server))[0]['NetworkSettings']['Networks'][network]['IPAddress']
            ex(server,'ip','tuntap','add','dev','icmpvpn0','mode','tun');ex(server,'ip','addr','add','10.77.0.1/24','dev','icmpvpn0');ex(server,'ip','link','set','icmpvpn0','mtu','1200','up')
            for name,cmd in [(server,['/work/build/icmpvpn-linux-arm64-highlatency','serve','--key-file','/run/icmpvpn/key']),(server,['python','/work/tests/udp_blaster.py'])]:
                fh=open(td/('log-'+str(len(processes))),'w');p=subprocess.Popen(['docker','exec',name,*cmd],stdout=fh,stderr=subprocess.STDOUT);processes.append((p,fh))
            ex(server,'sh','-c','test -e /run/icmpvpn/key.sessions || sleep 1')
            for spec in a.cases.split(','):
                name,rtt,jitter,loss=spec.split(':');rtt=int(rtt);jitter=int(jitter);loss=float(loss)
                for container in [server,client]:
                    # ICMP only: no delay applied to the UDP/TUN test source itself.
                    ex(container,'tc','qdisc','replace','dev','eth0','root','handle','1:','prio','bands','3')
                    ex(container,'tc','filter','add','dev','eth0','protocol','ip','parent','1:','prio','1','u32','match','ip','protocol','1','0xff','flowid','1:3')
                    cmd=['tc','qdisc','replace','dev','eth0','parent','1:3','handle','30:','netem','limit','20000','delay',f'{rtt//2}ms']
                    if jitter:cmd += [f'{jitter}ms','distribution','normal']
                    if loss:cmd += ['loss',f'{loss}%']
                    ex(container,*cmd)
                # source dedup keyed by random run id; previous session CLOSE arrives
                # within 2.5s (probe waits before exit), so next HELLO has a fresh SID.
                out=ex(client,'env','IVPN_JAVA=/usr/bin/java',f'IVPN_JAVA_CLASSES=/fixtures/{name}','python','/work/tests/highlatency_probe.py','--server',ip,'--key-file','/run/icmpvpn/key',timeout=90)
                d=json.loads(out);d.update(variant=name,injected_rtt_ms=rtt,one_way_jitter_ms=jitter,one_way_loss_pct=loss)
                d['netem_evidence']=ex(server,'tc','-s','qdisc','show','dev','eth0')
                results.append(d)
                output=ROOT/a.output;output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps({'results':results,'android_runtime_verified':False},indent=2)+'\n')
                print(json.dumps({k:v for k,v in d.items() if k!='netem_evidence'}),flush=True)
        finally:
            for container in reversed(containers):subprocess.run(['docker','rm','-f',container],capture_output=True,timeout=30)
            subprocess.run(['docker','network','rm',network],capture_output=True,timeout=30)
            for p,fh in processes:
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=10)
                fh.close()

if __name__=='__main__':main()
