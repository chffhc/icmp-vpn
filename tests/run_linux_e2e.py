#!/usr/bin/env python3
"""Isolated Docker E2E runner. No host/remote firewall changes.
The client worker is Linux, NOT an Android runtime acceptance test.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--image', default='icmp-vpn-integration:local')
    ap.add_argument('--rtt-ms', type=int, default=0)
    ap.add_argument('--java-controller', action='store_true')
    ap.add_argument('--loss-pct', type=float, default=0.0)
    ap.add_argument('--jitter-ms', type=int, default=0)
    ap.add_argument('--check', default='traffic_check.py')
    ap.add_argument('--check-args', default='')
    ap.add_argument('--check-timeout', type=int, default=100)
    ap.add_argument('--tcpaccel', action='store_true', help='start split-TCP proxy + owned redirect on server')
    ap.add_argument('--tcpaccel-cc', default='cubic')
    ap.add_argument('--tcpaccel-initcwnd', type=int, default=10)
    ap.add_argument('--tcpaccel-admit-queue', type=int, default=0, help='connect-before-accept NFQUEUE number (0=off)')
    ap.add_argument('--tcpaccel-extra', default='', help='extra tcpaccel flags, e.g. --client-pacing N')
    ap.add_argument('--client-rmem', default='', help='DIAGNOSTIC: client net.ipv4.tcp_rmem "min default max"')
    ap.add_argument('--client-initrwnd', type=int, default=0, help='DIAGNOSTIC: emulate a receiver with a large initial window')
    ap.add_argument('--binary', required=True, help='Project-relative Linux binary path')
    ap.add_argument('--server-args', default='serve --key-file /run/icmpvpn/key --tun icmpvpn0 --listen 0.0.0.0')
    ap.add_argument('--output', default=str(ROOT/'dist'/'linux-e2e.json'))
    args = ap.parse_args()
    if not 0 <= args.rtt_ms <= 3000: raise SystemExit('RTT outside isolated-test bounds')
    binary = ROOT / args.binary
    if not binary.is_file():
        raise SystemExit('Build server binary before this test: ' + str(binary))
    suffix = uuid.uuid4().hex[:10]
    network = 'ivpn-test-' + suffix
    names = {k: 'ivpn-' + k + '-' + suffix for k in ['server', 'client', 'target']}
    containers, processes = [], []
    def run(*cmd, **kw):
        return subprocess.run(list(cmd), check=True, text=True, capture_output=True, timeout=kw.pop('timeout', 180), **kw).stdout.strip()
    def ex(which, *cmd):
        return run('docker', 'exec', names[which], *cmd)
    def get_ip(which):
        value = json.loads(run('docker', 'inspect', names[which]))
        return value[0]['NetworkSettings']['Networks'][network]['IPAddress']
    def launch(which, cmd, path):
        fh = open(path, 'w')
        proc = subprocess.Popen(['docker', 'exec', names[which], *cmd], stdout=fh, stderr=subprocess.STDOUT)
        processes.append((proc, fh))
        return proc
    with tempfile.TemporaryDirectory(prefix='icmp-vpn-e2e-', dir=os.environ.get('TMPDIR')) as td:
        td = Path(td)
        keypath = td/'testkey'
        keypath.write_bytes(secrets.token_bytes(32))
        keypath.chmod(0o600)
        logs = {k: td/(k+'.log') for k in names}
        try:
            run('docker', 'network', 'create', network)
            for which in names:
                cmd = ['docker', 'run', '-d', '--name', names[which], '--network', network, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--mount', f'type=bind,src={ROOT},dst=/work,readonly']
                if which != 'target':
                    # CHOWN/FOWNER only so the test can root-own the copied 0600 key file.
                    cmd += ['--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW', '--cap-add', 'CHOWN', '--cap-add', 'FOWNER', '--device', '/dev/net/tun']
                if which == 'server':
                    cmd += ['--sysctl', 'net.ipv4.ip_forward=1']
                    if args.tcpaccel:  # cgroup sock_ops BPF for --syn-rto
                        cmd += ['--cap-add', 'BPF']
                if which == 'client':
                    cmd += ['--cap-add', 'SETUID', '--cap-add', 'SETGID', '--sysctl', 'net.ipv4.ping_group_range=0 65535']  # covers worker gid 65534; kernel 7.0 rejects 2^31-1
                    if args.client_rmem:  # /proc/sys is read-only inside; set at create time
                        cmd += ['--sysctl', 'net.ipv4.tcp_rmem='+args.client_rmem]
                # target binds fixture DNS port53 only (kernel may allow low ports).
                if which == 'target':
                    cmd += ['--cap-add', 'NET_BIND_SERVICE']
                    if os.environ.get('IVPN_CAPTURE'):
                        cmd += ['--cap-add', 'NET_RAW', '--cap-add', 'NET_ADMIN']
                cmd += [args.image, 'sleep', 'infinity']
                run(*cmd)
                containers.append(names[which])
            for which in ['server', 'client']:
                ex(which, 'mkdir', '-m', '0700', '/run/icmpvpn')
                run('docker', 'cp', str(keypath), names[which]+':/run/icmpvpn/key')
                ex(which, 'chown', '0:0', '/run/icmpvpn/key')
                ex(which, 'chmod', '0600', '/run/icmpvpn/key')
            server_ip, target_ip = get_ip('server'), get_ip('target')
            ex('server', 'ip', 'tuntap', 'add', 'dev', 'icmpvpn0', 'mode', 'tun')
            ex('server', 'ip', 'addr', 'add', '10.77.0.1/24', 'dev', 'icmpvpn0')
            ex('server', 'ip', 'link', 'set', 'icmpvpn0', 'mtu', '1200', 'up')
            ex('server', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.77.0.2/32', '-o', 'eth0', '-j', 'MASQUERADE')
            ex('server', 'iptables', '-A', 'FORWARD', '-i', 'icmpvpn0', '-o', 'eth0', '-s', '10.77.0.2/32', '-j', 'ACCEPT')
            ex('server', 'iptables', '-A', 'FORWARD', '-i', 'eth0', '-o', 'icmpvpn0', '-d', '10.77.0.2/32', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT')
            if args.java_controller:
                javac='/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home/bin/javac'
                classes=td/'classes'
                run(javac,'--release','17','-d',str(classes),str(ROOT/'android/app/src/main/java/org/nousresearch/icmpvpn/FlowControl.java'),str(ROOT/'tests/java/FlowControlHarness.java'))
                run('docker','cp',str(classes),names['client']+':/run/java-classes')
                ex('client','chmod','-R','a+rX','/run/java-classes')
            if args.rtt_ms:
                for which in ['server','client']:
                    ex(which,'tc','qdisc','add','dev','eth0','root','handle','1:','prio','bands','3')
                    ex(which,'tc','filter','add','dev','eth0','protocol','ip','parent','1:','prio','1','u32','match','ip','protocol','1','0xff','flowid','1:3')
                    netem=['tc','qdisc','add','dev','eth0','parent','1:3','netem','limit','20000','delay',f'{args.rtt_ms//2}ms']
                    if args.jitter_ms: netem += [f'{args.jitter_ms}ms','distribution','normal']
                    if args.loss_pct: netem += ['loss',f'{args.loss_pct}%']
                    ex(which,*netem)
            srv = launch('server', ['/work/'+args.binary, *shlex.split(args.server_args)], logs['server'])
            target = launch('target', ['python', '/work/tests/target.py'], logs['target'])
            if args.tcpaccel:
                net_cidr = json.loads(run('docker','network','inspect',network))[0]['IPAM']['Config'][0]['Subnet']
                aq = ['env','ADMIT_QUEUE='+str(args.tcpaccel_admit_queue)] if args.tcpaccel_admit_queue else []
                ex('server',*aq,'/work/server/scripts/tcpaccel-network.sh','up',str(args.tcpaccel_initcwnd),net_cidr)
                logs['tcpaccel'] = td/'tcpaccel.log'
                accel = launch('server', ['/work/'+args.binary,'tcpaccel','--congestion',args.tcpaccel_cc,'--allow-dst',net_cidr,*(['--admit-queue',str(args.tcpaccel_admit_queue)] if args.tcpaccel_admit_queue else []),*shlex.split(args.tcpaccel_extra)], logs['tcpaccel'])
                deadline = time.monotonic() + 20
                while 'tcpaccel listening' not in logs['tcpaccel'].read_text():
                    if accel.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('tcpaccel failed to start')
                    time.sleep(0.1)
            client_cmd=['python','/work/tests/linux_client.py','--server',server_ip,'--target',target_ip,'--key-file','/run/icmpvpn/key']
            if args.java_controller: client_cmd=['env','IVPN_JAVA=/usr/bin/java','IVPN_JAVA_CLASSES=/run/java-classes',*client_cmd,'--java-controller']
            client = launch('client', client_cmd, logs['client'])
            deadline = time.monotonic() + 60
            while 'READY encrypted ICMP' not in logs['client'].read_text():
                if any(p.poll() is not None for p in [srv, target, client]) or time.monotonic() > deadline:
                    raise RuntimeError('Handshake/process readiness failed')
                time.sleep(0.1)
            if args.tcpaccel and os.environ.get('IVPN_SS_SAMPLE'):
                logs['ss'] = td/'ss.log'
                launch('server', ['sh','-c','for i in $(seq 600); do echo T=$i; ss -tinm state established "( sport = :7011 )"; sleep 1; done'], logs['ss'])
            if args.check == 'admit_check.py':
                # Blackhole = silent drop on the server for both proxy dials (OUTPUT)
                # and direct forwarding (FORWARD); route it through the tunnel.
                bh = '.'.join(target_ip.split('.')[:3] + ['250'])
                for chain in ['OUTPUT', 'FORWARD']:
                    ex('server', 'iptables', '-I', chain, '1', '-d', bh, '-j', 'DROP')
                ex('client', 'ip', 'route', 'replace', bh + '/32', 'dev', 'clienttun0', 'src', '10.77.0.2')
            if args.client_initrwnd:
                ex('client','ip','route','change','default','dev','clienttun0','src','10.77.0.2','initrwnd',str(args.client_initrwnd))
                ex('client','ip','route','change',target_ip+'/32','dev','clienttun0','src','10.77.0.2','initrwnd',str(args.client_initrwnd))
            if os.environ.get('IVPN_CAPTURE'):
                # Diagnostic only: per-hop packet captures, printed on failure.
                for which, iface in [('server', 'icmpvpn0'), ('server', 'eth0'), ('target', 'eth0'), ('client', 'clienttun0')]:
                    path = td/('cap-'+which+'-'+iface+'.log')
                    logs['cap-'+which+'-'+iface] = path
                    launch(which, ['timeout', '40', 'tcpdump', '-Z', 'root', '-lnni', iface, 'not', 'icmp'], path)
                time.sleep(1.5)
                print('SERVER_STATE', ex('server', 'sh', '-c', 'ip -br addr; ip route; sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.icmpvpn0.rp_filter; iptables -S; iptables -t nat -S'), flush=True)
            checks = subprocess.run(['docker', 'exec', '--user', '65534', names['client'], 'python', '/work/tests/'+args.check, '--server', server_ip, '--target', target_ip, *shlex.split(args.check_args)], capture_output=True, text=True, timeout=args.check_timeout)
            if checks.returncode:
                raise RuntimeError('Traffic check failed: '+checks.stdout+checks.stderr)
            result = json.loads(checks.stdout)
            result['client_worker_log'] = logs['client'].read_text()
            result['server_log'] = logs['server'].read_text()
            result['route_evidence'] = ex('client', 'ip', 'route', 'get', target_ip)
            result['direct_eth0_reject'] = ex('client', 'iptables', '-S', 'OUTPUT')
            result['android_runtime_verified'] = False
            result['injected_rtt_ms'] = args.rtt_ms
            result['client_routes'] = ex('client','ip','route')
            result['server_netstat'] = ex('server','cat','/proc/net/netstat')
            result['client_tcp_rmem'] = ex('client','sysctl','-n','net.ipv4.tcp_rmem')
            result['tcpaccel'] = {'enabled': args.tcpaccel, 'cc': args.tcpaccel_cc, 'initcwnd': args.tcpaccel_initcwnd}
            if args.tcpaccel:
                result['tcpaccel']['nat'] = ex('server','iptables','-t','nat','-S','IVP1_TCPACCEL')
                if args.tcpaccel_admit_queue: result['tcpaccel']['mangle'] = ex('server','iptables','-t','mangle','-L','IVP1_TCPADMIT','-v','-n')
                result['tcpaccel']['route'] = ex('server','ip','route','show','10.77.0.2/32')
                result['tcpaccel']['proxied_sockets'] = ex('server','sh','-c','ss -tin state established "( sport = :7011 )" | head -40')
                subprocess.run(['docker','exec',names['server'],'pkill','-TERM','-f','icmpvpn-linux-arm64-tcpaccel tcpaccel'],capture_output=True,timeout=30)
                time.sleep(1)
                result['tcpaccel']['log'] = logs['tcpaccel'].read_text()
                if 'ss' in logs: result['tcpaccel']['ss_samples'] = logs['ss'].read_text()
                if 'tcpaccel final accepted=0 ' in result['tcpaccel']['log'] or 'tcpaccel final' not in result['tcpaccel']['log']:
                    raise RuntimeError('tcpaccel did not proxy any connection: '+result['tcpaccel']['log'])
            result['loss_pct_each_way'] = args.loss_pct
            result['jitter_ms'] = args.jitter_ms
            result['client_tcp'] = ex('client','sh','-c','cat /proc/sys/net/ipv4/tcp_congestion_control /proc/sys/net/ipv4/tcp_rmem')
            result['target_tcp'] = ex('target','sh','-c','cat /proc/sys/net/ipv4/tcp_congestion_control /proc/sys/net/ipv4/tcp_wmem')
            result['exact_java_controller'] = args.java_controller
            if args.rtt_ms: result['netem_evidence']=ex('server','tc','-s','qdisc','show','dev','eth0')
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, indent=2)+'\n')
            print(json.dumps(result, indent=2))
        except Exception:
            for k, path in logs.items():
                if path.exists():
                    print('\n--- '+k+' ---\n'+path.read_text())
            raise
        finally:
            for name in reversed(containers):
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30)
            subprocess.run(['docker', 'network', 'rm', network], capture_output=True, timeout=30)
            for p, fh in processes:
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=10)
                fh.close()


if __name__ == '__main__':
    main()
