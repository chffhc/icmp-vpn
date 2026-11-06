#!/bin/bash
# Handshake A/B: many short proxied connections at 2 s RTT (+loss), with and
# without the --syn-rto BPF fix. Metric: per-connection cwnd at open (collapse
# to 1 = bug) and SYN-ACK retransmits. Isolated rootful Docker in Lima VM.
set -u
cd "$(dirname "$0")/.."
export DOCKER_CONTEXT=${DOCKER_CONTEXT:-lima-rootful}
out=${OUT_DIR:-build/synrto-ab}; mkdir -p "$out"
N=${N:-60}
SIZES=$(python3 -c "print(','.join(['65536']*$N))")
SA='serve --key-file /run/icmpvpn/key --tun icmpvpn0 --listen 0.0.0.0 --queue-limit 4096'
for loss in ${LOSSES:-1}; do
  for v in ${VARIANTS:-fix nofix}; do
    if [ $v = fix ]; then S="--kernel-hz 1000"; else S="--syn-rto 0"; fi
    f="$out/$v-loss$loss.json"; [ -s "$f" ] && continue
    /usr/bin/perl -e 'alarm 1700; exec @ARGV' python3 tests/run_linux_e2e.py \
      --image icmp-vpn-highlatency:local --binary server/build/icmpvpn-linux-arm64-tcpaccel --server-args "$SA" \
      --java-controller --rtt-ms 2000 --loss-pct "$loss" \
      --tcpaccel --tcpaccel-cc bbr --tcpaccel-initcwnd 4096 \
      --tcpaccel-extra "--client-pacing 3400000 --client-sndbuf 16777216 --conn-log $S" \
      --client-initrwnd 4096 --client-rmem "4096 8388608 16777216" \
      --check tcp_bulk_check.py --check-args "--sizes $SIZES --deadline 60" \
      --check-timeout 1500 --output "$f" > "$out/$v-loss$loss.log" 2>&1
    echo "$v loss=$loss rc=$?"
  done
done
OUT=$out python3 - <<'EOF'
import json,glob,os,re,collections
for p in sorted(glob.glob(os.environ['OUT']+'/*.json')):
    d=json.load(open(p)); log=d['tcpaccel']['log']
    opens=[(int(c),int(r)) for c,r in re.findall(r'conn open dst=\S+ cwnd=(\d+) total_retrans=(\d+)',log)]
    t=[r['total_s'] for r in d['tcp_bulk']]; inc=sum(not r['complete'] for r in d['tcp_bulk'])
    ts=sorted(t)
    print(os.path.basename(p), 'conns',len(opens),'cwnd1',sum(c<10 for c,_ in opens),
          'synack_retx_hist',dict(collections.Counter(r for _,r in opens)),
          'p50 %.2f p90 %.2f max %.2f incomplete %d'%(ts[len(ts)//2],ts[int(len(ts)*.9)],ts[-1],inc))
EOF
