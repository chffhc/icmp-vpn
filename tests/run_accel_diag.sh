#!/bin/bash
# Diagnostic variants at fixed RTT/loss (isolated Docker; Linux client, not Android).
set -u
cd "$(dirname "$0")/.."
RTT=${RTT:-2000}; LOSS=${LOSS:-0}
out=${OUT_DIR:-build/accel-diag}; mkdir -p "$out"
SA='serve --key-file /run/icmpvpn/key --tun icmpvpn0 --listen 0.0.0.0'
run() { # name binary queue-limit extra-args...
  local name=$1 bin=$2 q=$3; shift 3
  local f="$out/$name-rtt$RTT-loss$LOSS.json"
  [ -s "$f" ] && return
  IVPN_SS_SAMPLE=1 /usr/bin/perl -e 'alarm 500; exec @ARGV' python3 tests/run_linux_e2e.py \
    --image icmp-vpn-highlatency:local --binary "$bin" --server-args "$SA --queue-limit $q" \
    --java-controller --rtt-ms "$RTT" --loss-pct "$LOSS" "$@" \
    --check tcp_bulk_check.py --check-args "--sizes 131072,1048576,4194304 --deadline 120" \
    --check-timeout 420 --output "$f" > "$out/$name-rtt$RTT-loss$LOSS.log" 2>&1
  echo "$name rc=$?"
}
B=server/build/icmpvpn-linux-arm64-tcpaccel
for v in ${VARIANTS:-direct-q4096 accel64-q4096 accel1024-pace-q4096 accel4096-pace-q4096}; do
  case $v in
    direct-q4096) run $v $B 4096 ;;
    accel64-q4096) run $v $B 4096 --tcpaccel --tcpaccel-initcwnd 64 ;;
    accel1024-pace-q4096) run $v $B 4096 --tcpaccel --tcpaccel-initcwnd 1024 --tcpaccel-extra "--client-pacing 2600000 --client-sndbuf 16777216" --client-initrwnd 1024 ;;
    accel4096-pace-q4096) run $v $B 4096 --tcpaccel --tcpaccel-initcwnd 4096 --tcpaccel-extra "--client-pacing 2600000 --client-sndbuf 16777216" --client-initrwnd 4096 ;;
    direct-rmemA) run $v $B 4096 --client-rmem "4096 1048576 2097152" ;;
    accel4096-pace-rmemA) run $v $B 4096 --tcpaccel --tcpaccel-initcwnd 4096 --tcpaccel-extra "--client-pacing 2600000 --client-sndbuf 16777216" --client-initrwnd 4096 --client-rmem "4096 1048576 2097152" ;;
    direct-rmemB) run $v $B 4096 --client-rmem "4096 8388608 16777216" ;;
    accel4096-pace-rmemB) run $v $B 4096 --tcpaccel --tcpaccel-initcwnd 4096 --tcpaccel-extra "--client-pacing 2600000 --client-sndbuf 16777216" --client-initrwnd 4096 --client-rmem "4096 8388608 16777216" ;;
    accelbbr4096-pace-rmemB) run $v $B 4096 --tcpaccel --tcpaccel-cc bbr --tcpaccel-initcwnd 4096 --tcpaccel-extra "--client-pacing 2600000 --client-sndbuf 16777216" --client-initrwnd 4096 --client-rmem "4096 8388608 16777216" ;;
    accel1024-pace-q256) run $v $B 256 --tcpaccel --tcpaccel-initcwnd 1024 --tcpaccel-extra "--client-pacing 2600000 --client-sndbuf 16777216" --client-initrwnd 1024 ;;
  esac
done
OUT=$out python3 - <<'EOF'
import json,glob,os,re
for p in sorted(glob.glob(os.environ['OUT']+'/*.json')):
    d=json.load(open(p)); tr=[l for l in d['client_worker_log'].splitlines() if l.startswith('TRACE')]
    data=[int(re.search(r' data=(\d+)',l).group(1)) for l in tr]
    print(os.path.basename(p), [(r['size'],r['total_s'],r['avg_mbps']) for r in d['tcp_bulk']], 'peak_data_pps=%s'%max(data or [0]))
EOF
