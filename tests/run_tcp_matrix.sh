#!/bin/bash
# Isolated Docker TCP matrix over the real ICMP tunnel (Linux client, not Android).
# Each case: fresh containers, netem on ICMP only (RTT/loss each way).
# VARIANT=direct (default, kernel forwarding) | VARIANT=accel (split-TCP proxy)
# ACCEL_CWND=initcwnd for the proxy->client route, ACCEL_CC=congestion control.
set -u
cd "$(dirname "$0")/.."
VARIANT=${VARIANT:-direct}
ACCEL_CWND=${ACCEL_CWND:-64}
ACCEL_CC=${ACCEL_CC:-cubic}
if [ "$VARIANT" = accel ]; then
  out=build/tcp-matrix-accel-${ACCEL_CC}-cwnd${ACCEL_CWND}
  bin=server/build/icmpvpn-linux-arm64-tcpaccel
  extra=(--tcpaccel --tcpaccel-cc "$ACCEL_CC" --tcpaccel-initcwnd "$ACCEL_CWND")
else
  out=build/tcp-matrix; bin=build/icmpvpn-linux-arm64-highlatency; extra=()
fi
mkdir -p "$out"
for rtt in ${RTTS:-500 1000 2000}; do
  for loss in ${LOSSES:-0 0.5 1}; do
    f="$out/rtt${rtt}-loss${loss}.json"
    [ -s "$f" ] && continue
    /usr/bin/perl -e 'alarm 600; exec @ARGV' python3 tests/run_linux_e2e.py \
      --image icmp-vpn-highlatency:local --binary "$bin" \
      --java-controller --rtt-ms "$rtt" --loss-pct "$loss" "${extra[@]}" \
      --check tcp_bulk_check.py --check-args "--sizes 131072,1048576,4194304 --deadline 120" \
      --check-timeout 420 --output "$f" > "$out/rtt${rtt}-loss${loss}.log" 2>&1
    echo "rtt=$rtt loss=$loss rc=$?"
  done
done
OUT="$out" python3 - <<'EOF'
import json,glob,os
for p in sorted(glob.glob(os.environ['OUT']+'/*.json')):
    d=json.load(open(p))
    for r in d['tcp_bulk']:
        print(d['injected_rtt_ms'],d['loss_pct_each_way'],r['size'],r['complete'],r['received'],r['connect_s'],r['first_byte_s'],r['milestones_s'],r['total_s'],r['avg_mbps'],r['body_mbps'])
EOF
