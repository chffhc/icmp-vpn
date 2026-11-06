#!/bin/bash
# cubic vs BBR on the split-TCP proxy, repeated, incl. a 32 MB transfer so the
# congestion controller (not initcwnd) decides the result. Isolated Lima VM.
# Linux test client, not Android. Proxy pacing matches deployable value (~27 Mbps).
set -u
cd "$(dirname "$0")/.."
export DOCKER_CONTEXT=${DOCKER_CONTEXT:-lima-ivpn-bbr}
out=${OUT_DIR:-build/accel-cc}; mkdir -p "$out"
SA='serve --key-file /run/icmpvpn/key --tun icmpvpn0 --listen 0.0.0.0 --queue-limit '${QUEUE_LIMIT:-4096}
B=server/build/icmpvpn-linux-arm64-tcpaccel
EXTRA="--client-pacing 3400000 --client-sndbuf 16777216 --conn-log ${SYNRTO_ARGS:-}"
for rep in ${REPS:-1 2 3}; do
  for loss in ${LOSSES:-0 1}; do
    for cc in ${CCS:-cubic bbr}; do
      f="$out/$cc-loss$loss-r$rep.json"
      [ -s "$f" ] && continue
      IVPN_SS_SAMPLE=1 /usr/bin/perl -e 'alarm 900; exec @ARGV' python3 tests/run_linux_e2e.py \
        --image icmp-vpn-highlatency:local --binary "$B" --server-args "$SA" \
        --java-controller --rtt-ms 2000 --loss-pct "$loss" \
        --tcpaccel --tcpaccel-cc "$cc" --tcpaccel-initcwnd 4096 --tcpaccel-extra "$EXTRA" \
        --client-initrwnd 4096 --client-rmem "4096 8388608 16777216" \
        --check tcp_bulk_check.py --check-args "--sizes 131072,1048576,4194304,33554432 --deadline 240" \
        --check-timeout 700 --output "$f" > "$out/$cc-loss$loss-r$rep.log" 2>&1
      echo "$cc loss=$loss rep=$rep rc=$?"
    done
  done
done
