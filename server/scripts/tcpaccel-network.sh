#!/usr/bin/env bash
# Explicit, owned redirection of tunnel-client TCP into the local tcpaccel proxy.
# up <initcwnd> [test-only-allow-cidr...] | down
# Optional env ADMIT_QUEUE=<n>: connect-before-accept. Client SYNs are queued
# (NFQUEUE, fail-open) to the proxy, which dials the destination first; SYNs
# whose dial fails come back with BYPASS_MARK and skip REDIRECT, so the client
# sees the direct path (timeout / RST) exactly as without the proxy.
# Creates only: nat chain IVP1_TCPACCEL, mangle chain IVP1_TCPADMIT (if
# ADMIT_QUEUE), their PREROUTING hooks, one /32 route to the tunnel client with
# initcwnd/initrwnd. Never changes sysctls.
set -euo pipefail
TUN=icmpvpn0
CLIENT=10.77.0.2
CHAIN=IVP1_TCPACCEL
ADMIT=IVP1_TCPADMIT
PORT=7011
BYPASS_MARK=0x10000000
STATE=/run/icmpvpn-tcpaccel.state
RESERVED="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4"
[[ $(id -u) == 0 ]] || { echo 'root required' >&2; exit 1; }
ipt() { iptables -w 5 "$@"; }
usage() { echo 'Usage: [ADMIT_QUEUE=n] tcpaccel-network.sh up <initcwnd 10..4096> [allow-cidr...] | down' >&2; exit 2; }
remove_all() {
  if ipt -t nat -C PREROUTING -i "$TUN" -s "$CLIENT/32" -p tcp -j "$CHAIN" 2>/dev/null; then ipt -t nat -D PREROUTING -i "$TUN" -s "$CLIENT/32" -p tcp -j "$CHAIN"; fi
  if ipt -t mangle -C PREROUTING -i "$TUN" -s "$CLIENT/32" -p tcp -j "$ADMIT" 2>/dev/null; then ipt -t mangle -D PREROUTING -i "$TUN" -s "$CLIENT/32" -p tcp -j "$ADMIT"; fi
  if ipt -t nat -S "$CHAIN" >/dev/null 2>&1; then ipt -t nat -F "$CHAIN"; ipt -t nat -X "$CHAIN"; fi
  if ipt -t mangle -S "$ADMIT" >/dev/null 2>&1; then ipt -t mangle -F "$ADMIT"; ipt -t mangle -X "$ADMIT"; fi
  if ip route show "$CLIENT/32" dev "$TUN" table main | grep -q initcwnd; then ip route del "$CLIENT/32" dev "$TUN"; fi
}
[[ $# -ge 1 ]] || usage
if [[ $1 == down ]]; then
  [[ -f $STATE && ! -L $STATE ]] || { echo 'No owned tcpaccel state; refusing guessed rollback.' >&2; exit 1; }
  remove_all
  rm -- "$STATE"
  echo 'tcpaccel redirection removed; tunnel TCP is forwarded directly again.'
  exit 0
fi
[[ $1 == up && $# -ge 2 ]] || usage
CWND=$2; shift 2
[[ $CWND =~ ^[0-9]+$ ]] && (( CWND >= 10 && CWND <= 4096 )) || usage
for c in "$@"; do [[ $c =~ ^[0-9.]+/[0-9]+$ ]] || usage; done
AQ=${ADMIT_QUEUE:-}
[[ -z $AQ ]] || { [[ $AQ =~ ^[0-9]+$ ]] && (( AQ >= 1 && AQ <= 65535 )); } || usage
ip link show dev "$TUN" >/dev/null
[[ ! -e $STATE && ! -L $STATE ]] || { echo 'tcpaccel state exists; refusing duplicate setup.' >&2; exit 1; }
if ipt -t nat -S "$CHAIN" >/dev/null 2>&1 || ipt -t mangle -S "$ADMIT" >/dev/null 2>&1 || ip route show "$CLIENT/32" | grep -q .; then
  echo 'Chain or client /32 route exists; refusing to adopt it.' >&2; exit 1
fi
umask 077
(set -o noclobber; echo "$CWND ${AQ:-0}" > "$STATE")
trap 'rc=$?; if [[ $rc != 0 ]]; then set +e; remove_all 2>/dev/null; rm -f -- "$STATE"; echo "tcpaccel setup failed; rolled back" >&2; fi' EXIT
ipt -t nat -N "$CHAIN"
# SYNs whose upstream dial failed: forward directly (no proxy).
ipt -t nat -A "$CHAIN" -m mark --mark "$BYPASS_MARK/$BYPASS_MARK" -j RETURN
for c in "$@"; do ipt -t nat -A "$CHAIN" -d "$c" -p tcp -j REDIRECT --to-ports "$PORT"; done
# Never proxy VPS-local or private/reserved destinations (proxy re-checks too).
ipt -t nat -A "$CHAIN" -m addrtype --dst-type LOCAL -j RETURN
for c in $RESERVED; do ipt -t nat -A "$CHAIN" -d "$c" -j RETURN; done
ipt -t nat -A "$CHAIN" -p tcp -j REDIRECT --to-ports "$PORT"
if [[ -n $AQ ]]; then
  ipt -t mangle -N "$ADMIT"
  for c in "$@"; do ipt -t mangle -A "$ADMIT" -d "$c" -p tcp --syn -j NFQUEUE --queue-num "$AQ" --queue-bypass; done
  ipt -t mangle -A "$ADMIT" -m addrtype --dst-type LOCAL -j RETURN
  for c in $RESERVED; do ipt -t mangle -A "$ADMIT" -d "$c" -j RETURN; done
  ipt -t mangle -A "$ADMIT" -p tcp --syn -j NFQUEUE --queue-num "$AQ" --queue-bypass
fi
ip route add "$CLIENT/32" dev "$TUN" src 10.77.0.1 initcwnd "$CWND" initrwnd "$CWND"
ipt -t nat -I PREROUTING 1 -i "$TUN" -s "$CLIENT/32" -p tcp -j "$CHAIN"
[[ -z $AQ ]] || ipt -t mangle -I PREROUTING 1 -i "$TUN" -s "$CLIENT/32" -p tcp -j "$ADMIT"
trap - EXIT
echo "tcpaccel redirection installed (initcwnd=$CWND admit_queue=${AQ:-off})."
