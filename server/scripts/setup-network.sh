#!/usr/bin/env bash
# Explicit, interface-scoped deployment only; never called by the server.
set -euo pipefail
TUN=icmpvpn0
FWD=IVP1_FORWARD
NAT=IVP1_NAT
STATE=/run/icmpvpn-setup.state
usage() { printf '%s\n' 'Usage: setup-network.sh up <egress-interface> | down' >&2; exit 2; }
[[ $(id -u) == 0 ]] || { printf '%s\n' 'Root is required for this explicit network setup.' >&2; exit 1; }
command -v ip >/dev/null
command -v iptables >/dev/null
[[ $# -ge 1 ]] || usage
ipt() { iptables -w 5 "$@"; }

if [[ $1 == down ]]; then
  [[ $# == 1 ]] || usage
  [[ -f $STATE && ! -L $STATE ]] || { printf '%s\n' 'No owned setup state; refusing guessed rollback.' >&2; exit 1; }
  read -r WAN < "$STATE"
  [[ $WAN =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]] || { printf '%s\n' 'Invalid setup state.' >&2; exit 1; }
  # Stop the server first. Delete only exact hooks and owned dedicated chains.
  # Existence checks make a partial rollback retryable without guessed names.
  if ipt -C FORWARD -i "$TUN" -j "$FWD" 2>/dev/null; then ipt -D FORWARD -i "$TUN" -j "$FWD"; fi
  if ipt -C FORWARD -o "$TUN" -j "$FWD" 2>/dev/null; then ipt -D FORWARD -o "$TUN" -j "$FWD"; fi
  if ipt -t nat -C POSTROUTING -s 10.77.0.2/32 -o "$WAN" -j "$NAT" 2>/dev/null; then ipt -t nat -D POSTROUTING -s 10.77.0.2/32 -o "$WAN" -j "$NAT"; fi
  if ipt -S "$FWD" >/dev/null 2>&1; then ipt -F "$FWD"; ipt -X "$FWD"; fi
  if ipt -t nat -S "$NAT" >/dev/null 2>&1; then ipt -t nat -F "$NAT"; ipt -t nat -X "$NAT"; fi
  if ip link show dev "$TUN" >/dev/null 2>&1; then ip tuntap del dev "$TUN" mode tun; fi
  rm -- "$STATE"
  printf '%s\n' 'Owned TUN/firewall setup removed; sysctls were not changed.'
  exit 0
fi
[[ $1 == up && $# == 2 ]] || usage
WAN=$2
[[ $WAN =~ ^[a-zA-Z0-9_.:-]{1,15}$ && $WAN != "$TUN" ]] || usage
ip link show dev "$WAN" >/dev/null
[[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] || { printf '%s\n' 'IPv4 forwarding is disabled. Review docs/server.md and explicitly enable it before setup.' >&2; exit 1; }
[[ ! -e $STATE && ! -L $STATE ]] || { printf '%s\n' 'Setup state exists; refusing duplicate setup.' >&2; exit 1; }
if ip link show dev "$TUN" >/dev/null 2>&1 || ipt -S "$FWD" >/dev/null 2>&1 || ipt -t nat -S "$NAT" >/dev/null 2>&1; then
  printf '%s\n' 'TUN or dedicated chain exists; refusing to adopt/overwrite it.' >&2; exit 1
fi
umask 077
# Exclusive ownership marker. /run must be trusted/root-owned.
(set -o noclobber; printf '%s\n' "$WAN" > "$STATE")
created_tun=0
created_fwd=0
created_nat=0
hook_in=0
hook_out=0
hook_nat=0
rollback_failed_up() {
  local rc=$?
  trap - EXIT
  if [[ $rc != 0 ]]; then
    set +e
    rollback_ok=1
    [[ $hook_nat == 0 ]] || ipt -t nat -D POSTROUTING -s 10.77.0.2/32 -o "$WAN" -j "$NAT" || rollback_ok=0
    [[ $hook_out == 0 ]] || ipt -D FORWARD -o "$TUN" -j "$FWD" || rollback_ok=0
    [[ $hook_in == 0 ]] || ipt -D FORWARD -i "$TUN" -j "$FWD" || rollback_ok=0
    [[ $created_nat == 0 ]] || { ipt -t nat -F "$NAT" && ipt -t nat -X "$NAT"; } || rollback_ok=0
    [[ $created_fwd == 0 ]] || { ipt -F "$FWD" && ipt -X "$FWD"; } || rollback_ok=0
    [[ $created_tun == 0 ]] || ip tuntap del dev "$TUN" mode tun || rollback_ok=0
    if [[ $rollback_ok == 1 ]]; then rm -- "$STATE"; else printf '%s\n' 'Rollback incomplete: ownership marker retained; inspect errors and retry down.' >&2; fi
    printf '%s\n' 'Setup failed; rollback attempted. Inspect any rollback errors above.' >&2
  fi
  exit "$rc"
}
trap rollback_failed_up EXIT
ip tuntap add dev "$TUN" mode tun
created_tun=1
ip addr add 10.77.0.1/24 dev "$TUN"
ip link set dev "$TUN" mtu 1200 up
ipt -N "$FWD"
created_fwd=1
ipt -A "$FWD" -i "$TUN" -s 10.77.0.2/32 -o "$WAN" -j ACCEPT
ipt -A "$FWD" -o "$TUN" -d 10.77.0.2/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt -A "$FWD" -j DROP
ipt -t nat -N "$NAT"
created_nat=1
ipt -t nat -A "$NAT" -j MASQUERADE
ipt -I FORWARD 1 -i "$TUN" -j "$FWD"
hook_in=1
ipt -I FORWARD 1 -o "$TUN" -j "$FWD"
hook_out=1
ipt -t nat -A POSTROUTING -s 10.77.0.2/32 -o "$WAN" -j "$NAT"
hook_nat=1
printf '%s\n' 'Owned TUN/NAT forwarding rules installed. Review iptables rules and outer ICMP ingress separately.'
