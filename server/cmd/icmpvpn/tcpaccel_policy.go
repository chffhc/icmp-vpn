package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// Destinations the transparent TCP accelerator must never dial on behalf of the
// tunnel client: VPS-local, loopback, RFC1918/CGNAT (cloud VPC, Docker, Tailscale),
// link-local, multicast and reserved space. The iptables chain RETURNs these
// before REDIRECT; this check is defense in depth inside the proxy itself.
var tcpAccelDenied = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"224.0.0.0/4", "240.0.0.0/4",
)

func mustPrefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}

// destinationAllowed reports whether the proxy may dial dst. allow is a
// test-only override for isolated fixtures on private Docker networks; a
// local address is refused even when allow-listed.
func destinationAllowed(dst netip.Addr, allow []netip.Prefix, local map[netip.Addr]bool) bool {
	dst = dst.Unmap()
	if !dst.Is4() || local[dst] {
		return false
	}
	for _, p := range allow {
		if p.Contains(dst) {
			return true
		}
	}
	for _, p := range tcpAccelDenied {
		if p.Contains(dst) {
			return false
		}
	}
	return true
}

type prefixList []netip.Prefix

func (p *prefixList) String() string {
	parts := make([]string, len(*p))
	for i, v := range *p {
		parts[i] = v.String()
	}
	return strings.Join(parts, ",")
}

func (p *prefixList) Set(v string) error {
	prefix, err := netip.ParsePrefix(v)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("invalid IPv4 CIDR %q", v)
	}
	*p = append(*p, prefix.Masked())
	return nil
}
