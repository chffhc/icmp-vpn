package main

import (
	"net/netip"
	"testing"
)

func TestTCPAccelDestinationPolicy(t *testing.T) {
	local := map[netip.Addr]bool{netip.MustParseAddr("10.2.20.7"): true, netip.MustParseAddr("203.0.113.9"): true}
	allow := []netip.Prefix{netip.MustParsePrefix("172.18.0.0/16"), netip.MustParsePrefix("10.2.20.0/24")}
	for _, tc := range []struct {
		addr  string
		allow bool
		want  bool
	}{
		{"1.1.1.1", false, true},
		{"8.8.8.8", false, true},
		{"127.0.0.1", false, false},
		{"10.77.0.1", false, false},
		{"10.2.20.1", false, false},
		{"172.17.0.2", false, false},
		{"192.168.50.10", false, false},
		{"100.100.100.100", false, false},
		{"169.254.169.254", false, false},
		{"224.0.0.1", false, false},
		{"0.0.0.0", false, false},
		{"203.0.113.9", false, false}, // VPS-local public address
		{"172.18.0.5", true, true},    // test fixture allow-list
		{"10.2.20.7", true, false},    // allow-list never permits local
		{"::ffff:1.1.1.1", false, true},
		{"2001:db8::1", false, false},
	} {
		var a []netip.Prefix
		if tc.allow {
			a = allow
		}
		if got := destinationAllowed(netip.MustParseAddr(tc.addr), a, local); got != tc.want {
			t.Errorf("%s allow=%v: got %v want %v", tc.addr, tc.allow, got, tc.want)
		}
	}
}

func TestTCPAccelPrefixFlag(t *testing.T) {
	var p prefixList
	if err := p.Set("172.18.3.4/16"); err != nil || p[0].String() != "172.18.0.0/16" {
		t.Fatal(p, err)
	}
	for _, bad := range []string{"", "x", "2001:db8::/32", "1.2.3.4"} {
		if p.Set(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
