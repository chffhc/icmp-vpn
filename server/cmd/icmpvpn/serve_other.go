//go:build !linux

package main

import (
	"context"
	"errors"
	"net/netip"

	"icmpvpn/server/vpn"
)

func runTCPAccel([]string) error {
	return errors.New("tcpaccel requires Linux netfilter REDIRECT; cross-build with GOOS=linux")
}

func serve(context.Context, *vpn.Engine, string, netip.Addr) error {
	return errors.New("serve requires Linux raw ICMP and TUN; cross-build with GOOS=linux")
}
