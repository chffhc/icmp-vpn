//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	soOriginalDst   = 80 // SOL_IP SO_ORIGINAL_DST (netfilter REDIRECT)
	tcpCongestion   = 13 // IPPROTO_TCP TCP_CONGESTION
	soMaxPacingRate = 47 // SOL_SOCKET SO_MAX_PACING_RATE
)

type tcpAccelConfig struct {
	pacing     int // bytes/s on the client-facing (long-RTT) leg; 0 = off
	sndbuf     int // forced send buffer on the client-facing leg; 0 = kernel autotune
	congestion string
	connLog    bool
	allow      []netip.Prefix
	local      map[netip.Addr]bool
	dialTO     time.Duration
	adm        *admission
}

type tcpAccelStats struct{ accepted, active, rejected, dialFailed, overload, bypassed, predialed atomic.Int64 }

// runTCPAccel is a split-TCP transparent proxy for tunnel TCP. The client's TCP
// terminates here (VPS), so the long-RTT segment back to the phone is sent by
// this kernel with a chosen congestion control and route initcwnd. Network
// redirection is installed separately by scripts/tcpaccel-network.sh.
// Semantics: the kernel completes the client handshake before the upstream
// dial; an unreachable upstream is reported to the client as a reset.
func runTCPAccel(args []string) error {
	fs := flag.NewFlagSet("tcpaccel", flag.ContinueOnError)
	listen := fs.String("listen", "10.77.0.1:7011", "TUN-local listen address (REDIRECT target)")
	congestion := fs.String("congestion", "bbr", "congestion control for both proxy legs")
	maxConns := fs.Int("max-conns", 512, "concurrent proxied connections, 1..8192")
	dialTimeout := fs.Duration("dial-timeout", 15*time.Second, "upstream connect timeout")
	pacing := fs.Int("client-pacing", 0, "bytes/s pacing on the tunnel leg (match tunnel capacity; 0=off)")
	sndbuf := fs.Int("client-sndbuf", 0, "forced send buffer bytes on the tunnel leg (needs CAP_NET_ADMIN; 0=autotune)")
	synRTO := fs.Duration("syn-rto", 3*time.Second, "initial SYN-ACK RTO for proxied handshakes via cgroup sock_ops BPF (0=off)")
	kernelHz := fs.Int("kernel-hz", 0, "kernel CONFIG_HZ for --syn-rto (0=auto-detect, fail closed)")
	admitQueue := fs.Int("admit-queue", 0, "NFQUEUE number for connect-before-accept (0=off: unreachable upstream => client RST)")
	bypassMark := fs.Uint("bypass-mark", 0x10000000, "fwmark bit set on SYNs that must skip REDIRECT (must match tcpaccel-network.sh)")
	failTTL := fs.Duration("fail-ttl", 60*time.Second, "after a failed dial, send that destination direct for this long")
	connLog := fs.Bool("conn-log", false, "log per-connection TCP_INFO (no payload, no client identity beyond tunnel)")
	var allow prefixList
	fs.Var(&allow, "allow-dst", "TEST ONLY: private IPv4 CIDR the proxy may dial (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pacing < 0 || *pacing > 1<<30 || *sndbuf < 0 || *sndbuf > 64<<20 {
		return errors.New("invalid pacing/sndbuf")
	}
	if fs.NArg() != 0 || *maxConns < 1 || *maxConns > 8192 || *dialTimeout <= 0 || *congestion == "" {
		return errors.New("invalid tcpaccel flags")
	}
	listenAddr, err := netip.ParseAddrPort(*listen)
	if err != nil || !listenAddr.Addr().Is4() {
		return errors.New("--listen must be literal IPv4:port")
	}
	if err := probeCongestion(*congestion); err != nil {
		return err
	}
	local, err := localAddrs()
	if err != nil {
		return err
	}
	if *synRTO != 0 {
		hz := *kernelHz
		if hz == 0 {
			if hz, err = kernelHZ(); err != nil {
				return err
			}
		}
		linkFD, desc, err := attachSynRTO(listenAddr.Port(), *synRTO, hz)
		if err != nil {
			return fmt.Errorf("syn-rto BPF: %w (use --syn-rto 0 to run without it)", err)
		}
		defer syscall.Close(linkFD)
		log.Printf("tcpaccel syn-rto attached %s", desc)
	}
	cfg := tcpAccelConfig{connLog: *connLog, pacing: *pacing, sndbuf: *sndbuf, congestion: *congestion, allow: allow, local: local, dialTO: *dialTimeout}
	var st tcpAccelStats
	if *admitQueue != 0 {
		if *admitQueue < 1 || *admitQueue > 65535 || *bypassMark == 0 || *bypassMark > 0xffffffff || *failTTL < 0 {
			return errors.New("invalid admit-queue/bypass-mark/fail-ttl")
		}
		q, err := openNFQ(uint16(*admitQueue), 4096)
		if err != nil {
			return fmt.Errorf("admit-queue: %w", err)
		}
		cfg.adm = newAdmission(cfg.dialTO, *failTTL, 4*(*maxConns))
		dial := func(dst netip.AddrPort) (net.Conn, error) { return dialUpstream(dst, cfg) }
		allowed := func(a netip.Addr) bool { return destinationAllowed(a, cfg.allow, cfg.local) }
		go serveAdmission(q, cfg.adm, dial, allowed, &st, *maxConns, uint32(*bypassMark))
		log.Printf("tcpaccel admission queue=%d bypass-mark=%#x fail-ttl=%s (unreachable upstream => client sees direct path)", *admitQueue, *bypassMark, *failTTL)
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error { return setCongestion(c, cfg.congestion) }}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ln, err := lc.Listen(ctx, "tcp4", listenAddr.String())
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); ln.Close() }()
	log.Printf("tcpaccel listening on %s congestion=%s max-conns=%d client-pacing=%d client-sndbuf=%d allow-dst=%s", listenAddr, cfg.congestion, *maxConns, cfg.pacing, cfg.sndbuf, allow.String())
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Printf("tcpaccel stats accepted=%d active=%d rejected=%d dial_failed=%d overload=%d bypassed=%d predialed=%d",
					st.accepted.Load(), st.active.Load(), st.rejected.Load(), st.dialFailed.Load(), st.overload.Load(), st.bypassed.Load(), st.predialed.Load())
			}
		}
	}()
	sem := make(chan struct{}, *maxConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				log.Printf("tcpaccel final accepted=%d active=%d rejected=%d dial_failed=%d overload=%d bypassed=%d predialed=%d",
					st.accepted.Load(), st.active.Load(), st.rejected.Load(), st.dialFailed.Load(), st.overload.Load(), st.bypassed.Load(), st.predialed.Load())
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		tc := c.(*net.TCPConn)
		select {
		case sem <- struct{}{}:
		default:
			st.overload.Add(1)
			reset(tc)
			continue
		}
		st.accepted.Add(1)
		st.active.Add(1)
		go func() {
			defer func() { <-sem; st.active.Add(-1) }()
			proxyConn(tc, cfg, &st)
		}()
	}
}

func proxyConn(c *net.TCPConn, cfg tcpAccelConfig, st *tcpAccelStats) {
	dst, err := originalDst(c)
	if err != nil || !destinationAllowed(dst.Addr(), cfg.allow, cfg.local) {
		st.rejected.Add(1)
		reset(c)
		return
	}
	keepAlive(c)
	start := time.Now()
	if cfg.connLog {
		ti := tcpInfo(c)
		log.Printf("conn open dst=%s cwnd=%d total_retrans=%d rtt_ms=%d", dst, ti.Snd_cwnd, ti.Total_retrans, ti.Rtt/1000)
	}
	if err := tuneClientLeg(c, cfg); err != nil {
		log.Printf("tune client leg: %v", err)
	}
	var uc net.Conn
	if cfg.adm != nil {
		if rp, ok := netip.ParseAddrPort(c.RemoteAddr().String()); ok == nil {
			if uc = cfg.adm.take(flowKey{sport: rp.Port(), dst: dst}); uc != nil {
				st.predialed.Add(1)
			}
		}
	}
	if uc == nil {
		uc, err = dialUpstream(dst, cfg)
	}
	if err != nil {
		st.dialFailed.Add(1)
		reset(c)
		return
	}
	u := uc.(*net.TCPConn)
	keepAlive(u)
	var once sync.Once
	closeAll := func() { once.Do(func() { c.Close(); u.Close() }) }
	var wg sync.WaitGroup
	pipe := func(dstConn, srcConn *net.TCPConn) {
		defer wg.Done()
		if _, err := io.Copy(dstConn, srcConn); err != nil {
			closeAll()
			return
		}
		dstConn.CloseWrite()
	}
	wg.Add(2)
	go pipe(u, c)
	go pipe(c, u)
	wg.Wait()
	if cfg.connLog {
		ti := tcpInfo(c)
		log.Printf("conn close dst=%s dur=%.1fs cwnd=%d ssthresh=%d total_retrans=%d rtt_ms=%d", dst, time.Since(start).Seconds(), ti.Snd_cwnd, ti.Snd_ssthresh, ti.Total_retrans, ti.Rtt/1000)
	}
	closeAll()
}

func dialUpstream(dst netip.AddrPort, cfg tcpAccelConfig) (net.Conn, error) {
	d := net.Dialer{Timeout: cfg.dialTO, Control: func(_, _ string, rc syscall.RawConn) error { return setCongestion(rc, cfg.congestion) }}
	return d.Dial("tcp4", dst.String())
}

// Long outages on satellite links: tolerate ~3 minutes before declaring a peer dead.
func keepAlive(c *net.TCPConn) {
	c.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 60 * time.Second, Interval: 15 * time.Second, Count: 8})
}

// tuneClientLeg paces the long-RTT tunnel leg at the known tunnel capacity so a
// large initial window does not burst into (and overflow) the bounded ICMP
// downstream queue. SO_MAX_PACING_RATE also enables kernel TCP internal pacing.
func tuneClientLeg(c *net.TCPConn, cfg tcpAccelConfig) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		if cfg.sndbuf > 0 {
			if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, cfg.sndbuf); e != nil {
				serr = fmt.Errorf("SO_SNDBUFFORCE: %w", e)
			}
		}
		if cfg.pacing > 0 {
			if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMaxPacingRate, cfg.pacing); e != nil {
				serr = fmt.Errorf("SO_MAX_PACING_RATE: %w", e)
			}
		}
	}); err != nil {
		return err
	}
	return serr
}

func tcpInfo(c *net.TCPConn) syscall.TCPInfo {
	var ti syscall.TCPInfo
	rc, err := c.SyscallConn()
	if err != nil {
		return ti
	}
	rc.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(ti))
		syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, syscall.TCP_INFO,
			uintptr(unsafe.Pointer(&ti)), uintptr(unsafe.Pointer(&size)), 0)
	})
	return ti
}

func reset(c *net.TCPConn) {
	c.SetLinger(0)
	c.Close()
}

func setCongestion(c syscall.RawConn, name string) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, tcpCongestion, name)
	}); err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("TCP_CONGESTION %s: %w", name, serr)
	}
	return nil
}

func probeCongestion(name string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptString(fd, syscall.IPPROTO_TCP, tcpCongestion, name); err != nil {
		return fmt.Errorf("congestion control %q unavailable: %w", name, err)
	}
	return nil
}

func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var sa syscall.RawSockaddrInet4
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(sa))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_IP, soOriginalDst,
			uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&size)), 0)
		if e != 0 {
			gerr = e
		}
	}); err != nil {
		return netip.AddrPort{}, err
	}
	if gerr != nil {
		return netip.AddrPort{}, gerr
	}
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(p[0])<<8|uint16(p[1])), nil
}

func localAddrs() (map[netip.Addr]bool, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := map[netip.Addr]bool{}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out[ip.Unmap()] = true
			}
		}
	}
	return out, nil
}
