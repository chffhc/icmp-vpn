//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"icmpvpn/server/vpn"
)

func openTUN(name string) (*os.File, error) {
	if len(name) == 0 || len(name) > 15 {
		return nil, errors.New("TUN name must be 1..15 bytes")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("TUN must already be configured (see docs/server.md): %w", err)
	}
	if iface.MTU != vpn.MaxPlaintext || iface.Flags&net.FlagUp == 0 {
		return nil, errors.New("TUN must be UP with MTU 1200")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	found := false
	for _, a := range addrs {
		if a.String() == "10.77.0.1/24" {
			found = true
		}
	}
	if !found {
		return nil, errors.New("TUN requires local address 10.77.0.1/24")
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	// ifreq is 40 bytes on both supported Linux amd64 and arm64 ABIs.
	var req [40]byte
	copy(req[:16], name)
	*(*uint16)(unsafe.Pointer(&req[16])) = 0x1001 // IFF_TUN | IFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, errno
	}
	// Wrap ONLY after TUNSETIFF. os.NewFile registers a nonblocking fd with
	// Go's edge-triggered netpoller immediately; an unattached /dev/net/tun
	// installs no wait queue (tun_chr_poll returns EPOLLERR), so reads would
	// park forever while writes still succeed (upstream works, downstream
	// silently stalls). Regression: tests/run_linux_e2e.py downstream TCP.
	return os.NewFile(uintptr(fd), "tun:"+name), nil
}
func openICMP(listen netip.Addr) (*os.File, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "raw-icmp")
	if err = syscall.Bind(fd, &syscall.SockaddrInet4{Addr: listen.As4()}); err != nil {
		f.Close()
		return nil, err
	}
	// Do not change host sysctls or kernel echo policy. Reflected unencrypted
	// replies are direction-authentication failures on the client.
	return f, nil
}

type readResult struct {
	data []byte
	err  error
}

func readLoop(ctx context.Context, wg *sync.WaitGroup, f *os.File, out chan<- readResult) {
	defer wg.Done()
	buf := make([]byte, 65535)
	for {
		n, err := f.Read(buf)
		r := readResult{err: err}
		if n > 0 {
			r.data = append([]byte(nil), buf[:n]...)
		}
		select {
		case out <- r:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}
func serve(ctx context.Context, engine *vpn.Engine, tunName string, listen netip.Addr) error {
	tun, err := openTUN(tunName)
	if err != nil {
		return fmt.Errorf("open TUN: %w", err)
	}
	raw, err := openICMP(listen)
	if err != nil {
		tun.Close()
		return fmt.Errorf("open raw ICMP (CAP_NET_RAW required): %w", err)
	}
	rawControl, err := raw.SyscallConn()
	if err != nil {
		raw.Close()
		tun.Close()
		return err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	// Closing pollable descriptors unblocks readers before joining them.
	defer func() { cancel(); raw.Close(); tun.Close(); wg.Wait() }()
	rawPackets := make(chan readResult, 1)
	tunPackets := make(chan readResult, 1)
	wg.Add(2)
	go readLoop(workerCtx, &wg, raw, rawPackets)
	go readLoop(workerCtx, &wg, tun, tunPackets)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	statsTick := time.NewTicker(30 * time.Second)
	defer statsTick.Stop()
	var malformed, tunDropped uint64
	var lastCapacityWarning time.Time
	report := func() {
		log.Printf("stats %+v malformed_icmp=%d tun_dropped=%d", engine.Stats(), malformed, tunDropped)
	}
	defer report()
	log.Printf("serving ICMP on %s TUN=%s; no routes/firewall/sysctls changed", listen, tunName)
	for {
		select {
		case <-ctx.Done():
			log.Print("shutdown requested")
			return nil
		case now := <-tick.C:
			engine.Tick(now)
		case <-statsTick.C:
			report()
		case r := <-tunPackets:
			if r.err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("TUN read: %w", r.err)
			}
			if err = engine.Enqueue(r.data, time.Now()); err != nil {
				tunDropped++
			}
		case r := <-rawPackets:
			if r.err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("ICMP read: %w", r.err)
			}
			echo, err := vpn.ParseRawEcho(r.data)
			if err != nil {
				malformed++
				continue
			}
			result, err := engine.Handle(echo.Source, echo.Payload, time.Now())
			if err != nil {
				if errors.Is(err, vpn.ErrSessionStore) {
					return err
				}
				if errors.Is(err, vpn.ErrSessionCapacity) && time.Since(lastCapacityWarning) >= 30*time.Second {
					log.Print(err)
					lastCapacityWarning = time.Now()
				}
				continue
			}
			if result.Upstream != nil {
				n, err := tun.Write(result.Upstream)
				if err != nil {
					return fmt.Errorf("TUN write: %w", err)
				}
				if n != len(result.Upstream) {
					return io.ErrShortWrite
				}
			}
			reply, err := vpn.BuildEcho(0, echo.Identifier, echo.Sequence, result.Reply)
			if err != nil {
				return err
			}
			// The actual received ping identifier/sequence are mirrored. Never use
			// the identifier as session identity (ping datagram kernels rewrite it).
			if err = raw.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return err
			}
			var sendErr error
			controlErr := rawControl.Write(func(fd uintptr) bool {
				for {
					sendErr = syscall.Sendto(int(fd), reply, 0, &syscall.SockaddrInet4{Addr: echo.Source.As4()})
					if sendErr != syscall.EINTR {
						break
					}
				}
				return sendErr != syscall.EAGAIN && sendErr != syscall.EWOULDBLOCK
			})
			if controlErr != nil {
				return fmt.Errorf("ICMP reply write: %w", controlErr)
			}
			if sendErr != nil {
				return fmt.Errorf("ICMP reply send: %w", sendErr)
			}
		}
	}
}
