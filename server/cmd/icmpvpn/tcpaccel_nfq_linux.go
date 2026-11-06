//go:build linux

package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

const (
	netlinkNetfilter = 12
	solNetlink       = 270
	netlinkNoENOBUFS = 5
)

type nfqueue struct {
	fd    int
	queue uint16
	mu    sync.Mutex
}

func openNFQ(queue uint16, maxLen uint32) (*nfqueue, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	q := &nfqueue{fd: fd, queue: queue}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	syscall.SetsockoptInt(fd, solNetlink, netlinkNoENOBUFS, 1)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, 8<<20)
	buf := make([]byte, 8192)
	for i, m := range nfqBindMsgs(queue, maxLen) {
		if err := q.send(m); err != nil {
			syscall.Close(fd)
			return nil, err
		}
		for {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				syscall.Close(fd)
				return nil, fmt.Errorf("nfqueue config ack: %w", err)
			}
			_, seq, errno, ok := parseNFQ(buf[:n])
			if !ok || seq != uint32(i+1) {
				continue
			}
			if errno != 0 {
				syscall.Close(fd)
				return nil, fmt.Errorf("nfqueue %d config step %d: %w", queue, i+1, syscall.Errno(-errno))
			}
			break
		}
	}
	return q, nil
}

func (q *nfqueue) send(m []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return syscall.Sendto(q.fd, m, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

func (q *nfqueue) verdict(p nfqPacket, d admitDecision, bypassMark uint32) {
	var m []byte
	switch d {
	case admitDrop:
		m = nfqVerdictMsg(q.queue, p.id, nfDrop, false, 0)
	case admitBypass:
		m = nfqVerdictMsg(q.queue, p.id, nfAccept, true, p.mark|bypassMark)
	default:
		m = nfqVerdictMsg(q.queue, p.id, nfAccept, false, 0)
	}
	if err := q.send(m); err != nil {
		log.Printf("nfqueue verdict: %v", err)
	}
}

// serveAdmission holds client SYNs until the upstream dial resolves.
func serveAdmission(q *nfqueue, adm *admission, dial func(netip.AddrPort) (net.Conn, error),
	allowed func(netip.Addr) bool, st *tcpAccelStats, maxPending int, bypassMark uint32) {
	pend := make(chan struct{}, maxPending)
	go func() {
		for range time.Tick(5 * time.Second) {
			adm.sweep()
		}
	}()
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(q.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ENOBUFS) {
				continue
			}
			log.Printf("nfqueue recv: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		pkts, _, _, _ := parseNFQ(buf[:n])
		for _, p := range pkts {
			k, ok := synKey(p.payload)
			if !ok || !allowed(k.dst.Addr()) {
				q.verdict(p, admitAccept, bypassMark)
				continue
			}
			switch d := adm.onSYN(k); d {
			case admitDial:
				select {
				case pend <- struct{}{}:
					go func(p nfqPacket, k flowKey) {
						c, err := dial(k.dst)
						<-pend
						if err != nil {
							st.dialFailed.Add(1)
							st.bypassed.Add(1)
						}
						q.verdict(p, adm.dialDone(k, c, err), bypassMark)
					}(p, k)
				default:
					adm.abandon(k)
					st.bypassed.Add(1)
					q.verdict(p, admitBypass, bypassMark)
				}
			case admitBypass:
				st.bypassed.Add(1)
				q.verdict(p, d, bypassMark)
			default:
				q.verdict(p, d, bypassMark)
			}
		}
	}
}
