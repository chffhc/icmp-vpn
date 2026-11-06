//go:build linux

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// A tiny cgroup sock_ops program that answers BPF_SOCK_OPS_TIMEOUT_INIT for
// sockets whose local port is the tcpaccel listener port. Effect: the SYN-ACK
// retransmission timer for proxied client handshakes starts at synRTO instead
// of the kernel's 1 s, so a 2 s tunnel RTT no longer causes spurious SYN-ACK
// retransmissions (which can collapse the new connection's cwnd to 1).
// Scope: attached via BPF link to this process's own cgroup only; every other
// port/op returns the kernel default. The link is held by an fd, so the
// program detaches automatically when the process exits (no pinned state).

const (
	bpfProgLoad         = 5
	bpfLinkCreate       = 28
	bpfProgTypeSockOp   = 13
	bpfCgroupSockOps    = 3
	sockOpsTimeoutInit  = 1
	sockOpsOffOp        = 0
	sockOpsOffReply     = 4
	sockOpsOffLocalPort = 68 // __u32 local_port, host byte order
)

type bpfInsn struct {
	code uint8
	regs uint8 // dst low nibble, src high nibble
	off  int16
	imm  int32
}

func synRTOProgram(port uint16, jiffies int32) []byte {
	ins := []bpfInsn{
		{0xbf, 0x16, 0, 0},                   // r6 = r1 (ctx)
		{0x61, 0x62, sockOpsOffOp, 0},        // r2 = *(u32 *)(r6 + op)
		{0x55, 0x02, 4, sockOpsTimeoutInit},  // if r2 != TIMEOUT_INIT goto ok
		{0x61, 0x62, sockOpsOffLocalPort, 0}, // r2 = *(u32 *)(r6 + local_port)
		{0x55, 0x02, 2, int32(port)},         // if r2 != port goto ok
		{0xb7, 0x02, 0, jiffies},             // r2 = jiffies
		{0x63, 0x26, sockOpsOffReply, 0},     // *(u32 *)(r6 + reply) = r2
		{0xb7, 0x00, 0, 1},                   // ok: r0 = 1
		{0x95, 0x00, 0, 0},                   // exit
	}
	var b bytes.Buffer
	for _, i := range ins {
		binary.Write(&b, binary.LittleEndian, i)
	}
	return b.Bytes()
}

// attachSynRTO loads and links the program to the caller's cgroup v2 and
// returns the link fd (must stay open for the process lifetime).
func attachSynRTO(port uint16, rto time.Duration, hz int) (int, string, error) {
	jiffies := int64(rto) * int64(hz) / int64(time.Second)
	if jiffies < int64(hz) || jiffies > 120*int64(hz) {
		return -1, "", fmt.Errorf("syn-rto %s out of range 1s..120s", rto)
	}
	prog := synRTOProgram(port, int32(jiffies))
	license := []byte("GPL\x00")
	logBuf := make([]byte, 16384)
	attr := make([]byte, 128)
	binary.LittleEndian.PutUint32(attr[0:], bpfProgTypeSockOp)
	binary.LittleEndian.PutUint32(attr[4:], uint32(len(prog)/8))
	binary.LittleEndian.PutUint64(attr[8:], uint64(uintptr(unsafe.Pointer(&prog[0]))))
	binary.LittleEndian.PutUint64(attr[16:], uint64(uintptr(unsafe.Pointer(&license[0]))))
	binary.LittleEndian.PutUint32(attr[24:], 1)
	binary.LittleEndian.PutUint32(attr[28:], uint32(len(logBuf)))
	binary.LittleEndian.PutUint64(attr[32:], uint64(uintptr(unsafe.Pointer(&logBuf[0]))))
	copy(attr[48:64], "ivpn_synrto")
	progFD, _, e := syscall.Syscall(sysBPF, bpfProgLoad, uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
	keepAliveBuffers(prog, license, logBuf)
	if e != 0 {
		return -1, "", fmt.Errorf("BPF_PROG_LOAD: %w: %s", e, strings.TrimRight(string(logBuf), "\x00"))
	}
	defer syscall.Close(int(progFD))
	cg, err := ownCgroupPath()
	if err != nil {
		return -1, "", err
	}
	cgFD, err := syscall.Open(cg, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open cgroup %s: %w", cg, err)
	}
	defer syscall.Close(cgFD)
	la := make([]byte, 64)
	binary.LittleEndian.PutUint32(la[0:], uint32(progFD))
	binary.LittleEndian.PutUint32(la[4:], uint32(cgFD))
	binary.LittleEndian.PutUint32(la[8:], bpfCgroupSockOps)
	linkFD, _, e := syscall.Syscall(sysBPF, bpfLinkCreate, uintptr(unsafe.Pointer(&la[0])), uintptr(len(la)))
	if e != 0 {
		return -1, "", fmt.Errorf("BPF_LINK_CREATE on %s: %w", cg, e)
	}
	return int(linkFD), fmt.Sprintf("cgroup=%s port=%d syn_rto=%s jiffies=%d hz=%d", cg, port, rto, jiffies, hz), nil
}

//go:noinline
func keepAliveBuffers(...[]byte) {}

func ownCgroupPath() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			p := filepath.Join("/sys/fs/cgroup", filepath.Clean("/"+rest))
			return p, nil
		}
	}
	return "", errors.New("cgroup v2 unified hierarchy required")
}

// kernelHZ reads CONFIG_HZ; fails closed when it cannot be determined.
func kernelHZ() (int, error) {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return 0, err
	}
	rel := make([]byte, 0, len(uts.Release))
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		rel = append(rel, byte(c))
	}
	try := func(r io.Reader) (int, bool) {
		s := bufio.NewScanner(r)
		for s.Scan() {
			if v, ok := strings.CutPrefix(s.Text(), "CONFIG_HZ="); ok {
				n, err := strconv.Atoi(v)
				return n, err == nil && n >= 100 && n <= 1000
			}
		}
		return 0, false
	}
	if f, err := os.Open("/boot/config-" + string(rel)); err == nil {
		defer f.Close()
		if n, ok := try(f); ok {
			return n, nil
		}
	}
	if f, err := os.Open("/proc/config.gz"); err == nil {
		defer f.Close()
		if z, err := gzip.NewReader(f); err == nil {
			if n, ok := try(z); ok {
				return n, nil
			}
		}
	}
	return 0, errors.New("cannot determine CONFIG_HZ; pass --kernel-hz")
}
