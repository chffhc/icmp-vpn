//go:build linux

package main

import (
	"encoding/binary"
	"testing"
)

func TestSynRTOProgramEncoding(t *testing.T) {
	p := synRTOProgram(7011, 750)
	if len(p) != 9*8 {
		t.Fatalf("len %d", len(p))
	}
	insn := func(i int) (uint8, uint8, int16, int32) {
		b := p[i*8:]
		return b[0], b[1], int16(binary.LittleEndian.Uint16(b[2:])), int32(binary.LittleEndian.Uint32(b[4:]))
	}
	if c, r, o, _ := insn(1); c != 0x61 || r != 0x62 || o != sockOpsOffOp {
		t.Fatal("op load")
	}
	if c, _, o, imm := insn(2); c != 0x55 || o != 4 || imm != sockOpsTimeoutInit {
		t.Fatal("op compare")
	}
	if _, _, o, _ := insn(3); o != sockOpsOffLocalPort {
		t.Fatal("port load")
	}
	if _, _, o, imm := insn(4); o != 2 || imm != 7011 {
		t.Fatal("port compare")
	}
	if _, _, _, imm := insn(5); imm != 750 {
		t.Fatal("jiffies")
	}
	if c, r, o, _ := insn(6); c != 0x63 || r != 0x26 || o != sockOpsOffReply {
		t.Fatal("reply store")
	}
	if c, _, _, imm := insn(7); c != 0xb7 || imm != 1 {
		t.Fatal("return 1")
	}
}
