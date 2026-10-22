package symbols

import (
	"bytes"
	"debug/elf"
	"strings"
	"testing"
)

func fixture(code []byte) (*ELF, Mapping) {
	raw := append(make([]byte, 32), code...)
	return &ELF{Reader: bytes.NewReader(raw), Machine: elf.EM_X86_64, Class: elf.ELFCLASS64, Programs: []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_X, Off: 32, Vaddr: 0x1000, Filesz: uint64(len(code))}}}, Symbols: []Symbol{{Name: "syscall_wrapper", Value: 0x1000, Size: 6}}}, Mapping{Start: 0x7000, End: 0x8000, Offset: 32, Perms: "r-xp", Path: "/lib/test.so"}
}
func TestForwardDisassembly(t *testing.T) {
	e, m := fixture([]byte{0x0f, 0x05, 0x48, 0x89, 0xc7, 0xc3, 0x0f})
	d := e.Disassemble(m, m.Start, []byte{0x0f, 0x05})
	if len(d.Instructions) != 3 || d.Instructions[0].Bytes != "0f05" || d.Instructions[0].Text != "syscall" || d.Instructions[1].Address != "0x0000000000007002" || d.Instructions[2].Symbol != "syscall_wrapper+0x5" || !strings.Contains(d.Stop, "7006") {
		t.Fatalf("unexpected decode: %+v", d)
	}
	if d = e.Disassemble(m, m.Start, []byte{0xcc}); len(d.Instructions) != 0 || !strings.Contains(d.Stop, "differ") {
		t.Fatal("accepted changed anchor")
	}
	m.Perms = "r--p"
	if d = e.Disassemble(m, m.Start, nil); len(d.Instructions) != 0 {
		t.Fatal("decoded non executable mapping")
	}
}
func TestDisassemblyLimits(t *testing.T) {
	e, m := fixture(bytes.Repeat([]byte{0x90}, 300))
	d := e.Disassemble(m, m.Start, nil)
	if len(d.Instructions) != 64 || d.Next != "0x0000000000007040" {
		t.Fatal("instruction limit")
	}
	m.End = m.Start + 1
	d = e.Disassemble(m, m.Start, nil)
	if len(d.Instructions) != 1 {
		t.Fatal("read across mapping boundary")
	}
	e.Machine = elf.EM_AARCH64
	if len(e.Disassemble(m, m.Start, nil).Instructions) != 0 {
		t.Fatal("decoded wrong ISA")
	}
}

func TestContinuationKeepsInstructionBoundary(t *testing.T) {
	// Five-byte MOV instructions straddle the nominal byte boundary.
	code := bytes.Repeat([]byte{0xb8, 1, 0, 0, 0}, 100)
	e, m := fixture(code)
	first := e.Disassemble(m, m.Start, nil)
	if len(first.Instructions) != 52 || first.Next != "0x0000000000007104" {
		t.Fatalf("bad first page: %d %s", len(first.Instructions), first.Next)
	}
	second := e.Disassemble(m, m.Start+260, nil)
	if second.Instructions[0].Address != first.Next || second.Instructions[0].Bytes != "b801000000" || len(second.Instructions) != 48 || second.Next != "" {
		t.Fatal("continuation lost instruction boundary")
	}
}

func TestEarlierDisassemblyUsesSymbolBoundary(t *testing.T) {
	code := bytes.Repeat([]byte{0xb8, 1, 0, 0, 0}, 150)
	e, m := fixture(code)
	e.Symbols[0].Size = uint64(len(code))
	d := e.DisassembleBefore(m, m.Start+700)
	if len(d.Instructions) != 64 || d.Previous != "0x000000000000717c" || d.Instructions[63].Address != "0x00000000000072b7" {
		t.Fatalf("bad earlier page: %+v", d)
	}
	d = e.DisassembleBefore(m, m.Start+380)
	if len(d.Instructions) != 64 || d.Previous != "0x000000000000703c" {
		t.Fatal("bad previous page")
	}
	if len(e.DisassembleBefore(m, m.Start+699).Instructions) != 0 {
		t.Fatal("accepted middle of instruction")
	}
	e.Symbols = nil
	if len(e.DisassembleBefore(m, m.Start+700).Instructions) != 0 {
		t.Fatal("guessed instruction boundary without symbol")
	}
}
