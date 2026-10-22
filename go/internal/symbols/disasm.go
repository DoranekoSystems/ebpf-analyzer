package symbols

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"golang.org/x/arch/x86/x86asm"
	"strconv"
	"strings"
)

type Instruction struct {
	Address string `json:"address"`
	Bytes   string `json:"bytes"`
	Text    string `json:"text"`
	Symbol  string `json:"symbol"`
}
type Disassembly struct {
	Address      string        `json:"address"`
	Source       string        `json:"source"`
	Boundary     string        `json:"boundary"`
	Stop         string        `json:"stop"`
	Next         string        `json:"next,omitempty"`
	Previous     string        `json:"previous,omitempty"`
	FileID       string        `json:"fileId"`
	Instructions []Instruction `json:"instructions"`
}

// DisassembleBefore decodes forward from a known symbol boundary. x86 instructions
// cannot safely be decoded by subtracting an arbitrary byte count from the PC.
func (e *ELF) DisassembleBefore(m Mapping, addr uint64) Disassembly {
	out := Disassembly{Address: fmt.Sprintf("0x%016x", addr), Source: "ELF file: " + m.Path, FileID: e.FileID,
		Boundary: "Decoded from ELF symbol start", Stop: "No earlier verified symbol boundary", Instructions: []Instruction{}}
	value, ok := e.Virtual(m, addr)
	if !ok {
		return out
	}
	symbol := e.Lookup(value)
	if symbol == nil || value <= symbol.Value || value-symbol.Value > 65536 || value-symbol.Value > addr-m.Start {
		return out
	}
	start := addr - (value - symbol.Value)
	at := start
	var lines []Instruction
	for at < addr {
		page := e.Disassemble(m, at, nil)
		if len(page.Instructions) == 0 {
			return out
		}
		for _, line := range page.Instructions {
			pc, err := strconv.ParseUint(strings.TrimPrefix(line.Address, "0x"), 16, 64)
			if err != nil || pc != at {
				return out
			}
			end := pc + uint64(len(line.Bytes)/2)
			if end > addr {
				return out
			}
			lines = append(lines, line)
			if len(lines) > 64 {
				lines = lines[1:]
			}
			at = end
			if at == addr {
				out.Instructions = lines
				out.Stop = "Start of symbol"
				if lines[0].Address != fmt.Sprintf("0x%016x", start) {
					out.Previous = lines[0].Address
					out.Stop = "Scroll up for earlier instructions"
				}
				return out
			}
		}
	}
	return out
}

func (e *ELF) Disassemble(m Mapping, addr uint64, expected []byte) Disassembly {
	out := Disassembly{Address: fmt.Sprintf("0x%016x", addr), Source: "ELF file: " + m.Path, Boundary: "Selected address; instruction boundary not independently verified", Instructions: []Instruction{}}
	out.FileID = e.FileID
	if e.Machine != elf.EM_X86_64 || e.Class != elf.ELFCLASS64 {
		out.Stop = "Only x86_64 ELF is supported"
		return out
	}
	value, ok := e.Virtual(m, addr)
	if !ok || !strings.Contains(m.Perms, "x") {
		out.Stop = "Not in an executable file-backed mapping"
		return out
	}
	fileOffset := m.Offset + addr - m.Start
	limit := uint64(271) // One maximum-length instruction of lookahead across a page boundary.
	if m.End-addr < limit {
		limit = m.End - addr
	}
	found := false
	for _, p := range e.Programs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && fileOffset >= p.Off && fileOffset-p.Off < p.Filesz && p.Vaddr+(fileOffset-p.Off) == value {
			if p.Filesz-(fileOffset-p.Off) < limit {
				limit = p.Filesz - (fileOffset - p.Off)
			}
			found = true
			break
		}
	}
	if !found {
		out.Stop = "Not in an executable ELF load segment"
		return out
	}
	if fileOffset > 1<<63-1 || e.Reader == nil {
		out.Stop = "Invalid file offset"
		return out
	}
	code := make([]byte, int(limit))
	n, err := e.Reader.ReadAt(code, int64(fileOffset))
	code = code[:n]
	if len(expected) > 0 {
		if len(code) < len(expected) || !bytes.Equal(code[:len(expected)], expected) {
			out.Stop = "ELF bytes differ from the captured instruction"
			return out
		}
		out.Boundary = "Start bytes match captured syscall opcode; remaining bytes are from ELF"
	}
	out.Stop = "End of file-backed range"
	if limit == 271 {
		out.Stop = "Scroll for more"
	}
	if err != nil {
		out.Stop = "File read boundary"
	}
	for at := 0; at < len(code); {
		if len(out.Instructions) >= 64 || at >= 256 {
			out.Stop = "Scroll for more"
			out.Next = fmt.Sprintf("0x%016x", addr+uint64(at))
			break
		}
		inst, e2 := x86asm.Decode(code[at:], 64)
		if e2 != nil || inst.Op == 0 || inst.Len <= 0 || inst.Len > len(code)-at {
			out.Stop = fmt.Sprintf("Cannot decode instruction at 0x%016x", addr+uint64(at))
			break
		}
		symbol := ""
		if s := e.Lookup(value + uint64(at)); s != nil {
			symbol = fmt.Sprintf("%s+0x%x", s.Name, value+uint64(at)-s.Value)
		}
		out.Instructions = append(out.Instructions, Instruction{fmt.Sprintf("0x%016x", addr+uint64(at)), hex.EncodeToString(code[at : at+inst.Len]), x86asm.IntelSyntax(inst, addr+uint64(at), nil), symbol})
		at += inst.Len
	}
	return out
}
