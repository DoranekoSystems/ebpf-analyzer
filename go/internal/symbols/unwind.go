package symbols

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"github.com/go-delve/delve/pkg/dwarf/frame"
	"strconv"
	"strings"
)

type StackFrame struct {
	PC     string `json:"pc"`
	SP     string `json:"sp"`
	FP     string `json:"fp"`
	Symbol string `json:"symbol"`
	Module string `json:"module"`
}
type StackTrace struct {
	Frames []StackFrame `json:"frames"`
	Stop   string       `json:"stop"`
}
type SavedStack struct {
	Base      string            `json:"base"`
	Data      []byte            `json:"data"`
	Registers map[string]string `json:"registers"`
	PC        string            `json:"pc"`
}

func (e *ELF) frameAt(pc uint64) (ctx *frame.FrameContext, err error) {
	defer func() {
		if recover() != nil {
			ctx = nil
			err = fmt.Errorf("unsupported or malformed CFI")
		}
	}()
	if !e.framesLoaded {
		e.framesLoaded = true
		if e.cfi == nil {
			e.frameError = fmt.Errorf("ELF has no .eh_frame")
		} else if e.cfi.Size > 8<<20 {
			e.frameError = fmt.Errorf("CFI section exceeds limit")
		} else {
			var data []byte
			data, e.frameError = e.cfi.Data()
			if e.frameError == nil {
				e.frames, e.frameError = frame.Parse(data, e.order, 0, 8, e.cfi.Addr)
			}
		}
	}
	if e.frameError != nil {
		return nil, e.frameError
	}
	fde, err := e.frames.FDEForPC(pc)
	if err != nil {
		return nil, fmt.Errorf("no CFI for this address")
	}
	return fde.EstablishFrame(pc), nil
}
func unsigned(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 64)
}
func addOffset(v uint64, n int64) (uint64, bool) {
	if n >= 0 {
		r := v + uint64(n)
		return r, r >= v
	}
	m := uint64(-(n + 1)) + 1
	return v - m, v >= m
}

// Only saved event memory is used. Never read a running thread's current stack.
func Unwind(s SavedStack, load func(uint64) (*ELF, Mapping, error)) StackTrace {
	out := StackTrace{Frames: []StackFrame{}}
	if len(s.Data) > 16384 {
		out.Stop = "Saved stack exceeds limit"
		return out
	}
	base, err := unsigned(s.Base)
	if err != nil {
		out.Stop = "Invalid stack base"
		return out
	}
	pc, err := unsigned(s.PC)
	if err != nil {
		out.Stop = "No verified PC"
		return out
	}
	names := []string{"rax_saved", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"}
	regs := map[uint64]uint64{}
	for i, name := range names {
		if v, e := unsigned(s.Registers[name]); e == nil {
			regs[uint64(i)] = v
		}
	}
	read := func(addr uint64) (uint64, bool) {
		if addr < base || addr-base > uint64(len(s.Data)) || uint64(len(s.Data))-(addr-base) < 8 {
			return 0, false
		}
		return binary.LittleEndian.Uint64(s.Data[addr-base:]), true
	}
	for depth := 0; depth < 64; depth++ {
		sp, ok := regs[7]
		if !ok {
			out.Stop = "Stack pointer unavailable"
			break
		}
		entry := StackFrame{PC: fmt.Sprintf("0x%016x", pc), SP: fmt.Sprintf("0x%016x", sp), FP: fmt.Sprintf("0x%016x", regs[6])}
		lookupPC := pc
		if depth > 0 && pc > 0 {
			lookupPC--
		}
		e, m, err := load(lookupPC)
		entry.Module = m.Path
		if err != nil {
			out.Frames = append(out.Frames, entry)
			out.Stop = err.Error()
			break
		}
		if e.Machine != elf.EM_X86_64 || e.Class != elf.ELFCLASS64 {
			out.Frames = append(out.Frames, entry)
			out.Stop = "Only x86_64 CFI is supported"
			break
		}
		value, ok := e.Virtual(m, lookupPC)
		if !ok {
			out.Frames = append(out.Frames, entry)
			out.Stop = "PC outside ELF load segment"
			break
		}
		entry.Module = m.Path
		if sym := e.Lookup(value); sym != nil {
			entry.Symbol = fmt.Sprintf("%s+0x%x", sym.Name, value-sym.Value)
		}
		out.Frames = append(out.Frames, entry)
		ctx, err := e.frameAt(value)
		if err != nil {
			out.Stop = err.Error()
			break
		}
		next, err := unwindRow(ctx, regs, read)
		if err != nil {
			out.Stop = err.Error()
			break
		}
		if next[7] <= sp {
			out.Stop = "Non-increasing stack pointer"
			break
		}
		if next[16] == 0 {
			out.Stop = "End of stack"
			break
		}
		pc = next[16]
		regs = next
		if depth == 63 {
			out.Stop = "64-frame limit"
		}
	}
	return out
}
func unwindRow(ctx *frame.FrameContext, regs map[uint64]uint64, read func(uint64) (uint64, bool)) (map[uint64]uint64, error) {
	if ctx.CFA.Rule != frame.RuleCFA {
		return nil, fmt.Errorf("CFI expression for CFA is not supported")
	}
	v, ok := regs[ctx.CFA.Reg]
	if !ok {
		return nil, fmt.Errorf("CFI register unavailable")
	}
	cfa, ok := addOffset(v, ctx.CFA.Offset)
	if !ok {
		return nil, fmt.Errorf("CFI address overflow")
	}
	next := map[uint64]uint64{7: cfa}
	for _, r := range []uint64{3, 6, 12, 13, 14, 15} {
		if v, ok := regs[r]; ok {
			next[r] = v
		}
	}
	for r, rule := range ctx.Regs {
		var value uint64
		valid := true
		switch rule.Rule {
		case frame.RuleUndefined:
			delete(next, r)
			continue
		case frame.RuleSameVal:
			value, valid = regs[r]
		case frame.RuleRegister:
			value, valid = regs[rule.Reg]
		case frame.RuleOffset:
			var addr uint64
			addr, valid = addOffset(cfa, rule.Offset)
			if valid {
				value, valid = read(addr)
			}
		case frame.RuleValOffset:
			value, valid = addOffset(cfa, rule.Offset)
		default:
			return nil, fmt.Errorf("Unsupported CFI register rule")
		}
		if !valid {
			return nil, fmt.Errorf("Required register or saved stack bytes unavailable")
		}
		next[r] = value
	}
	ret, ok := next[ctx.RetAddrReg]
	if !ok {
		return nil, fmt.Errorf("Return address unavailable")
	}
	next[16] = ret
	next[7] = cfa
	return next, nil
}
