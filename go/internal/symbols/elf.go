// Package symbols resolves only defined ELF symbols whose ranges contain an address.
package symbols

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"github.com/go-delve/delve/pkg/dwarf/frame"
	"io"
	"strconv"
	"strings"
)

type Mapping struct {
	Start, End, Offset, Inode uint64
	Device, Perms, Path       string
}

func Maps(text string) ([]Mapping, error) {
	var result []Mapping
	scan := bufio.NewScanner(strings.NewReader(text))
	scan.Buffer(make([]byte, 4096), 1024*1024)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) < 5 {
			return nil, fmt.Errorf("invalid maps record")
		}
		span := strings.Split(fields[0], "-")
		if len(span) != 2 {
			return nil, fmt.Errorf("invalid map range")
		}
		start, e1 := strconv.ParseUint(span[0], 16, 64)
		end, e2 := strconv.ParseUint(span[1], 16, 64)
		off, e3 := strconv.ParseUint(fields[2], 16, 64)
		ino, e4 := strconv.ParseUint(fields[4], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || end <= start {
			return nil, fmt.Errorf("invalid map values")
		}
		// Split only the first five fields; preserve spaces inside paths.
		rest := scan.Text()
		for i := 0; i < 5; i++ {
			rest = strings.TrimLeft(rest, " \t")
			at := strings.IndexAny(rest, " \t")
			if at < 0 {
				rest = ""
				break
			}
			rest = rest[at:]
		}
		result = append(result, Mapping{start, end, off, ino, fields[3], fields[1], strings.TrimLeft(rest, " \t")})
	}
	return result, scan.Err()
}

type Symbol struct {
	Name    string `json:"name"`
	Value   uint64 `json:"-"`
	Address string `json:"address"`
	Size    uint64 `json:"size"`
}
type ELF struct {
	Programs     []*elf.Prog
	Symbols      []Symbol
	Reader       io.ReaderAt
	Machine      elf.Machine
	Class        elf.Class
	cfi          *elf.Section
	order        binary.ByteOrder
	frames       frame.FrameDescriptionEntries
	frameError   error
	framesLoaded bool
	FileID       string
}

func Read(reader io.ReaderAt) (*ELF, error) {
	f, err := elf.NewFile(reader)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Type != elf.ET_DYN && f.Type != elf.ET_EXEC {
		return nil, fmt.Errorf("unsupported ELF type")
	}
	var total uint64
	for _, s := range f.Sections {
		if s.Type == elf.SHT_SYMTAB || s.Type == elf.SHT_DYNSYM || s.Type == elf.SHT_STRTAB {
			total += s.Size
			if s.Size > 32<<20 || total > 64<<20 {
				return nil, fmt.Errorf("symbol tables exceed limit")
			}
		}
	}
	result := &ELF{Programs: f.Progs, Reader: reader, Machine: f.Machine, Class: f.Class}
	result.cfi = f.Section(".eh_frame")
	result.order = f.ByteOrder
	seen := map[string]bool{}
	for _, read := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		list, err := read()
		if err == elf.ErrNoSymbols {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(list) > 500000 {
			return nil, fmt.Errorf("too many ELF symbols")
		}
		for _, s := range list {
			t := elf.ST_TYPE(s.Info)
			if s.Section == elf.SHN_UNDEF || s.Section >= elf.SHN_LORESERVE || s.Name == "" || (t != elf.STT_FUNC && t != elf.STT_OBJECT && t != elf.STT_NOTYPE) {
				continue
			}
			key := fmt.Sprintf("%x/%s", s.Value, s.Name)
			if seen[key] {
				continue
			}
			seen[key] = true
			name := s.Name
			if len(name) > 512 {
				name = name[:512]
			}
			result.Symbols = append(result.Symbols, Symbol{name, s.Value, fmt.Sprintf("0x%016x", s.Value), s.Size})
		}
	}
	return result, nil
}

// Translate the mapping's file offset through PT_LOAD, not address-mapStart.
func (e *ELF) Virtual(m Mapping, address uint64) (uint64, bool) {
	if address < m.Start || address >= m.End {
		return 0, false
	}
	delta := address - m.Start
	if m.Offset > ^uint64(0)-delta {
		return 0, false
	}
	fileOffset := m.Offset + delta
	for _, p := range e.Programs {
		if p.Type == elf.PT_LOAD && fileOffset >= p.Off && fileOffset-p.Off < p.Filesz {
			return p.Vaddr + (fileOffset - p.Off), true
		}
	}
	return 0, false
}
func (e *ELF) Lookup(value uint64) *Symbol {
	var best *Symbol
	for i := range e.Symbols {
		s := &e.Symbols[i]
		if value < s.Value || !(value == s.Value || (s.Size > 0 && value-s.Value < s.Size)) {
			continue
		}
		if best == nil || s.Value > best.Value {
			best = s
		}
	}
	return best
}
