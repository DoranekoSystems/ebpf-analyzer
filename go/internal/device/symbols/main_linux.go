//go:build linux

// One-shot, explicitly requested resolver. No BPF hooks, process injection or ELF transfers.
package symbols

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/symbols"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type request struct {
	PID           int                 `json:"pid"`
	BootID        string              `json:"bootId"`
	EventNS       string              `json:"eventNs"`
	Addresses     []string            `json:"addresses"`
	Disassemble   string              `json:"disassemble,omitempty"`
	ExpectedBytes string              `json:"expectedBytes,omitempty"`
	Stack         *symbols.SavedStack `json:"stack,omitempty"`
	MapsHash      string              `json:"mapsHash,omitempty"`
	CodeMapping   string              `json:"codeMapping,omitempty"`
	FileID        string              `json:"fileId,omitempty"`
	CodeOnly      bool                `json:"codeOnly,omitempty"`
	Before        bool                `json:"before,omitempty"`
}
type resolution struct {
	Address string `json:"address"`
	Module  string `json:"module"`
	Symbol  string `json:"symbol"`
	Status  string `json:"status"`
}
type module struct {
	Path      string           `json:"path"`
	Symbols   []symbols.Symbol `json:"symbols"`
	Truncated bool             `json:"truncated"`
}
type response struct {
	ResolvedAt  int64                `json:"resolvedAtEpochMs"`
	Scope       string               `json:"scope"`
	Results     []resolution         `json:"results"`
	Modules     []module             `json:"modules"`
	Error       string               `json:"error,omitempty"`
	Disassembly *symbols.Disassembly `json:"disassembly,omitempty"`
	StackTrace  *symbols.StackTrace  `json:"stackTrace,omitempty"`
	MapsHash    string               `json:"mapsHash"`
	CodeMapping string               `json:"codeMapping,omitempty"`
}

func Main() {
	time.AfterFunc(12*time.Second, func() { os.Exit(1) })
	result, err := run()
	if err != nil {
		result = response{Error: err.Error()}
	}
	json.NewEncoder(os.Stdout).Encode(result)
}
func read(path string, limit int) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if len(b) > limit {
		return nil, fmt.Errorf("file exceeds limit")
	}
	return b, e
}
func start(pid int) (uint64, error) {
	b, e := read(fmt.Sprintf("/proc/%d/stat", pid), 65536)
	if e != nil {
		return 0, e
	}
	s := string(b)
	at := strings.LastIndex(s, ")")
	if at < 0 {
		return 0, fmt.Errorf("invalid process stat")
	}
	fields := strings.Fields(s[at+1:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("short process stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
func run() (response, error) {
	out := response{Scope: "Current process maps (manual lookup); not event-time mappings", Results: []resolution{}, Modules: []module{}}
	var req request
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 65536)).Decode(&req); err != nil {
		return out, err
	}
	if req.PID <= 0 || len(req.Addresses) > 128 {
		return out, fmt.Errorf("invalid PID/address count")
	}
	var disasmAddr uint64
	var expected []byte
	if req.Disassemble != "" {
		var err error
		disasmAddr, err = strconv.ParseUint(strings.TrimPrefix(strings.ToLower(req.Disassemble), "0x"), 16, 64)
		if err != nil {
			return out, err
		}
		expected, err = hex.DecodeString(req.ExpectedBytes)
		if err != nil || len(expected) > 15 {
			return out, fmt.Errorf("invalid captured opcode")
		}
		req.Addresses = append([]string{req.Disassemble}, req.Addresses...)
		out.Disassembly = &symbols.Disassembly{Address: req.Disassemble, Source: "ELF file", Stop: "No readable ELF mapping", Instructions: []symbols.Instruction{}}
	}
	boot, err := read("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return out, err
	}
	if strings.TrimSpace(string(boot)) != req.BootID {
		return out, fmt.Errorf("device boot differs from capture")
	}
	event, err := strconv.ParseUint(req.EventNS, 10, 64)
	if err != nil {
		return out, err
	}
	before, err := start(req.PID)
	if err != nil {
		return out, fmt.Errorf("process no longer available")
	}
	aux, err := read("/proc/self/auxv", 4096)
	if err != nil {
		return out, err
	}
	var hz uint64
	for i := 0; i+16 <= len(aux); i += 16 {
		if binary.LittleEndian.Uint64(aux[i:]) == 17 {
			hz = binary.LittleEndian.Uint64(aux[i+8:])
			break
		}
	}
	if hz == 0 || before/hz > event/1000000000 || (before/hz == event/1000000000 && (before%hz)*1000000000/hz > event%1000000000) {
		return out, fmt.Errorf("PID was reused or capture clock is incompatible")
	}
	mapsPath := fmt.Sprintf("/proc/%d/maps", req.PID)
	mapsData, err := read(mapsPath, 4<<20)
	if err != nil {
		return out, err
	}
	maps, err := symbols.Maps(string(mapsData))
	if err != nil {
		return out, err
	}
	out.MapsHash = fmt.Sprintf("%x", sha256.Sum256(mapsData))
	if req.MapsHash != "" && req.MapsHash != out.MapsHash {
		return out, fmt.Errorf("process mappings changed; resolve again before scrolling")
	}
	cache := map[string]*symbols.ELF{}
	fail := map[string]string{}
	remaining := 5000
	var opened []*os.File
	defer func() {
		for _, f := range opened {
			f.Close()
		}
	}()
	loadELF := func(m symbols.Mapping) (*symbols.ELF, error) {
		key := fmt.Sprintf("%s/%d/%s", m.Device, m.Inode, m.Path)
		obj, exists := cache[key]
		if !exists {
			if len(cache) >= 8 {
				return nil, fmt.Errorf("Module limit reached")
			}
			cache[key] = nil
			file, e := os.Open(fmt.Sprintf("/proc/%d/map_files/%x-%x", req.PID, m.Start, m.End))
			if e != nil && !strings.HasSuffix(m.Path, " (deleted)") {
				file, e = os.Open(fmt.Sprintf("/proc/%d/root%s", req.PID, m.Path))
			}
			if e != nil {
				fail[key] = "ELF unavailable"
			} else {
				var st unix.Stat_t
				e = unix.Fstat(int(file.Fd()), &st)
				device := fmt.Sprintf("%02x:%02x", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
				if e != nil || st.Ino != m.Inode || device != m.Device {
					fail[key] = "Mapped file identity changed"
				} else {
					obj, e = symbols.Read(file)
					if e != nil {
						fail[key] = "No supported ELF symbols"
						if strings.HasSuffix(m.Path, ".apk") {
							fail[key] = "APK-backed ELF unwinding is not supported yet"
						}
					} else {
						cache[key] = obj
						obj.FileID = fmt.Sprintf("%s/%d/%d/%d/%d", device, st.Ino, st.Size, st.Mtim.Sec, st.Mtim.Nsec)
						n := len(obj.Symbols)
						if n > remaining {
							n = remaining
						}
						if !req.CodeOnly {
							out.Modules = append(out.Modules, module{m.Path, obj.Symbols[:n], n < len(obj.Symbols)})
						}
						remaining -= n
					}
				}
				opened = append(opened, file)
			}
		}
		if obj == nil {
			return nil, fmt.Errorf("%s", fail[key])
		}
		return obj, nil
	}
	seen := map[uint64]bool{}
	for _, text := range req.Addresses {
		addr, e := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(text), "0x"), 16, 64)
		if e != nil {
			return out, e
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		r := resolution{Address: fmt.Sprintf("0x%016x", addr), Status: "Unmapped"}
		for _, m := range maps {
			if addr < m.Start || addr >= m.End {
				continue
			}
			r.Module = fmt.Sprintf("%s + file 0x%x", m.Path, m.Offset+addr-m.Start)
			r.Status = "Module only"
			if !strings.HasPrefix(m.Path, "/") || m.Inode == 0 {
				break
			}
			obj, err := loadELF(m)
			if err != nil {
				r.Status = err.Error()
				break
			}
			if req.Disassemble != "" && addr == disasmAddr {
				out.CodeMapping = mappingID(m)
				if req.CodeMapping != "" && req.CodeMapping != out.CodeMapping {
					return out, fmt.Errorf("code mapping changed; resolve again before scrolling")
				}
				if req.FileID != "" && req.FileID != obj.FileID {
					return out, fmt.Errorf("ELF changed; resolve again before scrolling")
				}
				d := obj.Disassemble(m, addr, expected)
				if req.Before {
					d = obj.DisassembleBefore(m, addr)
				} else if !req.CodeOnly && len(d.Instructions) > 0 {
					before := obj.DisassembleBefore(m, addr)
					d.Instructions = append(before.Instructions, d.Instructions...)
					d.Previous = before.Previous
					d.Boundary += "; earlier context: " + before.Stop
				}
				out.Disassembly = &d
			}
			value, ok := obj.Virtual(m, addr)
			if !ok {
				r.Status = "Outside ELF load segment"
				break
			}
			r.Module = fmt.Sprintf("%s + ELF 0x%x", m.Path, value)
			if sym := obj.Lookup(value); sym != nil {
				r.Symbol = fmt.Sprintf("%s+0x%x", sym.Name, value-sym.Value)
				r.Status = "Resolved"
			}
			break
		}
		out.Results = append(out.Results, r)
	}
	if req.Stack != nil {
		trace := symbols.Unwind(*req.Stack, func(pc uint64) (*symbols.ELF, symbols.Mapping, error) {
			for _, m := range maps {
				if pc >= m.Start && pc < m.End && strings.Contains(m.Perms, "x") && strings.HasPrefix(m.Path, "/") {
					e, err := loadELF(m)
					return e, m, err
				}
			}
			return nil, symbols.Mapping{}, fmt.Errorf("Caller has no executable ELF mapping")
		})
		out.StackTrace = &trace
	}
	after, err := start(req.PID)
	if err != nil || before != after {
		return out, fmt.Errorf("process changed during lookup")
	}
	finalMaps, err := read(mapsPath, 4<<20)
	if err != nil {
		return out, err
	}
	if req.CodeOnly && req.CodeMapping != "" {
		current, e := symbols.Maps(string(finalMaps))
		if e != nil {
			return out, e
		}
		match := false
		for _, m := range current {
			if disasmAddr >= m.Start && disasmAddr < m.End && mappingID(m) == req.CodeMapping {
				match = true
				break
			}
		}
		if !match || out.CodeMapping != req.CodeMapping {
			return out, fmt.Errorf("code mapping changed during disassembly")
		}
	} else if !bytes.Equal(mapsData, finalMaps) {
		return out, fmt.Errorf("process mappings changed; retry manual lookup")
	}
	out.ResolvedAt = time.Now().UnixMilli()
	return out, nil
}

func mappingID(m symbols.Mapping) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%#v", m))))
}
