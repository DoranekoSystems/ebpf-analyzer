package symbols

import (
	"bytes"
	"debug/elf"
	"os"
	"testing"
)

func TestMapsAndLoadOffset(t *testing.T) {
	list, err := Maps("7f001000-7f002000 r-xp 00002000 08:01 123 /path/with spaces/lib.so\n")
	if err != nil || len(list) != 1 || list[0].Path != "/path/with spaces/lib.so" {
		t.Fatalf("maps: %v %v", list, err)
	}
	e := ELF{Programs: []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Off: 0x2000, Vaddr: 0x5000, Filesz: 0x1000}}}, Symbols: []Symbol{{Name: "function", Value: 0x5010, Size: 16}, {Name: "zero", Value: 0x5030}}}
	value, ok := e.Virtual(list[0], 0x7f001018)
	if !ok || value != 0x5018 || e.Lookup(value).Name != "function" {
		t.Fatal("load bias translation failed")
	}
	if e.Lookup(0x5020) != nil || e.Lookup(0x5031) != nil || e.Lookup(0x5030) == nil {
		t.Fatal("guessed symbol outside its range")
	}
	if _, ok := e.Virtual(list[0], list[0].End); ok {
		t.Fatal("matched end boundary")
	}
	if _, err := Maps("bad record"); err == nil {
		t.Fatal("accepted invalid maps")
	}
	if _, err := Read(bytes.NewReader([]byte("not ELF"))); err == nil {
		t.Fatal("accepted non ELF")
	}
}
func TestBuiltProbeELF(t *testing.T) {
	f, err := os.Open("../../bin/stackprobe-amd64")
	if err != nil {
		t.Skip("build stackprobe first")
	}
	defer f.Close()
	e, err := Read(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range e.Symbols {
		if s.Name == "main.stackConnect.abi0" {
			if e.Lookup(s.Value) == nil {
				t.Fatal("defined function unresolved")
			}
			return
		}
	}
	t.Fatal("known assembly symbol missing")
}
