package origin

import (
	"encoding/binary"
	"testing"
)

func fixture() Raw {
	r := Raw{Start: 123, ConnectionStart: 123, PID: 12, TID: 13, Status: 2, Captured: 256, StackError: -14, Instruction: [2]byte{0x0f, 0x05}}
	r.Registers[15] = 42
	r.Registers[16] = 0x1002
	r.Registers[17] = 0x33
	r.Registers[19] = 0x2000
	for i := range r.Stack {
		r.Stack[i] = 0xab
	}
	return r
}
func TestDecodeOnlyValidPrefixAndExactAddresses(t *testing.T) {
	r := fixture()
	if binary.Size(r) != 4328 {
		t.Fatal("BPF ABI size mismatch")
	}
	s, err := Decode(r, "boot/run")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Stack) != 256 || s.FailureOffset != 256 || s.StackError != -14 || s.SyscallPC != "0x0000000000001000" || s.StackBase != "0x0000000000002000" || s.ConnectionID != "boot/run/123" {
		t.Fatalf("invalid snapshot metadata: %+v", s)
	}
	r.Stack[0] = 0
	if s.Stack[0] != 0xab {
		t.Fatal("stack aliases reused BPF buffer")
	}
}

func TestIOEventsKeepTheirOwnIdentityAndThread(t *testing.T) {
	r := fixture()
	r.Kind = 1
	r.Start = 456
	r.TID = 99
	r.IORequested = 128
	r.Registers[15] = 1
	s, err := Decode(r, "boot/run")
	if err != nil {
		t.Fatal(err)
	}
	if s.EventID != "boot/run/io/456" || s.ConnectionID != "boot/run/123" || s.TID != 99 || s.Operation != "send" || s.RequestedIOBytes != 128 || s.Phase != "entry" {
		t.Fatal("I/O identity replaced by connection metadata")
	}
	r.Kind = 2
	if _, err := Decode(r, "boot/run"); err == nil {
		t.Fatal("write syscall accepted as receive")
	}
	r.Registers[15] = 0
	s, err = Decode(r, "boot/run")
	if err != nil || s.Operation != "receive" {
		t.Fatal("read syscall rejected")
	}
}
func TestRejectInvalidCapture(t *testing.T) {
	for _, change := range []func(*Raw){func(r *Raw) { r.Captured = StackBytes + 256 }, func(r *Raw) { r.Captured = 1 }, func(r *Raw) { r.Status = 1 }, func(r *Raw) { r.Instruction[0] = 0 }, func(r *Raw) { r.Registers[15] = 1 }, func(r *Raw) { r.Status = 3 }} {
		r := fixture()
		change(&r)
		if _, err := Decode(r, "run"); err == nil {
			t.Fatal("invalid snapshot accepted")
		}
	}
}
func TestFailedRegistersExportNoScratchMemory(t *testing.T) {
	r := fixture()
	r.Status = 5
	r.Captured = 0
	r.RegsError = -14
	r.StackError = 0
	s, err := Decode(r, "run")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Stack) != 0 || len(s.Registers) != 0 || s.SyscallPC != "" {
		t.Fatal("invalid registers or stale memory exported")
	}
}
