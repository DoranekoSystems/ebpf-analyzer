// Package origin decodes bounded snapshots copied by BPF at TCP_SYN_SENT.
// No target-process memory is read from userspace.
package origin

import (
	"encoding/hex"
	"fmt"
)

const StackBytes = 4096

// Raw is the x86_64 BPF map value (232 byte header + 4 KiB stack).
type Raw struct {
	Start                                   uint64
	PID, TID                                uint32
	RegsError, StackError, InstructionError int32
	Status, Captured, Kind                  uint32
	Registers                               [21]uint64
	Instruction                             [2]byte
	Padding                                 [6]byte
	ConnectionStart, IORequested            uint64
	Stack                                   [StackBytes]byte
}

type Snapshot struct {
	EventID          string            `json:"eventId,omitempty"`
	Operation        string            `json:"operation,omitempty"`
	Phase            string            `json:"phase,omitempty"`
	RequestedIOBytes uint64            `json:"requestedIoBytes,omitempty"`
	ConnectionID     string            `json:"connectionId"`
	PID              uint32            `json:"pid"`
	TID              uint32            `json:"tid"`
	Architecture     string            `json:"architecture"`
	Source           string            `json:"source"`
	CapturedAtBootNS string            `json:"capturedAtBootNs"`
	Status           string            `json:"status"`
	Registers        map[string]string `json:"registers"`
	RegisterError    int32             `json:"registerError"`
	InstructionError int32             `json:"instructionError"`
	InstructionHex   string            `json:"instructionHex"`
	SyscallPC        string            `json:"syscallPc,omitempty"`
	StackBase        string            `json:"stackBase"`
	RequestedBytes   int               `json:"requestedBytes"`
	CapturedBytes    uint32            `json:"capturedBytes"`
	FailureOffset    int               `json:"failureOffset"`
	StackError       int32             `json:"stackError"`
	Stack            []byte            `json:"stack"`
}

var names = [...]string{"r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax_saved", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "rflags", "rsp", "ss"}
var statuses = map[uint32]string{1: "captured-limit", 2: "partial-read", 3: "unsupported-user-frame", 4: "unsupported-syscall", 5: "register-read-failed", 6: "unverified-syscall-instruction", 7: "stack-read-failed"}

func syscallAllowed(kind uint32, nr uint64) bool {
	switch kind {
	case 0:
		return nr == 42
	case 1:
		return nr == 1 || nr == 20 || nr == 44 || nr == 46 || nr == 307
	case 2:
		return nr == 0 || nr == 19 || nr == 45 || nr == 47 || nr == 299
	}
	return false
}

func Decode(raw Raw, runID string) (Snapshot, error) {
	status, ok := statuses[raw.Status]
	if !ok || raw.Kind > 2 || raw.ConnectionStart == 0 || raw.Captured > StackBytes || raw.Captured%256 != 0 {
		return Snapshot{}, fmt.Errorf("invalid BPF origin header")
	}
	if raw.Status == 1 && raw.Captured != StackBytes {
		return Snapshot{}, fmt.Errorf("incomplete full stack")
	}
	if raw.Status >= 3 && raw.Captured != 0 {
		return Snapshot{}, fmt.Errorf("invalid unsupported stack payload")
	}
	s := Snapshot{ConnectionID: fmt.Sprintf("%s/%d", runID, raw.Start), PID: raw.PID, TID: raw.TID, Architecture: "x86_64", Source: "sock:inet_sock_set_state/TCP_SYN_SENT/current-task", CapturedAtBootNS: fmt.Sprint(raw.Start), Status: status, Registers: map[string]string{}, RegisterError: raw.RegsError, InstructionError: raw.InstructionError, StackBase: fmt.Sprintf("0x%016x", raw.Registers[19]), RequestedBytes: StackBytes, CapturedBytes: raw.Captured, FailureOffset: -1, StackError: raw.StackError, Stack: append([]byte{}, raw.Stack[:raw.Captured]...)}
	s.ConnectionID = fmt.Sprintf("%s/%d", runID, raw.ConnectionStart)
	if raw.Kind != 0 {
		s.EventID = fmt.Sprintf("%s/io/%d", runID, raw.Start)
		s.Phase = "entry"
		s.RequestedIOBytes = raw.IORequested
		if raw.Kind == 1 {
			s.Operation = "send"
			s.Source = "kprobe/tcp_sendmsg"
		} else {
			s.Operation = "receive"
			s.Source = "kprobe/tcp_recvmsg"
		}
	}
	if raw.RegsError == 0 {
		for i, name := range names {
			s.Registers[name] = fmt.Sprintf("0x%016x", raw.Registers[i])
		}
	}
	if raw.Status == 1 || raw.Status == 2 || raw.Status == 7 {
		if !syscallAllowed(raw.Kind, raw.Registers[15]) || raw.Registers[17] != 0x33 || raw.Registers[16] < 2 || raw.Instruction != [2]byte{0x0f, 0x05} || raw.InstructionError != 0 || raw.RegsError != 0 {
			return Snapshot{}, fmt.Errorf("invalid verified syscall frame")
		}
		s.SyscallPC = fmt.Sprintf("0x%016x", raw.Registers[16]-2)
		s.InstructionHex = hex.EncodeToString(raw.Instruction[:])
	}
	if raw.StackError != 0 {
		s.FailureOffset = int(raw.Captured)
	}
	return s, nil
}
