//go:build linux && amd64

package fridacapture

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed frida_bpfel.o
var program []byte

type state struct {
	PID, TID, Operation, Armed uint32
	Pending, Done              uint32
	SignalResult               int32
	Skipped                    uint32
	Deadline, Entered, Exited  uint64
	Result                     int64
	Saved                      [21]uint64
}

func Main() {
	if err := run(); err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 5 {
		return fmt.Errorf("expected PID TID send|receive eventBootNs")
	}
	pid, e := strconv.ParseUint(os.Args[1], 10, 32)
	if e != nil || pid == 0 {
		return fmt.Errorf("invalid PID")
	}
	tid, e := strconv.ParseUint(os.Args[2], 10, 32)
	if e != nil || tid == 0 {
		return fmt.Errorf("invalid TID")
	}
	operation := uint32(2)
	if os.Args[3] == "send" {
		operation = 1
	} else if os.Args[3] != "receive" {
		return fmt.Errorf("unsupported operation")
	}
	status, e := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/status", pid, tid))
	if e != nil {
		return e
	}
	eventNS, e := strconv.ParseUint(os.Args[4], 10, 64)
	if e != nil {
		return e
	}
	stat, e := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/stat", pid, tid))
	if e != nil {
		return e
	}
	end := strings.LastIndex(string(stat), ")")
	if end < 0 {
		return fmt.Errorf("invalid thread stat")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return fmt.Errorf("short thread stat")
	}
	started, e := strconv.ParseUint(fields[19], 10, 64)
	if e != nil {
		return e
	}
	aux, e := os.ReadFile("/proc/self/auxv")
	if e != nil {
		return e
	}
	var hz uint64
	for i := 0; i+16 <= len(aux); i += 16 {
		if binary.LittleEndian.Uint64(aux[i:]) == 17 {
			hz = binary.LittleEndian.Uint64(aux[i+8:])
			break
		}
	}
	if hz == 0 || started/hz > eventNS/1e9 || (started/hz == eventNS/1e9 && (started%hz)*1e9/hz > eventNS%1e9) {
		return fmt.Errorf("TID was reused since the selected event")
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "SigBlk:") {
			v, e := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "SigBlk:")), 16, 64)
			if e != nil || v&(1<<4) != 0 {
				return fmt.Errorf("target blocks SIGTRAP")
			}
		}
	}
	if e = rlimit.RemoveMemlock(); e != nil {
		return e
	}
	spec, e := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program))
	if e != nil {
		return e
	}
	c, e := ebpf.NewCollection(spec)
	if e != nil {
		return e
	}
	defer c.Close()
	hook, e := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_exit", Program: c.Programs["io_exit"]})
	if e != nil {
		return e
	}
	defer hook.Close()
	name, prog := "tcp_recvmsg", "receive_entry"
	if operation == 1 {
		name, prog = "tcp_sendmsg", "send_entry"
	}
	entry, e := link.Kprobe(name, c.Programs[prog], nil)
	if e != nil {
		return e
	}
	defer entry.Close()
	var ts unix.Timespec
	if e = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); e != nil {
		return e
	}
	s := state{PID: uint32(pid), TID: uint32(tid), Operation: operation, Armed: 1, Deadline: uint64(ts.Nano()) + 15_000_000_000}
	key := uint32(0)
	if e = c.Maps["control"].Put(key, &s); e != nil {
		return e
	}
	defer func() { s.Armed = 0; c.Maps["control"].Put(key, &s) }()
	lease := make(chan struct{}, 1)
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if scanner.Text() == "ping" {
				select {
				case lease <- struct{}{}:
				default:
				}
			}
		}
	}()
	fmt.Println(`{"ready":true}`)
	poll := time.NewTicker(20 * time.Millisecond)
	defer poll.Stop()
	timeout := time.NewTimer(16 * time.Second)
	defer timeout.Stop()
	heartbeat := time.NewTimer(3 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-closed:
			return fmt.Errorf("controller disconnected")
		case <-timeout.C:
			return fmt.Errorf("no completed TCP %s on TID %d; skipped %d readiness/restart/unsupported calls", os.Args[3], tid, s.Skipped)
		case <-heartbeat.C:
			return fmt.Errorf("controller lease expired")
		case <-lease:
			if !heartbeat.Stop() {
				select {
				case <-heartbeat.C:
				default:
				}
			}
			heartbeat.Reset(3 * time.Second)
		case <-poll.C:
			if e = c.Maps["control"].Lookup(key, &s); e != nil {
				return e
			}
			if s.Done != 0 {
				return json.NewEncoder(os.Stdout).Encode(s)
			}
		}
	}
}
