//go:build linux && amd64

package fridastream

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed fridastream_bpfel.o
var program []byte

type event struct {
	PID, TID, Operation, Flags uint32
	SignalResult               int32
	Pad                        uint32
	Entered, Exited, Requested uint64
	Result                     int64
	Saved                      [21]uint64
}

func Main() {
	if e := run(); e != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]string{"type": "error", "error": e.Error()})
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("expected PID")
	}
	pid, e := strconv.ParseUint(os.Args[1], 10, 32)
	if e != nil || pid == 0 {
		return fmt.Errorf("invalid PID")
	}
	identity, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return e
	}
	start := strings.Fields(string(identity)[strings.LastIndex(string(identity), ")")+1:])[19]
	kernel, e := btf.LoadKernelSpec()
	if e != nil {
		return e
	}
	var task *btf.Struct
	if e = kernel.TypeByName("task_struct", &task); e != nil {
		return e
	}
	var offset uint32
	for _, m := range task.Members {
		if m.Name == "blocked" {
			sig, ok := btf.UnderlyingType(m.Type).(*btf.Struct)
			if !ok {
				return fmt.Errorf("unsupported sigset ABI")
			}
			for _, n := range sig.Members {
				if n.Name == "sig" {
					offset = m.Offset.Bytes() + n.Offset.Bytes()
				}
			}
		}
	}
	if offset == 0 {
		return fmt.Errorf("SIGTRAP mask offset unavailable")
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
	reader, e := ringbuf.NewReader(c.Maps["events"])
	if e != nil {
		return e
	}
	defer reader.Close()
	h, e := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_exit", Program: c.Programs["io_exit"]})
	if e != nil {
		return e
	}
	defer h.Close()
	for _, pair := range [][2]string{{"tcp_sendmsg", "send_entry"}, {"tcp_recvmsg", "receive_entry"}} {
		h, e := link.Kprobe(pair[0], c.Programs[pair[1]], nil)
		if e != nil {
			return e
		}
		defer h.Close()
	}
	cfg := struct {
		PID, BlockedOffset uint32
		Deadline           uint64
	}{PID: uint32(pid), BlockedOffset: offset}
	key := uint32(0)
	renew := func() error {
		var ts unix.Timespec
		if e := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); e != nil {
			return e
		}
		cfg.Deadline = uint64(ts.Nano()) + 3_000_000_000
		return c.Maps["control"].Put(key, &cfg)
	}
	if e = renew(); e != nil {
		return e
	}
	defer func() { cfg.PID = 0; c.Maps["control"].Put(key, &cfg) }()
	encoder := json.NewEncoder(os.Stdout)
	if e = encoder.Encode(map[string]any{"type": "ready", "pid": pid}); e != nil {
		return e
	}
	records := make(chan event, 256)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			record, e := reader.Read()
			if e != nil {
				return
			}
			var v event
			if binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &v) == nil {
				select {
				case records <- v:
				case <-done:
					return
				}
			}
		}
	}()
	commands := make(chan string, 256)
	go func() {
		defer close(commands)
		scan := bufio.NewScanner(os.Stdin)
		for scan.Scan() {
			select {
			case commands <- scan.Text():
			case <-done:
				return
			}
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	last := time.Now()
	for {
		select {
		case command, ok := <-commands:
			if !ok {
				return nil
			}
			fields := strings.Fields(command)
			if len(fields) == 1 && fields[0] == "ping" {
				last = time.Now()
				if e = renew(); e != nil {
					return e
				}
			}
			if len(fields) == 3 && fields[0] == "ack" {
				tid, _ := strconv.ParseUint(fields[1], 10, 32)
				stamp, _ := strconv.ParseUint(fields[2], 10, 64)
				var pending uint64
				k := uint32(tid)
				if c.Maps["inflight"].Lookup(k, &pending) == nil && pending == stamp {
					c.Maps["inflight"].Delete(k)
				}
			}
		case v := <-records:
			if e = encoder.Encode(struct {
				event
				AtEpochMs int64
			}{v, time.Now().UnixMilli() + (int64(v.Exited)-bootTime())/1000000}); e != nil {
				return e
			}
		case <-tick.C:
			if time.Since(last) > 3*time.Second {
				return fmt.Errorf("controller disconnected")
			}
			current, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
			if e != nil {
				return fmt.Errorf("target exited")
			}
			fields := strings.Fields(string(current)[strings.LastIndex(string(current), ")")+1:])
			if len(fields) < 20 || fields[19] != start {
				return fmt.Errorf("target changed")
			}
			var lost uint64
			c.Maps["dropped"].Lookup(key, &lost)
			if e = encoder.Encode(map[string]any{"type": "stats", "dropped": lost}); e != nil {
				return e
			}
		}
	}
}

func bootTime() int64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return ts.Nano()
}
