//go:build linux

package collector

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/DoranekoSystems/ebpf-analyzer/internal/attribution"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/control"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/origin"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:embed tcp_bpfel.o
var object []byte

type flow struct {
	Start, Established, End                  uint64
	PID, TID, UID, State                     uint32
	SourcePort, DestinationPort, Family, Pad uint16
	Source, Destination, Comm                [16]byte
}

func Main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	interval := flag.Duration("interval", 500*time.Millisecond, "sampling interval")
	duration := flag.Duration("duration", 0, "exit after this duration (0 = until signal)")
	selfTest := flag.Bool("self-test", false, "create one loopback TCP connection from this collector")
	dial := flag.String("dial", "", "test client only: connect to IP:port without loading BPF")
	payload := flag.String("payload", "", "test client payload; verify byte-for-byte echo after half-close")
	captureInterface := flag.String("capture-interface", "", "passively copy IP packets on this interface (e.g. eth0)")
	controlEnabled := flag.Bool("control", false, "require stdin ping lease; detach when the host disconnects")
	userStack := flag.Bool("user-stack", false, "copy saved x86_64 connect registers and up to 4 KiB user stack at SYN_SENT")
	ioEvents := flag.Bool("io-events", false, "capture per-call TCP send/receive entry registers and raw stacks (x86_64)")
	flag.Parse()
	if *dial != "" {
		conn, err := net.DialTimeout("tcp", *dial, 3*time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"pid": os.Getpid(), "client": conn.LocalAddr().String()}); err != nil {
			return err
		}
		if *payload != "" {
			if _, err := io.WriteString(conn, *payload); err != nil {
				return err
			}
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
				return err
			}
			data, err := io.ReadAll(conn)
			if err != nil {
				return err
			}
			if string(data) != *payload {
				return fmt.Errorf("echo payload mismatch")
			}
		} else {
			time.Sleep(3 * time.Second)
		}
		return nil
	}
	if *interval < 100*time.Millisecond {
		return fmt.Errorf("interval must be at least 100ms")
	}
	if err := validateFormat(); err != nil {
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("memlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return err
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF (SELinux/capabilities may restrict this): %w", err)
	}
	defer collection.Close()
	if *userStack || *ioEvents {
		if runtime.GOARCH != "amd64" || collection.Maps["origin_enabled"] == nil {
			return fmt.Errorf("user-stack requires the x86_64 BPF/collector build")
		}
		var zero uint32
		var enabled uint32
		if *userStack {
			enabled |= 1
		}
		if *ioEvents {
			enabled |= 2
		}
		if err := collection.Maps["origin_enabled"].Update(zero, enabled, ebpf.UpdateAny); err != nil {
			return err
		}
		log.Printf("saved registers/raw stack: connect=%v I/O=%v (4 KiB limit, x86_64)", *userStack, *ioEvents)
	}
	if *ioEvents {
		for _, probe := range []struct{ name, program string }{{"inet_sock_destruct", "trace_destruct"}, {"tcp_sendmsg", "trace_send"}, {"tcp_recvmsg", "trace_receive"}} {
			attachment, err := link.Kprobe(probe.name, collection.Programs[probe.program], nil)
			if err != nil {
				return fmt.Errorf("attach I/O event %s: %w", probe.name, err)
			}
			defer attachment.Close()
		}
		log.Print("attached TCP send/receive entry events; these are not IP packet events")
	}
	attachment, err := link.Tracepoint("sock", "inet_sock_set_state", collection.Programs["trace_state"], nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}
	defer attachment.Close()
	log.Printf("attached sock:inet_sock_set_state; collector PID=%d", os.Getpid())
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *controlEnabled {
		go control.WatchControl(ctx, cancel, os.Stdin, 5*time.Second)
	}
	if *duration > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, *duration)
		defer stop()
	}
	if *selfTest {
		if err := testConnection(); err != nil {
			return err
		}
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	// A run ID prevents accidental collisions across collector restarts within one boot.
	runID := fmt.Sprintf("%s/%d", strings.TrimSpace(string(boot)), time.Now().UnixNano())
	packages := &attribution.PackageResolver{Path: "/data/system/packages.list"}
	var capture *copies
	if *captureInterface != "" {
		var cleanup func()
		capture, cleanup, err = startCopies(ctx, *captureInterface)
		if err != nil {
			return fmt.Errorf("start passive copies: %w", err)
		}
		defer cleanup()
		log.Printf("passive packet copies on %s; original traffic unchanged", *captureInterface)
	}
	// Anchor boot time once: resampling rounded milliseconds makes SYN time jitter.
	var anchor unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &anchor); err != nil {
		return err
	}
	epochOffset := (time.Now().UnixNano() - anchor.Nano()) / 1e6
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	encoder := json.NewEncoder(os.Stdout)
	for {
		if err := sample(collection, encoder, runID, packages, capture, epochOffset); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func sample(c *ebpf.Collection, encoder *json.Encoder, runID string, packages *attribution.PackageResolver, capture *copies, offset int64) error {
	now := time.Now().UnixMilli()
	if err := packages.Refresh(time.Now()); err != nil {
		log.Printf("package resolution refresh unavailable: %v", err)
	}
	batch := attribution.Batch{SchemaVersion: 1, SampledAt: now, Connections: []attribution.Observation{}}
	var originKeys []uint64
	if origins := c.Maps["origins"]; origins != nil {
		var zero uint32
		if err := c.Maps["origin_drops"].Lookup(zero, &batch.OriginDrops); err != nil {
			return err
		}
		it := origins.Iterate()
		var key uint64
		var raw origin.Raw
		for it.Next(&key, &raw) {
			snapshot, err := origin.Decode(raw, runID)
			if err != nil {
				return err
			}
			batch.Origins = append(batch.Origins, snapshot)
			originKeys = append(originKeys, key)
			if len(originKeys) >= 128 {
				break
			}
		}
		if err := it.Err(); err != nil {
			return err
		}
	}
	if capture != nil {
		packets, drops, err := capture.drain()
		if err != nil {
			return err
		}
		batch.Packets, err = json.Marshal(packets)
		if err != nil {
			return err
		}
		batch.CopyDrops = drops
	}
	var zero uint32
	if err := c.Maps["drops"].Lookup(zero, &batch.Drops); err != nil {
		return err
	}
	iterator := c.Maps["flows"].Iterate()
	var key uint64
	var f flow
	var completed []uint64
	for iterator.Next(&key, &f) {
		if f.End != 0 {
			completed = append(completed, key)
		}
		if f.Established == 0 || f.SourcePort == 0 {
			continue
		}
		end := now
		if f.End != 0 {
			// Include the final millisecond in the exclusive upper bound.
			end = int64(f.End/1e6) + offset + 1
		}
		start := int64(f.Start/1e6) + offset
		if end <= start {
			end = start + 1
		}
		o := observation(f, runID, packages.Names, offset, now)
		o.From, o.To = start, end
		batch.Connections = append(batch.Connections, o)
	}
	if err := iterator.Err(); err != nil {
		return err
	}
	if err := encoder.Encode(batch); err != nil {
		return err
	}
	for _, id := range originKeys {
		if err := c.Maps["origins"].Delete(id); err != nil {
			return err
		}
	}
	for _, id := range completed {
		if err := c.Maps["flows"].Delete(id); err != nil {
			return err
		}
	}
	return nil
}

func observation(f flow, runID string, packages map[uint32][]string, offset, now int64) attribution.Observation {
	app := fmt.Sprintf("Unknown (UID %d)", f.UID)
	pkg := ""
	if names := packages[f.UID]; len(names) == 1 {
		app, pkg = names[0], names[0]
	} else if len(names) > 1 {
		app = fmt.Sprintf("Shared UID %d (%d packages)", f.UID, len(names))
	}
	return attribution.Observation{ConnectionID: fmt.Sprintf("%s/%d", runID, f.Start),
		ClientIP: address(f.Source, f.Family), ClientPort: int(f.SourcePort), ServerIP: address(f.Destination, f.Family), ServerPort: int(f.DestinationPort),
		From: int64(f.Start/1e6) + offset, To: now, PID: f.PID, TID: f.TID, UID: f.UID, AppName: app, PackageName: pkg,
		ProcessName: strings.TrimRight(string(f.Comm[:]), "\x00"), Closed: f.End != 0}
}

func address(raw [16]byte, family uint16) string {
	if family == 2 {
		return net.IP(raw[:4]).String()
	}
	return net.IP(raw[:]).String()
}

func validateFormat() error {
	path := "/sys/kernel/tracing/events/sock/inet_sock_set_state/format"
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read tracepoint ABI: %w", err)
	}
	for _, field := range []struct {
		name         string
		offset, size int
	}{
		{"skaddr", 8, 8}, {"oldstate", 16, 4}, {"newstate", 20, 4}, {"sport", 24, 2},
		{"dport", 26, 2}, {"family", 28, 2}, {"protocol", 30, 2}, {"saddr", 32, 4},
		{"daddr", 36, 4}, {"saddr_v6", 40, 16}, {"daddr_v6", 56, 16},
	} {
		pattern := fmt.Sprintf(`field:[^;]*\b%s(?:\[\d+\])?;\s*offset:%d;\s*size:%d;`, field.name, field.offset, field.size)
		if !regexp.MustCompile(pattern).Match(data) {
			return fmt.Errorf("unsupported tracepoint ABI for %s", field.name)
		}
	}
	return nil
}

func testConnection() error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
		done <- err
	}()
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		return err
	}
	log.Printf("self-test: PID=%d %s -> %s", os.Getpid(), conn.LocalAddr(), conn.RemoteAddr())
	conn.Close()
	return <-done
}
