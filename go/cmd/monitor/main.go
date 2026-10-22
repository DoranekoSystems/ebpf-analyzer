package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/attribution"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/monitor"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	serial := flag.String("serial", "emulator-5554", "adb serial")
	adb := flag.String("adb", "adb", "adb executable")
	remote := flag.String("remote", "/data/local/tmp/ebpf-analyzer", "Android collector binary")
	iface := flag.String("interface", "any", "device interface to copy; any = all; empty disables packet copies")
	output := flag.String("output", "captures/monitor.json", "passive extension snapshot")
	duration := flag.Duration("duration", 0, "stop after duration; default Ctrl+C")
	userStack := flag.Bool("user-stack", true, "capture x86_64 connect registers/raw stack; false for unsupported devices")
	ioEvents := flag.Bool("io-events", true, "capture independent x86_64 TCP send/receive entry snapshots")
	flag.Parse()
	if !regexp.MustCompile(`^/[A-Za-z0-9/_.-]+$`).MatchString(*remote) || !regexp.MustCompile(`^[A-Za-z0-9_.-]*$`).MatchString(*iface) {
		return fmt.Errorf("invalid remote path or interface")
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0755); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	args := []string{"-s", *serial, "shell", "-T", "su", "0", *remote, "monitor", "-control"}
	if *userStack {
		args = append(args, "-user-stack")
	}
	if *ioEvents {
		args = append(args, "-io-events")
	}
	if *iface != "" {
		args = append(args, "-capture-interface", *iface)
	}
	cmd := exec.Command(*adb, args...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	events := make(chan attribution.Batch, 4)
	done := make(chan error, 1)
	readerCtx, cancelReader := context.WithCancel(context.Background())
	defer cancelReader()
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 65536), 16*1024*1024)
		var readErr error
		for scanner.Scan() {
			var b attribution.Batch
			if err := json.Unmarshal(scanner.Bytes(), &b); err != nil {
				readErr = err
				break
			}
			if b.SchemaVersion != 1 {
				readErr = fmt.Errorf("unsupported collector schema")
				break
			}
			select {
			case events <- b:
			case <-readerCtx.Done():
			}
		}
		if readErr == nil {
			readErr = scanner.Err()
		}
		if readErr != nil {
			stdin.Close()
		}
		waitErr := cmd.Wait()
		if readErr != nil {
			done <- readErr
		} else {
			done <- waitErr
		}
	}()
	state := monitor.NewState()
	finished := false
	defer func() {
		cancelReader()
		stdin.Close()
		if !finished {
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				cmd.Process.Kill()
				<-done
			}
		}
		state.Running = false
		state.UpdatedAt = time.Now().UnixMilli()
		if err := monitor.Write(*output, state.Snapshot); err != nil {
			log.Printf("final snapshot: %v", err)
		}
	}()
	absolute, _ := filepath.Abs(*output)
	log.Printf("Passive monitor: %s (no proxy or adb forward required)", absolute)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	if _, err = fmt.Fprintln(stdin, "ping"); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			finished = true
			if err == nil {
				return fmt.Errorf("collector stopped unexpectedly")
			}
			return err
		case <-ticker.C:
			if _, err := fmt.Fprintln(stdin, "ping"); err != nil {
				return err
			}
		case batch := <-events:
			var packets []monitor.Packet
			if len(batch.Packets) > 0 {
				if err := json.Unmarshal(batch.Packets, &packets); err != nil {
					return err
				}
			}
			state.Add(batch.Connections, packets)
			state.AddOrigins(batch.Origins)
			state.OriginDrops = batch.OriginDrops
			state.UpdatedAt = time.Now().UnixMilli()
			state.Drops = batch.Drops
			state.CopyDrops = batch.CopyDrops
			if err := monitor.Write(*output, state.Snapshot); err != nil {
				return err
			}
		}
	}
}
