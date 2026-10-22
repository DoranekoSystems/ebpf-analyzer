package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/monitor"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
	"net"
	"sync"
	"time"
)

type copies struct {
	sync.Mutex
	packets []monitor.Packet
	drops   uint64
	err     error
	fd      int
}

// This filter is attached only to our AF_PACKET socket. It limits the private
// copy to 65535 bytes; it cannot drop, redirect or modify the original traffic.
// Userspace stores only the first 2048 bytes and reports the original length.
func startCopies(ctx context.Context, iface string) (*copies, func(), error) {
	index := 0
	if iface != "any" {
		dev, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, nil, err
		}
		index = dev.Index
	}
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "monitor_copy", Type: ebpf.SocketFilter, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 65535), asm.Return()}})
	if err != nil {
		return nil, nil, err
	}
	defer program.Close()
	// ETH_P_ALL in network byte order, supported collector architectures are little endian.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0x0300)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*copies, func(), error) { unix.Close(fd); return nil, nil, err }
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, program.FD()); err != nil {
		return fail(err)
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
		return fail(err)
	}
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: 0x0300, Ifindex: index}); err != nil {
		return fail(err)
	}
	state := &copies{fd: fd}
	child, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer unix.Close(fd)
		buf := make([]byte, 2048)
		oob := make([]byte, 256)
		for child.Err() == nil {
			n, oobn, _, from, err := unix.Recvmsg(fd, buf, oob, unix.MSG_TRUNC)
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 100)
				continue
			}
			if err != nil {
				state.Lock()
				state.err = fmt.Errorf("packet copy: %w", err)
				state.Unlock()
				return
			}
			length := n
			if length > len(buf) {
				length = len(buf)
			}
			at := time.Now().UnixMilli()
			messages, parseErr := unix.ParseSocketControlMessage(oob[:oobn])
			if parseErr == nil {
				for _, m := range messages {
					if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SO_TIMESTAMPNS && len(m.Data) >= 16 {
						at = int64(binary.NativeEndian.Uint64(m.Data[:8]))*1000 + int64(binary.NativeEndian.Uint64(m.Data[8:16]))/1e6
					}
				}
			}
			p, ok := monitor.Decode(buf[:length], n, at)
			if address, ok := from.(*unix.SockaddrLinklayer); ok {
				p.InterfaceIndex = address.Ifindex
			}
			if !ok {
				continue
			}
			state.Lock()
			if len(state.packets) < 512 {
				state.packets = append(state.packets, p)
			} else {
				state.drops++
			}
			state.Unlock()
		}
	}()
	return state, func() { cancel(); <-done }, nil
}

func (c *copies) drain() ([]monitor.Packet, uint64, error) {
	c.Lock()
	defer c.Unlock()
	packets := c.packets
	c.packets = nil
	stats, err := unix.GetsockoptTpacketStats(c.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return nil, c.drops, err
	}
	c.drops += uint64(stats.Drops)
	return packets, c.drops, c.err
}
